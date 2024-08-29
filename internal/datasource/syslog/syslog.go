package syslog

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slog"
)

const (
	// socketType is the name of the type of unix domain socket used.
	socketType = "unixgram"
	// datagramChannelBufferSize is the size of the channel buffer for datagram messages.
	// This determines how many messages can be held in the buffer before the program blocks,
	// waiting for space to become available.
	datagramChannelBufferSize = 1024
	// datagramReadBufferSize is the size of the read buffer for datagram messages.
	// This determines the maximum size of the messages that can be received via the datagram socket.
	datagramReadBufferSize = 65536
	// socketDirMode is the mode for the socket directory.
	socketDirMode = 0777
	// socketFileMode is the mode for the socket file.
	socketFileMode = 0777
)

// atomicBool is a boolean type that can be accessed atomically.
type atomicBool struct {
	flag int32
}

// Set method for atomicBool struct that sets a boolean value atomically.
func (b *atomicBool) Set(value bool) {
	var i int32 = 0
	if value {
		i = 1
	}
	atomic.StoreInt32(&(b.flag), int32(i))
}

// Get method for atomicBool struct that gets a boolean value atomically.
func (b *atomicBool) Get() bool {
	return atomic.LoadInt32(&(b.flag)) != 0
}

// SocketOpt struct is used to set the permissions and ownership of a socket.
type SocketOpt struct {
	UID int
	GID int
}

// Connection interface is used to abstract the net.PacketConn and net.UnixConn types.
type Connection interface {
	io.Reader
	io.Closer
}

// ProcessNginxAccessLogLine is a function type that processes a single line of an NGINX access log.
type ProcessNginxAccessLogLine func(string) error

// Sink struct is responsible for managing and handling syslog messages.
// Usage:
//
//	opts := syslog.SocketOpt{UID: 0, GID: 0, Mode: 0666}
//	sink := NewNginxSink("/var/run/syslog.sock", opts, "nginx", processNginxAccessLogLine)
//
//	defer sink.Close()
//	sink.MountSocket()
//	sink.HandleMessages()
type Sink struct {
	SocketName      string
	SocketDir       string
	LineProcessor   ProcessNginxAccessLogLine
	MessageSplitter bufio.SplitFunc
	socketOpt       SocketOpt
	msgSeparator    []byte
	closed          atomicBool
	conn            Connection
	wait            sync.WaitGroup
	datagramChannel chan []byte
	datagramPool    sync.Pool
}

// socketType returns the type of unix domain socket used.
func (s *Sink) socketType() string {
	return socketType
}

// NewNginxSink creates a new Sink struct used to manage and handle syslog messages.
// This instance is configured for NGINX logs because it ignores all syslog fields.
func NewNginxSink(socketName string, socketDir string, socketOpt SocketOpt, syslogTag string,
	lineProcessor ProcessNginxAccessLogLine) *Sink {

	if lineProcessor == nil {
		slog.Error("lineProcessor cannot be nil")
	}

	socketAbsDir, absErr := filepath.Abs(socketDir)
	if absErr != nil {
		slog.Error("Unable to parse absolute path for socket directory: %v", absErr)
	}

	// Start with a closed flag
	closed := atomicBool{flag: 1}

	sink := &Sink{
		closed:        closed,
		SocketName:    socketName,
		SocketDir:     socketAbsDir,
		socketOpt:     socketOpt,
		LineProcessor: lineProcessor,
		msgSeparator:  []byte(syslogTag + ": "),
		datagramPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, datagramReadBufferSize)
			}},
	}

	return sink
}

// SocketPath returns the path to the syslog socket.
func (s *Sink) SocketPath() string {
	return filepath.Join(s.SocketDir, s.SocketName)
}

// MountSocket creates a Unix domain socket, sets permissions, and starts handling incoming syslog messages.
func (s *Sink) MountSocket() (err error) {
	socketDirErr := s.buildSocketDir()
	if socketDirErr != nil {
		return errors.WithStack(socketDirErr)
	}

	// Remove socket if it already exists because the create socket
	// syscall will fail if the socket already exists.
	removeErr := os.Remove(s.SocketPath())
	if removeErr == nil {
		slog.Debug("Removed socket: %s", s.SocketPath())
	} else if !errors.Is(removeErr, os.ErrNotExist) {
		return errors.WithStack(removeErr)
	}

	// There is the potential for a race condition here where a file could
	// be created before the socket is created or the containing directory
	// removed. If this happens, the socket will fail to be created.
	// This is unlikely to happen in practice and will result in an error.

	unixAddr, addrErr := net.ResolveUnixAddr(socketType, s.SocketPath())
	if addrErr != nil {
		return errors.WithStack(addrErr)
	}

	conn, listenErr := net.ListenUnixgram(socketType, unixAddr)
	if listenErr != nil {
		return errors.WithMessagef(listenErr,
			"failed to open socket on path [%s]", unixAddr.Name)
	}

	// There is a potential race condition here as well. The
	// socket is created with the default permissions of (0775/srwxrwxr-x)
	// ownership of the user and group that created the socket.
	// This means that there is a period of time the socket is accessible
	// with the default ownership and permissions.
	//
	// We mitigate this by creating the socket in a directory with restrictive
	// permissions and ownership (refer to the top of this function).

	ownerErr := s.assignOwner(unixAddr.Name)
	if ownerErr != nil {
		return errors.WithStack(ownerErr)
	}
	permErr := assignPermissions(unixAddr.Name, socketFileMode)
	if permErr != nil {
		return errors.WithStack(permErr)
	}

	bufferSetErr := conn.SetReadBuffer(datagramReadBufferSize)
	if bufferSetErr != nil {
		return errors.WithMessagef(bufferSetErr,
			"failed to set read buffer size to %d for socket on path: %s",
			datagramReadBufferSize, unixAddr.Name)
	}

	s.conn = conn
	// We have assigned the connection to the sink, so we can now allow
	// access to the socket.
	s.closed.Set(false)

	slog.Info("Socket mounted on path: ", "path", unixAddr.Name)
	slog.Info("Checking socket connection object.")
	if s.conn == nil {
		slog.Error("Socket connection is nil after mounting.")
	} else {
		slog.Info("Socket connection established", "connection", s.conn)
	}
	return nil
}

// buildSocketDir creates the socket directory if it doesn't exist and sets
// the owner and permissions on the directory.
func (s *Sink) buildSocketDir() error {
	// Create the socket directory if it doesn't exist and set permissions
	// so that it is inaccessible to other users.
	mkdirErr := os.Mkdir(s.SocketDir, 0770)
	if mkdirErr == nil {
		slog.Debug("Created socket directory: %s", s.SocketDir)
	} else if !errors.Is(mkdirErr, os.ErrExist) {
		return errors.WithStack(mkdirErr)
	} else {
		slog.Debug("Socket directory already exists: %s", s.SocketDir)
	}
	// Now set the owner and permissions on the directory. Owner is set first
	// because the current permissions are denying all users access to the directory.
	// Once the owner is set, the permissions can be set to allow the owner to
	// the desired permissions.
	ownerErr := s.assignOwner(s.SocketDir)
	if ownerErr != nil {
		return errors.WithStack(ownerErr)
	}
	permErr := assignPermissions(s.SocketDir, socketDirMode)
	if permErr != nil {
		return errors.WithStack(permErr)
	}
	return nil
}

// IsClosed method returns true if the socket is closed.
func (s *Sink) IsClosed() bool {
	return s.closed.Get()
}

// Close method closes the underlying unix socket.
func (s *Sink) Close() error {
	if s.IsClosed() {
		return nil
	}

	s.closed.Set(true)
	var closeErr error = nil
	if s.conn != nil {
		closeErr = errors.WithStack(s.conn.Close())
	}

	removeErr := os.Remove(s.SocketPath())
	if removeErr != nil {
		if errors.Is(removeErr, os.ErrNotExist) {
			log.Debug(removeErr)
		} else {
			log.Warn(removeErr)
		}
	}

	return closeErr
}

// HandleMessages method reads lines from the socket and prints them.
func (s *Sink) HandleMessages() {
	if s.conn == nil {
		slog.Error("Socket not mounted")
	}
	if s.IsClosed() {
		slog.Error("Socket is closed")
	}

	slog.Info("Starting to read syslog messages for socket: ", s.SocketPath())

	s.parseDatagrams()
	s.receiveDatagrams()
}

// WaitForMessages method waits for messages to be received on the socket.
func (s *Sink) WaitForMessages() {
	s.HandleMessages()
	s.wait.Wait()
}

// assignOwner sets the for the specified path to the socketOpt owner.
func (s *Sink) assignOwner(path string) error {
	if chownErr := os.Chown(path, s.socketOpt.UID, s.socketOpt.GID); chownErr != nil {
		return errors.WithStack(chownErr)
	}
	slog.Debug("Setting owner of %s to %d:%d", path, s.socketOpt.UID, s.socketOpt.GID)
	return nil
}

// assignPermissions sets the permissions for the specified path.
func assignPermissions(path string, permissions int) error {
	fileMode := os.FileMode(permissions)
	chmodErr := os.Chmod(path, fileMode)
	if chmodErr != nil {
		return errors.WithStack(chmodErr)
	}
	slog.Debug("Setting permissions of %s to %o", path, fileMode)

	return nil
}

// splitMessageFromEvent splits syslog messages by a predefined separator (syslog tag)
// which results in extracting only the message portion of the syslog event.
func (s *Sink) splitMessageFromEvent(data []byte) (token []byte, err error) {
	// Use the syslog tag as the separator to split syslog-specific data from
	// the rest of the message.
	separator := s.msgSeparator
	if len(data) == 0 {
		return nil, nil
	}

	if i := bytes.Index(data, separator); i >= 0 {
		substring := data[i+len(separator):]
		return substring, nil
	} else {
		slog.Warn("No separator found in syslog data: %v", string(data))
		return nil, nil
	}
}

// receiveDatagrams method reads datagrams from the socket and sends a byte
// slice to the channel for processing.
func (s *Sink) receiveDatagrams() {
	if s.IsClosed() {
		slog.Error("Socket is closed")
	}
	slog.Info("Staring to receive datagrams")

	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		for !s.IsClosed() {
			buffer := s.datagramPool.Get().([]byte)
			slog.Info("Waiting to read from socket...")
			n, readErr := s.conn.Read(buffer)
			if readErr != nil {
				opError, ok := readErr.(*net.OpError)
				sleepTime := 10 * time.Millisecond
				if ok && !opError.Temporary() && !opError.Timeout() {
					return
				}
				slog.Debug("Transient error reading from socket - sleeping for %v: %v", sleepTime, readErr)
				time.Sleep(sleepTime)
			} else {
				// Skip null bytes
				for ; (n > 0) && (buffer[n-1] < 32); n-- {
				}
				if n > 0 {
					s.datagramChannel <- buffer[:n]
				}
			}
		}
	}()
}

// parseDatagrams method parses datagrams from the channel and invokes the
// LineProcessor method to process the message field from the syslog event.
func (s *Sink) parseDatagrams() {
	if s.IsClosed() {
		slog.Error("Socket is closed")
		return
	}

	s.datagramChannel = make(chan []byte, datagramChannelBufferSize)
	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		for !s.IsClosed() {
			datagram := <-s.datagramChannel
			slog.Info("Received datagram from channel: %s", string(datagram))
			data, splitErr := s.splitMessageFromEvent(datagram)
			if splitErr == nil {
				line := string(data)
				processorErr := s.LineProcessor(line)
				if processorErr != nil {
					slog.Error("Failed to process syslog message: %v", processorErr)
				}
			} else {
				slog.Warn("Failed to split syslog message: %v", splitErr)
			}

			// Reset the slice length and put it back into the pool
			s.datagramPool.Put(datagram[:0])
		}

	}()
}
