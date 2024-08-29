package syslog

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func processSyslogLine(line string) error {
	println(line)
	return nil
}

func TestMountSyslogSink(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	log.SetReportCaller(true)

	sockOpts := SocketOpt{UID: os.Getuid(), GID: os.Getgid()}
	syslogSink := NewNginxSink("access-logs.sock",
		"/tmp/nginx-agent", sockOpts, "nginx_agent", processSyslogLine)

	defer (func() {
		closeErr := syslogSink.Close()
		if closeErr != nil {
			log.Warnf("%v", closeErr)
		}
	})()

	err := syslogSink.MountSocket()
	if err != nil {
		log.Error(err)
	}

	syslogSink.WaitForMessages()
}

type MockProcessor struct {
	count int32
}

func (p *MockProcessor) Increment() {
	atomic.AddInt32(&p.count, 1)
}

func (p *MockProcessor) Count() int32 {
	return atomic.LoadInt32(&p.count)
}

func (p *MockProcessor) Process(line string) error {
	p.Increment()
	log.Tracef("Processing syslog message: %s", line)
	if !strings.HasPrefix(line, "test log line") {
		log.Fatalf("Expected line to start with 'test log line', got: %s", line)
	}
	return nil
}

// Integration test for MountSocket and HandleMessages
func TestMountSocketAndHandleMessages(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	log.SetReportCaller(true)

	// Mock line processor for testing
	mockProcessor := &MockProcessor{count: 0}

	socketDir := filepath.Join(os.TempDir(), fmt.Sprintf("nginx-agent-%d", time.Now().UnixNano()))
	defer func() {
		removeErr := os.RemoveAll(socketDir)
		if removeErr != nil {
			t.Error("Failed to remove socket directory: ", removeErr)
		}
	}()

	sockOpts := SocketOpt{UID: os.Getuid(), GID: os.Getgid()}
	syslogTag := "nginx"
	syslogSink := NewNginxSink("test.sock", socketDir, sockOpts, syslogTag, mockProcessor.Process)

	err := syslogSink.MountSocket()
	if err != nil {
		t.Error("Failed to mount socket: ", err)
	}

	go func() {
		syslogSink.WaitForMessages()
	}()

	// Connect to the unix socket
	c, err := net.Dial(syslogSink.socketType(), syslogSink.SocketPath())
	if err != nil {
		t.Error("Failed to dial: ", err)
	}

	defer func() {
		closeErr := c.Close()
		if closeErr != nil {
			t.Error("Failed to close socket client: ", closeErr)
		}
	}()

	msgCount := 10
	writtenMsgs := 0
	// Write to the socket
	for i := 1; i <= msgCount; i++ {
		_, err = c.Write([]byte(fmt.Sprintf("%s: test log line %d", syslogTag, i)))
		if err != nil {
			t.Error("Failed to write: ", err)
		}
		writtenMsgs++
	}

	for int(mockProcessor.Count()) < msgCount {
		log.Debugf("Waiting for [%d/%d] messages to be processed - sleeping for 1 second",
			mockProcessor.Count(), writtenMsgs)
		time.Sleep(1 * time.Second)
	}
}
