package resource

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"

	"github.com/nginx/agent/v3/internal/config"
	"github.com/nginx/agent/v3/internal/datasource/syslog"
)

const syslogTailerChannelSize = 1024

type (
	SyslogNginxMonitorOperator struct {
		agentConfig  *config.Config
		sink         *syslog.Sink
		errorChannel chan error
	}

	SyslogOperator struct {
		agentConfig *config.Config
		monitor     *SyslogNginxMonitorOperator
	}
)

var (
	syslogReloadErrorList = []*regexp.Regexp{
		regexp.MustCompile(`.*\[emerg\].*`),
		regexp.MustCompile(`.*\[alert\].*`),
		regexp.MustCompile(`.*\[crit\].*`),
	}
	syslogWarningRegex = regexp.MustCompile(`.*\[warn\].*`)
)

func NewSyslogOperator(agentConfig *config.Config) *SyslogOperator {
	monitor, err := NewSysLogMonitorOperator(agentConfig)
	if err != nil {
		slog.Error("Failed to initialize SyslogOperator", "error", err)
		return nil
	}

	return &SyslogOperator{
		agentConfig: agentConfig,
		monitor:     monitor,
	}
}

func (s *SyslogOperator) Tail(ctx context.Context, errorLog string, errorChannel chan error) {
	// Delegate the actual monitoring to SyslogNginxMonitorOperator
	slog.Info("Tail method called")       // Log that Tail() is called
	s.monitor.errorChannel = errorChannel // Set the error channel to communicate errors
	s.monitor.Monitor(ctx)
}

// NewSysLogMonitorOperator creates a new SyslogNginxMonitorOperator instance
func NewSysLogMonitorOperator(agentConfig *config.Config) (*SyslogNginxMonitorOperator, error) {
	socketName := "agent.sock"
	socketDir := "/var/run"
	socketOpt := syslog.SocketOpt{UID: 0, GID: 0}

	sink := syslog.NewNginxSink(socketName, socketDir, socketOpt, "nginx", func(line string) error {
		return processLogLine(line, agentConfig)
	})
	if err := sink.MountSocket(); err != nil {
		return nil, fmt.Errorf("failed to mount socket: %w", err)
	}

	sendTestMessage("/var/run/agent.sock")

	return &SyslogNginxMonitorOperator{
		agentConfig:  agentConfig,
		sink:         sink,
		errorChannel: make(chan error, syslogTailerChannelSize),
	}, nil
}

// Monitor starts monitoring the syslog for NGINX errors
func (l *SyslogNginxMonitorOperator) Monitor(ctx context.Context) {
	slog.Info("Monitor method called")
	go l.sink.HandleMessages()

	go func() {
		for {
			select {
			case err := <-l.errorChannel:
				if err != nil {
					slog.ErrorContext(ctx, "Error detected in NGINX logs", "error", err)
					// Handle the error accordingly or stop monitoring
					return
				}
			case <-ctx.Done():
				l.sink.Close()
				return
			}
		}
	}()
}

// processLogLine processes each log line and checks for errors
func processLogLine(line string, agentConfig *config.Config) error {
	slog.Info("Received log line from socket", "line", line) // Debugging
	if doesLogLineContainError(line, agentConfig) {
		return fmt.Errorf("processLogLine error: %v", line)
	}
	return nil
}

// doesLogLineContainError checks if a log line contains an error or warning
func doesLogLineContainError(line string, agentConfig *config.Config) bool {
	if agentConfig.DataPlaneConfig.Nginx.TreatWarningsAsError && syslogWarningRegex.MatchString(line) {
		return true
	}

	for _, errorRegex := range syslogReloadErrorList {
		if errorRegex.MatchString(line) {
			return true
		}
	}

	return false
}

// Function to send a test message to the socket
func sendTestMessage(socketPath string) {
	conn, err := net.Dial("unixgram", socketPath)
	if err != nil {
		slog.Error("Failed to connect to the Unix socket for testing", "error", err)
		return
	}
	defer conn.Close()

	testMessage := "2024/08/28 12:34:58 [emerg] Test emergency message from code"
	_, err = conn.Write([]byte(testMessage))
	if err != nil {
		slog.Error("Failed to send test message to the Unix socket", "error", err)
	} else {
		slog.Info("Successfully sent test message to the Unix socket")
	}
}
