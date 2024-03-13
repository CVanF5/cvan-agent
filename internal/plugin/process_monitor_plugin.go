// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"context"
	"log/slog"
	"time"

	"github.com/nginx/agent/v3/internal/bus"
	"github.com/nginx/agent/v3/internal/config"
	"github.com/nginx/agent/v3/internal/datasource/host"
	"github.com/nginx/agent/v3/internal/model"
)

type GetProcessesFunc func() ([]*model.Process, error)

type ProcessMonitor struct {
	monitoringFrequency time.Duration
	processes           []*model.Process
	messagePipe         bus.MessagePipeInterface
	getProcessesFunc    GetProcessesFunc
	processTicker       *time.Ticker
}

func NewProcessMonitor(agentConfig *config.Config) *ProcessMonitor {
	return &ProcessMonitor{
		monitoringFrequency: agentConfig.ProcessMonitor.MonitoringFrequency,
		processes:           []*model.Process{},
		getProcessesFunc:    host.GetProcesses,
		processTicker:       nil,
	}
}

func (pm *ProcessMonitor) Init(messagePipe bus.MessagePipeInterface) error {
	pm.messagePipe = messagePipe
	go pm.run(messagePipe.Context())

	return nil
}

func (pm *ProcessMonitor) Close() error {
	pm.processes = nil

	return nil
}

func (*ProcessMonitor) Info() *bus.Info {
	return &bus.Info{
		Name: "process-monitor",
	}
}

func (*ProcessMonitor) Process(*bus.Message) {}

func (*ProcessMonitor) Subscriptions() []string {
	return []string{}
}

func (pm *ProcessMonitor) run(ctx context.Context) {
	slog.Debug("Process monitor started", "monitoring_period", pm.monitoringFrequency)

	processes, err := pm.getProcessesFunc()
	if err == nil {
		pm.processes = processes
		pm.messagePipe.Process(&bus.Message{Topic: bus.OsProcessesTopic, Data: processes})
	}

	slog.Debug("Processes updated")

	pm.processTicker = time.NewTicker(pm.monitoringFrequency)
	defer pm.processTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pm.processTicker.C:
			processes, err := pm.getProcessesFunc()
			if err != nil {
				slog.Error("Unable to get process information", "error", err)

				continue
			}

			pm.processes = processes
			pm.messagePipe.Process(&bus.Message{Topic: bus.OsProcessesTopic, Data: processes})
			slog.Debug("Processes updated")
		}
	}
}
