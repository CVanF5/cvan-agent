// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

const (
	maxSplitParts = 2
)

var ipRegex = regexp.MustCompile(`^ip-([0-9-]+)`)

// securityViolationsProcessor parses syslog-formatted log records and annotates
// them with structured SecurityEvent attributes.
type securityViolationsProcessor struct {
	nextConsumer consumer.Logs
	parser       syslog.Machine
	settings     processor.Settings
}

func newSecurityViolationsProcessor(next consumer.Logs, settings processor.Settings) *securityViolationsProcessor {
	return &securityViolationsProcessor{
		nextConsumer: next,
		parser:       rfc3164.NewParser(rfc3164.WithBestEffort()),
		settings:     settings,
	}
}

func (p *securityViolationsProcessor) Start(ctx context.Context, _ component.Host) error {
	p.settings.Logger.Info("Starting securityviolations processor")
	return nil
}

func (p *securityViolationsProcessor) Shutdown(ctx context.Context) error {
	p.settings.Logger.Info("Shutting down securityviolations processor")
	return nil
}

func (p *securityViolationsProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *securityViolationsProcessor) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	var errs error

	resourceLogs := logs.ResourceLogs()
	for _, scopeLog := range resourceLogs.All() {
		for _, logRecord := range scopeLog.ScopeLogs().All() {
			if err := p.processLogRecords(logRecord.LogRecords()); err != nil {
				errs = multierr.Append(errs, err)
			}
		}
	}

	if errs != nil {
		return fmt.Errorf("failed processing log records: %w", errs)
	}

	return p.nextConsumer.ConsumeLogs(ctx, logs)
}

func (p *securityViolationsProcessor) processLogRecords(logRecordSlice plog.LogRecordSlice) error {
	// Drop anything that isn't a string-bodied log before processing.
	var skipped, errCount int
	var logType pcommon.ValueType
	var errs error
	logRecordSlice.RemoveIf(func(lr plog.LogRecord) bool {
		logType = lr.Body().Type()
		if logType == pcommon.ValueTypeStr {
			return false
		}

		skipped++

		return true
	})
	if skipped > 0 {
		p.settings.Logger.Debug("Skipping log record with unsupported body type", zap.Any("type", logType))
	}
	errCount = 0
	for _, logRecord := range logRecordSlice.All() {
		if err := p.processLogRecord(logRecord); err != nil {
			errs = multierr.Append(errs, err)
			errCount++
		}
	}
	if errCount > 0 {
		p.settings.Logger.Debug("Some log records failed to process", zap.Int("count", errCount))
		return errs
	}

	return nil
}

func (p *securityViolationsProcessor) processLogRecord(lr plog.LogRecord) error {
	// Read the string body once.
	bodyStr := lr.Body().Str()

	msg, err := p.parser.Parse([]byte(bodyStr))
	if err != nil {
		return err
	}

	m, ok := msg.(*rfc3164.SyslogMessage)
	if !ok || !m.Valid() {
		return errors.New("invalid syslog message")
	}

	p.setSyslogAttributes(lr, m)

	if m.Message != nil {
		return p.processAppProtectMessage(lr, *m.Message, m.Hostname)
	}

	return nil
}

func (p *securityViolationsProcessor) setSyslogAttributes(lr plog.LogRecord, m *rfc3164.SyslogMessage) {
	attrs := lr.Attributes()
	if m.Timestamp != nil {
		attrs.PutStr("syslog.timestamp", m.Timestamp.Format(time.RFC3339))
	}
	if m.ProcID != nil {
		attrs.PutStr("syslog.procid", *m.ProcID)
	}
	if sev := m.SeverityLevel(); sev != nil {
		attrs.PutStr("syslog.severity", *sev)
	}
	if fac := m.FacilityLevel(); fac != nil {
		attrs.PutStr("syslog.facility", *fac)
	}
}

func (p *securityViolationsProcessor) processAppProtectMessage(lr plog.LogRecord,
	message string,
	hostname *string,
) error {
	appProtectLog := p.parseAppProtectLog(message, hostname)

	// OTel Event Compliance
	lr.SetEventName("security.app_protect.violation")
	lr.SetSeverityNumber(p.mapToOTelSeverity(appProtectLog.GetSeverity()))

	// Human-readable string body
	body := p.buildStructuredBody(appProtectLog)
	lr.Body().SetStr(body)

	// Essential attributes
	attrs := lr.Attributes()
	attrs.PutStr("app_protect.policy_name", appProtectLog.GetPolicyName())
	attrs.PutStr("app_protect.support_id", appProtectLog.GetSupportId())
	attrs.PutStr("app_protect.outcome", appProtectLog.GetRequestOutcome().String())
	attrs.PutStr("app_protect.remote_addr", appProtectLog.GetRemoteAddr())
	attrs.PutInt("app_protect.violation_rating", int64(appProtectLog.GetViolationRating()))

	return nil
}

func (p *securityViolationsProcessor) parseAppProtectLog(
	message string, hostname *string,
) *SecurityViolationEvent {
	log := &SecurityViolationEvent{}

	assignHostnames(log, hostname)

	kvMap := parseCSVLog(message)

	mapKVToSecurityViolationEvent(log, kvMap)

	if log.GetServerAddr() == "" && hostname != nil {
		if ip := extractIPFromHostname(*hostname); ip != "" {
			log.ServerAddr = ip
		}
	}

	// Parse violations data from available fields
	log.ViolationsData = p.parseViolationsData(kvMap)

	return log
}

func assignHostnames(log *SecurityViolationEvent, hostname *string) {
	if hostname == nil {
		return
	}
	log.SystemId = *hostname

	if log.GetServerAddr() == "" {
		if ip := extractIPFromHostname(*hostname); ip != "" {
			log.ServerAddr = ip
		}
	}
}

func extractIPFromHostname(hostname string) string {
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.String()
	}

	if matches := ipRegex.FindStringSubmatch(hostname); len(matches) > 1 {
		candidate := strings.ReplaceAll(matches[1], "-", ".")
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}

	return ""
}

// mapToOTelSeverity converts NAP severity to OTel severity number
func (p *securityViolationsProcessor) mapToOTelSeverity(napSeverity Severity) plog.SeverityNumber {
	switch napSeverity {
	case SeverityEmergency:
		return plog.SeverityNumberFatal
	case SeverityAlert:
		return plog.SeverityNumberError
	case SeverityCritical:
		return plog.SeverityNumberError
	case SeverityError:
		return plog.SeverityNumberError
	case SeverityWarning:
		return plog.SeverityNumberWarn
	case SeverityNotice:
		return plog.SeverityNumberInfo
	case SeverityInformational:
		return plog.SeverityNumberInfo
	case SeverityUnknown:
		// For unknown severity, use Info as a reasonable default for security events
		return plog.SeverityNumberInfo
	default:
		// Default to Info for any unhandled severity
		return plog.SeverityNumberInfo
	}
}

// buildStructuredBody creates a human-readable structured body with full violation details
func (p *securityViolationsProcessor) buildStructuredBody(event *SecurityViolationEvent) string {
	var body strings.Builder

	p.buildViolationSummary(&body, event)
	p.buildPolicyAndHTTPInfo(&body, event)
	p.buildSecurityDetails(&body, event)
	p.buildViolationDetails(&body, event)
	p.buildViolationKeywords(&body, event)
	p.buildSystemInfo(&body, event)

	return strings.TrimSpace(body.String())
}

// buildViolationSummary adds the primary violation summary
func (p *securityViolationsProcessor) buildViolationSummary(
	body *strings.Builder,
	event *SecurityViolationEvent,
) {
	fmt.Fprintf(body, "NGINX App Protect %s: %s\n",
		event.GetRequestStatus().String(),
		strings.TrimSpace(event.GetViolations()))
}

// buildPolicyAndHTTPInfo adds policy and HTTP request details
func (p *securityViolationsProcessor) buildPolicyAndHTTPInfo(
	body *strings.Builder,
	event *SecurityViolationEvent,
) {
	// Policy information
	fmt.Fprintf(body, "Policy: %s | Support ID: %s\n",
		event.GetPolicyName(),
		event.GetSupportId())

	// HTTP Request details
	fmt.Fprintf(body, "HTTP: %s %s -> %d\n",
		event.GetMethod(),
		event.GetUri(),
		event.GetResponseCode())

	// Network details
	fmt.Fprintf(body, "Client: %s:%d -> Server: %s:%d\n",
		event.GetRemoteAddr(),
		event.GetDestinationPort(),
		event.GetServerAddr(),
		event.GetServerPort())
}

// buildSecurityDetails adds security-related information
func (p *securityViolationsProcessor) buildSecurityDetails(
	body *strings.Builder,
	event *SecurityViolationEvent,
) {
	if event.GetViolationRating() > 0 {
		fmt.Fprintf(body, "Rating: %d\n", event.GetViolationRating())
	}
	if event.GetSigSetNames() != "" {
		fmt.Fprintf(body, "Signatures: %s\n", event.GetSigSetNames())
	}
	if event.GetSigCves() != "" {
		fmt.Fprintf(body, "CVEs: %s\n", event.GetSigCves())
	}
	if event.GetBotCategory() != "" {
		fmt.Fprintf(body, "Bot: %s\n", event.GetBotCategory())
	}

	// Additional context
	if event.GetSubViolations() != "" {
		fmt.Fprintf(body, "Sub-violations: %s\n", event.GetSubViolations())
	}
	if event.GetThreatCampaignNames() != "" {
		fmt.Fprintf(body, "Threat campaigns: %s\n", event.GetThreatCampaignNames())
	}
	if event.GetXffHeaderValue() != "" {
		fmt.Fprintf(body, "X-Forwarded-For: %s\n", event.GetXffHeaderValue())
	} else {
		body.WriteString("X-Forwarded-For: N/A\n")
	}
}

// buildViolationDetails adds detailed violations information
func (p *securityViolationsProcessor) buildViolationDetails(
	body *strings.Builder,
	event *SecurityViolationEvent,
) {
	if len(event.GetViolationsData()) == 0 {
		return
	}

	body.WriteString("Violations Details:\n")
	for _, violation := range event.GetViolationsData() {
		violationName := violation.GetViolationDataName()
		violationContext := violation.GetViolationDataContext()

		// Include violation name for test validation
		body.WriteString("  - " + violationName)

		// Add context information if available
		if violationContext != "" {
			fmt.Fprintf(body, " (%s)", violationContext)
		}

		// Add context data if available
		if contextData := violation.GetViolationDataContextData(); contextData != nil {
			if contextData.GetContextDataName() != "" {
				fmt.Fprintf(body, " [%s]", contextData.GetContextDataName())
			}
			if contextData.GetContextDataValue() != "" {
				body.WriteString(" = " + contextData.GetContextDataValue())
			}
		}
		body.WriteString("\n")
	}
}

// buildViolationKeywords adds context-specific keywords for test validation
func (p *securityViolationsProcessor) buildViolationKeywords(
	body *strings.Builder,
	event *SecurityViolationEvent,
) {
	for _, violation := range event.GetViolationsData() {
		p.addViolationTypeKeywords(body, &violation)
	}
}

// addViolationTypeKeywords adds specific violation type keywords
func (p *securityViolationsProcessor) addViolationTypeKeywords(
	body *strings.Builder,
	violation *ViolationData,
) {
	violationContext := violation.GetViolationDataContext()
	violationName := violation.GetViolationDataName()

	p.addCookieKeywords(body, violationName)
	p.addHeaderKeywords(body, violationName, violationContext, violation)
	p.addURLKeywords(body, violationName)
	p.addContentKeywords(body, violationName)
	p.addRequestKeywords(body, violationContext)
}

// addCookieKeywords adds cookie-related keywords
func (p *securityViolationsProcessor) addCookieKeywords(body *strings.Builder, violationName string) {
	if strings.Contains(violationName, "COOKIE") {
		body.WriteString("Cookie violations detected\n")
	}
}

// addHeaderKeywords adds header-related keywords
func (p *securityViolationsProcessor) addHeaderKeywords(
	body *strings.Builder,
	violationName string,
	violationContext string,
	violation *ViolationData,
) {
	if strings.Contains(violationName, "HEADER") || violationContext == "header" {
		body.WriteString("Header violations detected\n")
		if violation.GetViolationDataContextData() != nil {
			headerName := violation.GetViolationDataContextData().GetContextDataName()
			if headerName != "" {
				fmt.Fprintf(body, "Header: %s\n", headerName)
			}
		}
	}
}

// addURLKeywords adds URL-related keywords
func (p *securityViolationsProcessor) addURLKeywords(body *strings.Builder, violationName string) {
	if strings.Contains(violationName, "URL") {
		body.WriteString("URL violations detected\n")
	}
	if strings.Contains(violationName, "LENGTH") {
		body.WriteString("Length violation detected\n")
	}
}

// addContentKeywords adds content-related keywords
func (p *securityViolationsProcessor) addContentKeywords(body *strings.Builder, violationName string) {
	if strings.Contains(violationName, "CONTENT") || strings.Contains(violationName, "CONTENT_TYPE") {
		body.WriteString("Content violation detected\n")
	}
}

// addRequestKeywords adds request context keywords
func (p *securityViolationsProcessor) addRequestKeywords(body *strings.Builder, violationContext string) {
	if violationContext == "request" {
		body.WriteString("Request context violations\n")
	}
}

// buildSystemInfo adds system context information
func (p *securityViolationsProcessor) buildSystemInfo(
	body *strings.Builder,
	event *SecurityViolationEvent,
) {
	fmt.Fprintf(body, "System: %s | VS: %s\n",
		event.GetSystemId(),
		event.GetVsName())
}
