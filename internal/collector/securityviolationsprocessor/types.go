// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

// SecurityViolationEvent represents the structured NGINX App Protect
// security violation data
type SecurityViolationEvent struct {
	// Name of the security policy
	PolicyName string
	// Unique support ID for the violation
	SupportId string
	// Outcome of the request (e.g., REJECTED, PASSED)
	RequestOutcome RequestOutcome
	// Reason for the outcome
	RequestOutcomeReason RequestOutcomeReason
	// Reason for blocking exception if applicable
	BlockingExceptionReason string
	// HTTP method used
	Method string
	// Protocol used (e.g., HTTP/1.1)
	Protocol string
	// X-Forwarded-For header value
	XffHeaderValue string
	// Request URI
	Uri string
	// Full request
	Request string
	// Indicates if the request was truncated
	IsTruncated bool
	// Status of the request
	RequestStatus RequestStatus
	// HTTP response code
	ResponseCode uint32
	// Server address
	ServerAddr string
	// Virtual server name
	VsName string
	// Remote address of the client
	RemoteAddr string
	// Destination port
	DestinationPort uint32
	// Server port
	ServerPort uint32
	// List of violations
	Violations string
	// List of sub-violations
	SubViolations string
	// Violation rating
	ViolationRating uint32
	// Signature set names
	SigSetNames string
	// Signature CVEs
	SigCves string
	// Client class
	ClientClass string
	// Client application
	ClientApplication string
	// Client application version
	ClientApplicationVersion string
	// Severity of the violation
	Severity Severity
	// Threat campaign names
	ThreatCampaignNames string
	// Bot anomalies detected
	BotAnomalies string
	// Bot category
	BotCategory string
	// Enforced bot anomalies
	EnforcedBotAnomalies string
	// Bot signature name
	BotSignatureName string
	// System ID
	SystemId string
	// Display name
	DisplayName string
	// Detailed violation data
	ViolationsData []ViolationData
}

// ViolationData represents individual violation details
type ViolationData struct {
	// Name of the violation
	ViolationDataName string
	// Context of the violation
	ViolationDataContext string
	// Context data associated with the violation
	ViolationDataContextData ContextData
	// Signature data for the violation
	ViolationDataSignatures []SignatureData
}

// SignatureData represents signature data contained within each violation
type SignatureData struct {
	// Signature ID
	SigDataId uint32
	// Blocking mask
	SigDataBlockingMask string
	// Buffer information
	SigDataBuffer string
	// Offset in the buffer
	SigDataOffset uint32
	// Length of the signature match
	SigDataLength uint32
}

// ContextData represents the context data of the violation
type ContextData struct {
	// Name of the context
	ContextDataName string
	// Value of the context
	ContextDataValue string
}

// RequestStatus represents the status of the request
type RequestStatus int

const (
	RequestStatusUnknown RequestStatus = iota
	RequestStatusBlocked
	RequestStatusAlerted
	RequestStatusPassed
)

func (r RequestStatus) String() string {
	switch r {
	case RequestStatusBlocked:
		return "REQUEST_STATUS_BLOCKED"
	case RequestStatusAlerted:
		return "REQUEST_STATUS_ALERTED"
	case RequestStatusPassed:
		return "REQUEST_STATUS_PASSED"
	default:
		return "REQUEST_STATUS_UNKNOWN"
	}
}

// RequestOutcome represents the outcome of the request
type RequestOutcome int

const (
	RequestOutcomeUnknown RequestOutcome = iota
	RequestOutcomePassed
	RequestOutcomeRejected
)

func (r RequestOutcome) String() string {
	switch r {
	case RequestOutcomePassed:
		return "REQUEST_OUTCOME_PASSED"
	case RequestOutcomeRejected:
		return "REQUEST_OUTCOME_REJECTED"
	default:
		return "REQUEST_OUTCOME_UNKNOWN"
	}
}

// RequestOutcomeReason represents the reason for the request outcome
type RequestOutcomeReason int

const (
	SecurityWafUnknown RequestOutcomeReason = iota
	SecurityWafOk
	SecurityWafViolation
	SecurityWafFlagged
	SecurityWafViolationTransparent
)

func (r RequestOutcomeReason) String() string {
	switch r {
	case SecurityWafOk:
		return "SECURITY_WAF_OK"
	case SecurityWafViolation:
		return "SECURITY_WAF_VIOLATION"
	case SecurityWafFlagged:
		return "SECURITY_WAF_FLAGGED"
	case SecurityWafViolationTransparent:
		return "SECURITY_WAF_VIOLATION_TRANSPARENT"
	default:
		return "SECURITY_WAF_UNKNOWN"
	}
}

// Severity represents the severity level of the violation
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityEmergency
	SeverityAlert
	SeverityCritical
	SeverityError
	SeverityWarning
	SeverityNotice
	SeverityInformational
)

func (s Severity) String() string {
	switch s {
	case SeverityEmergency:
		return "SEVERITY_EMERGENCY"
	case SeverityAlert:
		return "SEVERITY_ALERT"
	case SeverityCritical:
		return "SEVERITY_CRITICAL"
	case SeverityError:
		return "SEVERITY_ERROR"
	case SeverityWarning:
		return "SEVERITY_WARNING"
	case SeverityNotice:
		return "SEVERITY_NOTICE"
	case SeverityInformational:
		return "SEVERITY_INFORMATIONAL"
	default:
		return "SEVERITY_UNKNOWN"
	}
}

// Helper methods for backward compatibility with protobuf-style accessors

func (e *SecurityViolationEvent) GetPolicyName() string {
	return e.PolicyName
}

func (e *SecurityViolationEvent) GetSupportId() string {
	return e.SupportId
}

func (e *SecurityViolationEvent) GetRequestOutcome() RequestOutcome {
	return e.RequestOutcome
}

func (e *SecurityViolationEvent) GetRequestOutcomeReason() RequestOutcomeReason {
	return e.RequestOutcomeReason
}

func (e *SecurityViolationEvent) GetBlockingExceptionReason() string {
	return e.BlockingExceptionReason
}

func (e *SecurityViolationEvent) GetMethod() string {
	return e.Method
}

func (e *SecurityViolationEvent) GetProtocol() string {
	return e.Protocol
}

func (e *SecurityViolationEvent) GetXffHeaderValue() string {
	return e.XffHeaderValue
}

func (e *SecurityViolationEvent) GetUri() string {
	return e.Uri
}

func (e *SecurityViolationEvent) GetRequest() string {
	return e.Request
}

func (e *SecurityViolationEvent) GetIsTruncated() bool {
	return e.IsTruncated
}

func (e *SecurityViolationEvent) GetRequestStatus() RequestStatus {
	return e.RequestStatus
}

func (e *SecurityViolationEvent) GetResponseCode() uint32 {
	return e.ResponseCode
}

func (e *SecurityViolationEvent) GetServerAddr() string {
	return e.ServerAddr
}

func (e *SecurityViolationEvent) GetVsName() string {
	return e.VsName
}

func (e *SecurityViolationEvent) GetRemoteAddr() string {
	return e.RemoteAddr
}

func (e *SecurityViolationEvent) GetDestinationPort() uint32 {
	return e.DestinationPort
}

func (e *SecurityViolationEvent) GetServerPort() uint32 {
	return e.ServerPort
}

func (e *SecurityViolationEvent) GetViolations() string {
	return e.Violations
}

func (e *SecurityViolationEvent) GetSubViolations() string {
	return e.SubViolations
}

func (e *SecurityViolationEvent) GetViolationRating() uint32 {
	return e.ViolationRating
}

func (e *SecurityViolationEvent) GetSigSetNames() string {
	return e.SigSetNames
}

func (e *SecurityViolationEvent) GetSigCves() string {
	return e.SigCves
}

func (e *SecurityViolationEvent) GetClientClass() string {
	return e.ClientClass
}

func (e *SecurityViolationEvent) GetClientApplication() string {
	return e.ClientApplication
}

func (e *SecurityViolationEvent) GetClientApplicationVersion() string {
	return e.ClientApplicationVersion
}

func (e *SecurityViolationEvent) GetSeverity() Severity {
	return e.Severity
}

func (e *SecurityViolationEvent) GetThreatCampaignNames() string {
	return e.ThreatCampaignNames
}

func (e *SecurityViolationEvent) GetBotAnomalies() string {
	return e.BotAnomalies
}

func (e *SecurityViolationEvent) GetBotCategory() string {
	return e.BotCategory
}

func (e *SecurityViolationEvent) GetEnforcedBotAnomalies() string {
	return e.EnforcedBotAnomalies
}

func (e *SecurityViolationEvent) GetBotSignatureName() string {
	return e.BotSignatureName
}

func (e *SecurityViolationEvent) GetSystemId() string {
	return e.SystemId
}

func (e *SecurityViolationEvent) GetDisplayName() string {
	return e.DisplayName
}

func (e *SecurityViolationEvent) GetViolationsData() []ViolationData {
	return e.ViolationsData
}

// Getter methods for ViolationData

func (v *ViolationData) GetViolationDataName() string {
	return v.ViolationDataName
}

func (v *ViolationData) GetViolationDataContext() string {
	return v.ViolationDataContext
}

func (v *ViolationData) GetViolationDataContextData() *ContextData {
	return &v.ViolationDataContextData
}

func (v *ViolationData) GetViolationDataSignatures() []SignatureData {
	return v.ViolationDataSignatures
}

// Getter methods for ContextData

func (c *ContextData) GetContextDataName() string {
	return c.ContextDataName
}

func (c *ContextData) GetContextDataValue() string {
	return c.ContextDataValue
}

// Getter methods for SignatureData

func (s *SignatureData) GetSigDataId() uint32 {
	return s.SigDataId
}

func (s *SignatureData) GetSigDataBlockingMask() string {
	return s.SigDataBlockingMask
}

func (s *SignatureData) GetSigDataBuffer() string {
	return s.SigDataBuffer
}

func (s *SignatureData) GetSigDataOffset() uint32 {
	return s.SigDataOffset
}

func (s *SignatureData) GetSigDataLength() uint32 {
	return s.SigDataLength
}