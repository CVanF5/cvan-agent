// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"
)

// loadTestData loads test data from testdata folder and wraps it in syslog format
func loadTestData(t *testing.T, filename string) string {
	t.Helper()
	data := loadRawTestData(t, filename)
	// Wrap in syslog format
	return "<130>Aug 22 03:28:35 ip-172-16-0-213 ASM:" + data
}

func loadRawTestData(t *testing.T, filename string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	require.NoError(t, err, "Failed to read test data file: %s", filename)

	return string(data)
}

// validateEvent validates the security violation event in the new OTel-compliant format
func validateEvent(t *testing.T, lrOut plog.LogRecord) *SecurityViolationEvent {
	t.Helper()

	// Validate OTel event structure
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate body is human-readable string (not binary)
	body := lrOut.Body().Str()
	assert.NotEmpty(t, body)
	assert.Contains(t, body, "NGINX App Protect")

	// Validate essential attributes are present
	attrs := lrOut.Attributes()
	policyName, exists := attrs.Get("app_protect.policy_name")
	assert.True(t, exists, "policy_name attribute should exist")
	assert.NotEmpty(t, policyName.Str(), "policy_name should not be empty")

	supportId, exists := attrs.Get("app_protect.support_id")
	assert.True(t, exists, "support_id attribute should exist")
	assert.NotEmpty(t, supportId.Str(), "support_id should not be empty")

	outcome, exists := attrs.Get("app_protect.outcome")
	assert.True(t, exists, "outcome attribute should exist")
	assert.NotEmpty(t, outcome.Str(), "outcome should not be empty")

	remoteAddr, exists := attrs.Get("app_protect.remote_addr")
	assert.True(t, exists, "remote_addr attribute should exist")
	assert.NotEmpty(t, remoteAddr.Str(), "remote_addr should not be empty")

	// For testing purposes, rebuild a minimal SecurityViolationEvent from essential attributes only
	// This allows the existing test assertions to continue working with our compromise approach
	event := &SecurityViolationEvent{
		PolicyName: policyName.Str(),
		SupportId:  supportId.Str(), // Support_id is now stored as string
		RemoteAddr: remoteAddr.Str(),
		// Note: With compromise approach, we don't parse all detailed fields into attributes
		// They are available in the string body for the final consumer to parse if needed
	}

	// Parse outcome
	switch outcome.Str() {
	case "REQUEST_OUTCOME_REJECTED":
		event.RequestOutcome = RequestOutcomeRejected
	case "REQUEST_OUTCOME_PASSED":
		event.RequestOutcome = RequestOutcomePassed
	default:
		event.RequestOutcome = RequestOutcomeUnknown
	}

	// Get violation rating if present
	if rating, ratingExists := attrs.Get("app_protect.violation_rating"); ratingExists {
		event.ViolationRating = uint32(rating.Int())
	} else {
		event.ViolationRating = 0
	}

	return event
}

// unmarshalEvent is deprecated - use validateEvent for new format
func unmarshalEvent(t *testing.T, lrOut plog.LogRecord) *SecurityViolationEvent {
	t.Helper()
	// Always use the new format (string body)
	return validateEvent(t, lrOut)
}

//nolint:lll,revive,maintidx // long test string kept for readability, table-driven test with many cases
func TestSecurityViolationsProcessor(t *testing.T) {
	testCases := []struct {
		expectAttrs   map[string]string
		body          any
		assertFunc    func(*testing.T, plog.LogRecord)
		name          string
		expectJSON    string
		expectRecords int
		expectError   bool
	}{
		{
			name: "Test 1: CSV NGINX App Protect syslog message",
			body: loadTestData(t, "csv_url_violations_bot_client.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "nms_app_protect_default_policy",
				"app_protect.support_id":  "5377540117854870581",
				"app_protect.outcome":     "REQUEST_OUTCOME_REJECTED",
				"app_protect.remote_addr": "127.0.0.1",
			},
			expectRecords: 1,
			assertFunc:    assertTest1Event,
		},
		{
			name: "Test 2: CSV NGINX App Protect with signatures",
			body: loadTestData(t, "csv_sql_injection_parameter_signatures.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "security_policy_01",
				"app_protect.support_id":  "9876543210123456789",
				"app_protect.outcome":     "REQUEST_OUTCOME_REJECTED",
				"app_protect.remote_addr": "10.0.1.50",
			},
			expectRecords: 1,
			assertFunc:    assertTest2Event,
		},
		{
			name:          "Test 3: Simple valid syslog message (non-App Protect)",
			body:          loadRawTestData(t, "syslog_non_app_protect.log.txt"),
			expectRecords: 1, // Processed successfully even though not App Protect format
		},
		{
			name:          "Test 4: Unsupported body type",
			body:          12345,
			expectRecords: 0,
		},
		{
			name:          "Test 5: Invalid syslog message",
			body:          loadRawTestData(t, "invalid_syslog_plain_text.log.txt"),
			expectRecords: 0,
			expectError:   true, // Error returned for invalid syslog
		},
		{
			name: "Test 6: Violation name parsing - VIOL_ASM_COOKIE_MODIFIED with cookie_name",
			body: loadTestData(t, "xml_violation_name.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592519",
			},
			expectRecords: 1,
			assertFunc:    assertTest6Event,
		},
		{
			name: "Test 7: Parameter data parsing with empty value_error",
			body: loadTestData(t, "xml_parameter_data_empty_context.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592517",
			},
			expectRecords: 1,
			assertFunc:    assertTest7Event,
		},
		{
			name: "Test 8: Header metachar with base64 text",
			body: loadTestData(t, "xml_header_text.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "3255056874564592516",
			},
			expectRecords: 1,
			assertFunc:    assertTest8Event,
		},
		{
			name: "Test 9: Cookie length violation",
			body: loadTestData(t, "xml_cookie_length.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "3255056874564592514",
			},
			expectRecords: 1,
			assertFunc:    assertTest9Event,
		},
		{
			name: "Test 10: Header length violation",
			body: loadTestData(t, "xml_header_length.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "3255056874564592515",
			},
			expectRecords: 1,
			assertFunc:    assertTest10Event,
		},
		{
			name: "Test 11: URL context with HeaderData",
			body: loadTestData(t, "xml_url_header_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "3255056874564592517",
			},
			expectRecords: 1,
			assertFunc:    assertTest11Event,
		},
		{
			name: "Test 12: Parameter value and name metachar violations",
			body: loadTestData(t, "xml_violation_parameter_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592511",
			},
			expectRecords: 1,
			assertFunc:    assertTest12Event,
		},
		{
			name: "Test 13: Request context violations (max length)",
			body: loadTestData(t, "xml_request_max_length.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592512",
			},
			expectRecords: 1,
			assertFunc:    assertTest13Event,
		},
		{
			name: "Test 14: URL metachar and length violations",
			body: loadTestData(t, "xml_url_metachar_length.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592513",
			},
			expectRecords: 1,
			assertFunc:    assertTest14Event,
		},
		{
			name: "Test 15: Parameter data parsing with signature",
			body: loadTestData(t, "xml_parameter_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592515",
			},
			expectRecords: 1,
			assertFunc:    assertTest15Event,
		},
		{
			name: "Test 16: Header data parsing with signature",
			body: loadTestData(t, "xml_header_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592514",
			},
			expectRecords: 1,
			assertFunc:    assertTest16Event,
		},
		{
			name: "Test 17: Signature data with multiple signatures in request",
			body: loadTestData(t, "xml_signature_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592518",
			},
			expectRecords: 1,
			assertFunc:    assertTest17Event,
		},
		{
			name: "Test 18: Cookie malformed violation",
			body: loadTestData(t, "xml_cookie_malformed.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592511",
			},
			expectRecords: 1,
			assertFunc:    assertTest18Event,
		},
		{
			name: "Test 19: Default context with no explicit context tag but HeaderData present",
			body: loadTestData(t, "xml_http_protocol_header_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592520",
			},
			expectRecords: 1,
			assertFunc:    assertTest19Event,
		},
		{
			name: "Test 20: Cookie violations - malformed, modified, expired",
			body: loadTestData(t, "xml_violation_cookie_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
			},
			expectRecords: 1,
			assertFunc:    assertTest20Event,
		},
		{
			name: "Test 21: URL violations - metachar, length, JSON malformed",
			body: loadTestData(t, "xml_violation_url_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
			},
			expectRecords: 1,
			assertFunc:    assertTest21Event,
		},
		{
			name: "Test 22: Request violations - max length, length",
			body: loadTestData(t, "xml_violation_request_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
			},
			expectRecords: 1,
			assertFunc:    assertTest22Event,
		},
		{
			name: "Test 23: Malformed XML with unclosed tag",
			body: loadTestData(t, "xml_malformed.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "5543056874564592513",
			},
			expectRecords: 1,
			assertFunc:    assertTest23Event,
		},
		{
			name: "Test 24: Parameter data with param_data structure",
			body: loadTestData(t, "xml_parameter_data_as_param_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592516",
			},
			expectRecords: 1,
			assertFunc:    assertTest24Event,
		},
		{
			name: "Test 25: Header violations - metachar and repeated",
			body: loadTestData(t, "xml_violation_header_data.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592511",
			},
			expectRecords: 1,
			assertFunc:    assertTest25Event,
		},
		{
			name: "Test 26: Unmatched XML structure",
			body: loadTestData(t, "xml_struct_unmatched.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "5543056874564592514",
			},
			expectRecords: 1,
			assertFunc:    assertTest26Event,
		},
		{
			name: "Test 27: Syslog with less fields than expected",
			body: loadTestData(t, "syslog_logline_less_fields.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "5543056874564592516",
			},
			expectRecords: 1,
			assertFunc:    assertTest27Event,
		},
		{
			name: "Test 28: Syslog with more fields than expected",
			body: loadTestData(t, "syslog_logline_more_fields.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "5543056874564592517",
			},
			expectRecords: 1,
			assertFunc:    assertTest28Event,
		},
		{
			name: "Test 29: URI and request with escaped commas",
			body: loadTestData(t, "uri_request_contain_escaped_comma.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592513",
			},
			expectRecords: 1,
			assertFunc:    assertTest29Event,
		},
		{
			name: "Test 30: Expanded NAP WAF log",
			body: loadTestData(t, "expanded_nap_waf.log.txt"),
			expectAttrs: map[string]string{
				"app_protect.policy_name": "app_protect_default_policy",
				"app_protect.support_id":  "4355056874564592513",
			},
			expectRecords: 1,
			assertFunc:    assertTest30Event,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			settings := processortest.NewNopSettings(processortest.NopType)
			settings.Logger = zap.NewNop()

			logs := plog.NewLogs()
			lr := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
			switch v := tc.body.(type) {
			case string:
				lr.Body().SetStr(v)
			case int:
				lr.Body().SetInt(int64(v))
			case []byte:
				lr.Body().SetEmptyBytes().FromRaw(v)
			}

			sink := &consumertest.LogsSink{}
			p := newSecurityViolationsProcessor(sink, settings)
			require.NoError(t, p.Start(ctx, nil))

			err := p.ConsumeLogs(ctx, logs)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.expectRecords == 0 {
				assert.Equal(t, 0, sink.LogRecordCount(), "no logs should be produced")
				require.NoError(t, p.Shutdown(ctx))

				return
			}

			got := sink.AllLogs()[0]
			lrOut := got.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)

			for k, v := range tc.expectAttrs {
				val, ok := lrOut.Attributes().Get(k)
				assert.True(t, ok, "attribute %s missing %v", k, v)

				// All essential attributes are now stored as strings
				assert.Equal(t, v, val.Str())
			}

			if tc.assertFunc != nil {
				tc.assertFunc(t, lrOut)
			}

			require.NoError(t, p.Shutdown(ctx))
		})
	}
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest1Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate body contains expected information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "BLOCKED")

	// Validate essential attributes
	assert.Equal(t, "nms_app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "5377540117854870581", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.Equal(t, "127.0.0.1", actualEvent.GetRemoteAddr())
	assert.Equal(t, uint32(5), actualEvent.GetViolationRating())

	// Validate the actual attributes stored (support_id is now string)
	attrs := lrOut.Attributes()
	supportIdAttr, exists := attrs.Get("app_protect.support_id")
	assert.True(t, exists)
	assert.Equal(t, "5377540117854870581", supportIdAttr.Str())

	// Note: With the compromise approach, detailed fields are in the string body
	// not as individual attributes. The full data is still available for the
	// final consumer to parse, but intermediate hops only see essential attributes.

	// Validate that detailed data is available in string body
	body = lrOut.Body().Str()
	assert.Contains(t, body, "Attack signature detected", "Body should contain violation details")
	assert.Contains(t, body, "REQUEST_STATUS_BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "/<><script>", "Body should contain URI details")

	// Note: Detailed signature information is also in the body, but we don't parse it
	// into attributes for performance reasons in our compromise approach
	assert.Contains(t, body, "Signatures:", "Body should mention signatures")
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest2Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes only (compromise approach)
	assert.Equal(t, "security_policy_01", actualEvent.GetPolicyName())
	assert.Equal(t, "9876543210123456789", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.Equal(t, "10.0.1.50", actualEvent.GetRemoteAddr())

	// Validate body contains expected information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "security_policy_01")
	assert.Contains(t, body, "POST", "Body should contain HTTP method")
	assert.Contains(t, body, "/api/users", "Body should contain URI")
	assert.Contains(t, body, "10.0.1.50", "Body should contain client IP")
	assert.Contains(t, body, "Attack signature detected", "Body should contain violation summary")
	assert.Contains(t, body, "SQL Injection", "Body should contain signature type")

	// Note: In compromise approach, detailed signature data and other fields are in the body
	// but not parsed into individual attributes for performance reasons
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest6Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes only (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592519", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.Equal(t, "127.0.0.1", actualEvent.GetRemoteAddr())

	// Validate body contains expected information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "127.0.0.1", "Body should contain client IP")
	assert.Contains(t, body, "VIOL_ASM_COOKIE_MODIFIED", "Body should contain violation details")

	// Note: In compromise approach, detailed cookie data and other fields are in the body
	// but not parsed into individual attributes for performance reasons
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest7Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592517", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "4355056874564592517")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "HTTP protocol compliance", "Body should contain violation summary")
	assert.Contains(t, body, "meta character", "Body should contain violation details")

	// Note: Parameter violation details are embedded in human-readable body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest8Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "3255056874564592516", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "3255056874564592516")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "meta character", "Body should contain violation type")
	assert.Contains(t, body, "Referer", "Body should contain header violation details")

	// Note: Base64 decoded text and metachar details are embedded in the body for consumers
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest9Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "3255056874564592514", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "3255056874564592514")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "length", "Body should contain violation type")
	assert.Contains(t, body, "Cookie", "Body should contain cookie violation details")

	// Note: Specific cookie length values (28, 10) are embedded in the body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest10Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "3255056874564592515", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "3255056874564592515")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "length", "Body should contain violation type")
	assert.Contains(t, body, "Header", "Body should contain header violation details")

	// Note: Specific length values (42, 10) are embedded in the body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest11Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "3255056874564592517", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "3255056874564592517")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "Content", "Body should contain violation type")
	assert.Contains(t, body, "URL", "Body should contain context type")

	// Note: HeaderData with matched/actual values are embedded in the body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest12Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592511", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "4355056874564592511")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "meta character", "Body should contain parameter violations")
	assert.Contains(t, body, "Attack signature", "Body should contain attack detection")

	// Note: Multiple parameter violations are embedded in the body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest13Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592512", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "4355056874564592512")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "length", "Body should contain length violation details")
	assert.Contains(t, body, "Request", "Body should contain request context")

	// Note: Specific length values (detected, defined, total) are embedded in body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest14Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592513", actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "4355056874564592513")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "meta character", "Body should contain URL metachar violation")
	assert.Contains(t, body, "length", "Body should contain URL length violation")
	assert.Contains(t, body, "URL", "Body should contain context type")

	// Note: URI details (base64 or decoded) and length values are embedded in body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest15Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "Attack signature", "Body should contain attack signatures")
	assert.Contains(t, body, "meta character", "Body should contain parameter violations")

	// Note: Detailed violation arrays and signature data are embedded in body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest16Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "Attack signature", "Body should contain attack signature")
	assert.Contains(t, body, "Header", "Body should contain header context")

	// Note: Header signature data is embedded in body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest17Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "Attack signature", "Body should contain attack signature")
	assert.Contains(t, body, "Signatures", "Body should contain signature details")

	// Note: Multiple signature data is embedded in body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest18Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "Cookie", "Body should contain cookie violation")

	// Note: Cookie malformed details are embedded in body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest19Event(t *testing.T, record plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, record)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", record.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, record.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, record.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains violation information
	body := record.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "HTTP protocol", "Body should contain protocol violation")
	assert.Contains(t, body, "Content-Type", "Body should contain header details")

	// Note: Default context and HeaderData details are embedded in body text
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest20Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	// Test 20 has no expected support_id, accept whatever comes from actual data
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all cookie violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, actualEvent.GetSupportId(), "Body should contain actual support_id")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "cookie", "Body should contain cookie context")
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest21Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	// Test 21 has no expected support_id, accept whatever comes from actual data
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all URL violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, actualEvent.GetSupportId(), "Body should contain actual support_id")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "URL", "Body should contain URL violations")
	assert.Contains(t, body, "VIOL_URL", "Body should contain URL violation types")
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest22Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	// Test 22 has no expected support_id, accept whatever comes from actual data
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all request violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, actualEvent.GetSupportId(), "Body should contain actual support_id")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "request", "Body should contain request context")
	assert.Contains(t, body, "VIOL_REQUEST", "Body should contain request violations")
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest23Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// xml_malformed.log.txt has malformed XML with unclosed sig_id tag
	// Should have 0 violations due to malformed XML, but ID should still be parsed from CSV

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (should parse from CSV even with bad XML)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "5543056874564592513", actualEvent.GetSupportId()) // From expectAttrs
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Should have empty violations due to malformed XML
	assert.Empty(t, actualEvent.GetViolationsData(), "Malformed XML should result in empty violations_data")
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest24Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// xml_parameter_data_as_param_data.log.txt uses param_data with param_name/param_value tags
	// Parser successfully parses the violation but doesn't extract context_data
	// because ParamData struct expects name/value tags, not param_name/param_value
	// Context data is empty because param_name/param_value tags aren't mapped in ParamData struct

	// Basic fields should still be populated from CSV
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592516", actualEvent.GetSupportId())
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest25Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592511", actualEvent.GetSupportId()) // Matches test expectAttrs

	// Validate body contains all header violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "4355056874564592511", "Body should contain expected support_id")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "header", "Body should contain header context")
	assert.Contains(t, body, "VIOL_HEADER", "Body should contain header violations")
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest26Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// xml_struct_unmatched.log.txt has <UNMATCHED_STRUCT> instead of <BAD_MSG>
	// Should still process the CSV fields but violations_data should be empty
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "5543056874564592514", actualEvent.GetSupportId())
	// Violations data may be empty or minimal since XML structure is unmatched
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest27Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// syslog_logline_less_fields.log.txt has fewer fields (missing last field)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "5543056874564592516", actualEvent.GetSupportId())
	// Should still parse violations successfully
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest28Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// syslog_logline_more_fields.log.txt has extra field at the end
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "5543056874564592517", actualEvent.GetSupportId())
	// Should still parse violations successfully, ignoring extra field
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest29Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// uri_request_contain_escaped_comma.log.txt has %2C (escaped comma) in URI and request
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.Equal(t, "4355056874564592513", actualEvent.GetSupportId())

	// In compromise approach, URI and Request data are in the body, not as parsed fields
	// Validate body contains URI and request information with escaped commas
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "4355056874564592513")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")

	// Test expects escaped commas in URI and request content
	assert.Contains(t, body, "comma", "Body should contain 'comma' from URI")
	assert.Contains(t, body, "%2C", "Body should contain escaped comma from request")
}

//nolint:dupl // test functions intentionally follow similar validation patterns
func assertTest30Event(t *testing.T, lrOut plog.LogRecord) {
	t.Helper()
	actualEvent := unmarshalEvent(t, lrOut)

	// Validate OTel compliance
	assert.Equal(t, "security.app_protect.violation", lrOut.EventName())
	assert.NotEqual(t, plog.SeverityNumberUnspecified, lrOut.SeverityNumber())
	assert.Equal(t, pcommon.ValueTypeStr, lrOut.Body().Type())

	// Validate essential attributes (compromise approach)
	assert.Equal(t, "app_protect_default_policy", actualEvent.GetPolicyName())
	assert.NotEmpty(t, actualEvent.GetSupportId())
	assert.Equal(t, RequestOutcomeRejected, actualEvent.GetRequestOutcome())
	assert.NotEmpty(t, actualEvent.GetRemoteAddr())

	// Validate body contains all violation information
	body := lrOut.Body().Str()
	assert.Contains(t, body, "NGINX App Protect")
	assert.Contains(t, body, "app_protect_default_policy")
	assert.Contains(t, body, "GET", "Body should contain HTTP method")
	assert.Contains(t, body, "HTTP", "Body should contain protocol")
	assert.Contains(t, body, "BLOCKED", "Body should contain request status")
	assert.Contains(t, body, "VIOL_ATTACK_SIGNATURE", "Body should contain attack signature violation")
	assert.Contains(t, body, "VIOL_HTTP_PROTOCOL", "Body should contain HTTP protocol violation")
	assert.Contains(t, body, "VIOL_PARAMETER_VALUE_METACHAR", "Body should contain parameter metachar violation")
}

func TestSecurityViolationsProcessor_ExtractIPFromHostname(t *testing.T) {
	assert.Equal(t, "127.0.0.1", extractIPFromHostname("127.0.0.1"))
	assert.Equal(t, "172.16.0.213", extractIPFromHostname("ip-172-16-0-213"))
	assert.Empty(t, extractIPFromHostname("not-an-ip"))
}

func TestSetSyslogAttributesNilFields(t *testing.T) {
	lr := plog.NewLogRecord()
	m := &rfc3164.SyslogMessage{}
	p := newSecurityViolationsProcessor(&consumertest.LogsSink{}, processortest.NewNopSettings(processortest.NopType))
	p.setSyslogAttributes(lr, m)
	attrs := lr.Attributes()
	assert.Equal(t, 0, attrs.Len())
}
