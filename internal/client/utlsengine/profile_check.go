package utlsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type profileCheckContextKey struct{}

var nextConnectionID atomic.Uint64

// ConnectionReport is the JSON-ready result for one TLS connection attempt.
type ConnectionReport struct {
	ConnectionID         string                    `json:"connection_id"`
	Leg                  string                    `json:"leg"`
	Attempt              int                       `json:"attempt"`
	HelloIndex           int                       `json:"hello_index"`
	CaptureStatus        string                    `json:"capture_status"`
	Expected             ClientProfileExpected     `json:"expected"`
	Actual               *Fingerprint              `json:"actual,omitempty"`
	Constraints          []ClientProfileConstraint `json:"constraints,omitempty"`
	IgnoredDynamic       []string                  `json:"ignored_dynamic,omitempty"`
	Diff                 []ProfileDifference       `json:"diff,omitempty"`
	Error                string                    `json:"error,omitempty"`
	EngineVersion        string                    `json:"engine_version,omitempty"`
	NormalizationVersion string                    `json:"normalization_version,omitempty"`
}

// ProfileCheckSlot collects results for a single HTTP request without storing
// request-specific state on the shared dialer.
type ProfileCheckSlot struct {
	mu       sync.Mutex
	reports  []ConnectionReport
	attempts int
}

// BeginProfileCheckAttempt reserves the next one-based network attempt in ctx.
func BeginProfileCheckAttempt(ctx context.Context) int {
	slot, _ := ctx.Value(profileCheckContextKey{}).(*ProfileCheckSlot)
	if slot == nil {
		return 1
	}
	slot.mu.Lock()
	slot.attempts++
	attempt := slot.attempts
	slot.mu.Unlock()
	return attempt
}

// NewProfileCheckContext adds a request-local slot for TLS connection reports.
func NewProfileCheckContext(ctx context.Context) (context.Context, *ProfileCheckSlot) {
	slot := &ProfileCheckSlot{}
	return context.WithValue(ctx, profileCheckContextKey{}, slot), slot
}

// RecordProfileCheck adds a report to the request-local slot, if present.
func RecordProfileCheck(ctx context.Context, report ConnectionReport) {
	slot, _ := ctx.Value(profileCheckContextKey{}).(*ProfileCheckSlot)
	if slot == nil {
		return
	}
	slot.mu.Lock()
	slot.reports = append(slot.reports, report)
	slot.mu.Unlock()
}

// ProfileCheckReports returns a stable copy of reports attached to ctx.
func ProfileCheckReports(ctx context.Context) (reports []ConnectionReport, ok bool) {
	slot, ok := ctx.Value(profileCheckContextKey{}).(*ProfileCheckSlot)
	if !ok || slot == nil {
		return nil, false
	}
	slot.mu.Lock()
	reports = append([]ConnectionReport(nil), slot.reports...)
	slot.mu.Unlock()
	if reports == nil {
		reports = []ConnectionReport{}
	}
	return reports, true
}

// NewConnectionID creates a process-unique identifier for one TLS connection.
func NewConnectionID() string {
	return fmt.Sprintf("tls-%d", nextConnectionID.Add(1))
}

// NewConnectionReport creates the machine-readable connection entry for a check.
func NewConnectionReport(
	profile ClientProfile,
	check ProfileCheckResult,
	connectionID string,
	attempt, helloIndex int,
) (report ConnectionReport) {
	return NewConnectionReportForLeg(profile, check, connectionID, "target", attempt, helloIndex)
}

// NewConnectionReportForLeg creates a connection report for a named TLS leg.
func NewConnectionReportForLeg(
	profile ClientProfile,
	check ProfileCheckResult,
	connectionID, leg string,
	attempt, helloIndex int,
) (report ConnectionReport) {
	if connectionID == "" {
		connectionID = NewConnectionID()
	}
	if leg == "" {
		leg = "target"
	}
	if attempt < 1 {
		attempt = 1
	}
	if helloIndex < 1 {
		helloIndex = 1
	}
	report = ConnectionReport{
		ConnectionID: connectionID,
		Leg:          leg, Attempt: attempt, HelloIndex: helloIndex,
		CaptureStatus: check.Status, Expected: profile.Expected, Diff: check.Diffs,
		Constraints:    append([]ClientProfileConstraint(nil), profile.Policy.Constraints...),
		IgnoredDynamic: append([]string(nil), profile.Policy.IgnoredDynamic...),
		Error:          check.Error, EngineVersion: profile.Engine.Version,
		NormalizationVersion: profile.Expected.NormalizationVersion,
	}
	if check.Status != "INCOMPLETE" && check.Status != "CONNECTION_ERROR" &&
		check.Status != "NOT_OBSERVED" && check.Status != "REUSED_CONNECTION" {
		actual := check.Actual
		report.Actual = &actual
	}
	return report
}

// ProfileCheckResult describes how the ClientHello observed on the wire compares
// with the imported profile.
type ProfileCheckResult struct {
	Status         string                    `json:"status"`
	Expected       ClientProfileExpected     `json:"expected"`
	Actual         Fingerprint               `json:"actual"`
	Constraints    []ClientProfileConstraint `json:"constraints,omitempty"`
	IgnoredDynamic []string                  `json:"ignored_dynamic,omitempty"`
	Diffs          []ProfileDifference       `json:"diffs,omitempty"`
	Error          string                    `json:"error,omitempty"`
}

// ProfileDifference records one expected/actual value difference.
type ProfileDifference struct {
	Path     string `json:"path"`
	Expected any    `json:"expected"`
	Actual   any    `json:"actual"`
	Policy   string `json:"policy"`
}

// ProfileCheckError is returned when a requested strict profile check fails.
type ProfileCheckError struct {
	status string
	err    error
}

// NewProfileCheckError creates a status-bearing profile check error.
func NewProfileCheckError(status string, err error) *ProfileCheckError {
	return &ProfileCheckError{status: status, err: err}
}

func (e *ProfileCheckError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("TLS profile check %s: %v", e.status, e.err)
	}
	return fmt.Sprintf("strict TLS profile check failed: %s", e.status)
}

// Status returns the machine-readable failure status.
func (e *ProfileCheckError) Status() string { return e.status }

// ExitCode maps the profile status to the documented command exit code.
func (e *ProfileCheckError) ExitCode() int {
	switch e.status {
	case "UNSUPPORTED":
		return 2
	case "CONNECTION_ERROR":
		return 3
	case "MISMATCH", "PARTIAL_MATCH":
		return 4
	case "INCOMPLETE", "NOT_OBSERVED", "REUSED_CONNECTION":
		return 5
	default:
		return 3
	}
}

func (e *ProfileCheckError) Unwrap() error { return e.err }

// CheckClientProfile compares profile expectations and constraints against a
// captured ClientHello. Dynamic exclusions are report metadata; TLS-NORM-1
// already omits or normalizes their wire-level values.
func CheckClientProfile(profile ClientProfile, actual Fingerprint) (result ProfileCheckResult) {
	result = ProfileCheckResult{
		Status:         "MATCH",
		Expected:       profile.Expected,
		Actual:         actual,
		Constraints:    append([]ClientProfileConstraint(nil), profile.Policy.Constraints...),
		IgnoredDynamic: append([]string(nil), profile.Policy.IgnoredDynamic...),
	}
	partial := false
	unsupported := false
	for _, expected := range []struct {
		path string
		want string
		got  string
	}{
		{"expected.ja3", profile.Expected.JA3, actual.JA3String},
		{"expected.ja3_hash", profile.Expected.JA3Hash, actual.JA3},
		{"expected.ja4", profile.Expected.JA4, actual.JA4},
	} {
		if expected.want != "" && expected.want != expected.got {
			result.Diffs = append(
				result.Diffs,
				ProfileDifference{Path: expected.path, Expected: expected.want, Actual: expected.got, Policy: "MUST"},
			)
		}
	}
	unsupported = checkNormalizedProfileExpectation(profile, actual, &result)
	if checkProfileConstraints(profile, actual, &result) {
		unsupported = true
	}

	for _, path := range profile.Policy.MustMatch {
		if want, got, ok := profileField(profile, actual, path); ok && !reflect.DeepEqual(want, got) {
			result.Diffs = append(
				result.Diffs,
				ProfileDifference{Path: path, Expected: want, Actual: got, Policy: "MUST"},
			)
		}
	}
	for _, path := range profile.Policy.ShouldMatch {
		want, got, ok := profileField(profile, actual, path)
		if !ok {
			partial = true
			result.Diffs = append(
				result.Diffs,
				ProfileDifference{Path: path, Expected: nil, Actual: nil, Policy: "UNSUPPORTED"},
			)
			continue
		}
		if !reflect.DeepEqual(want, got) {
			partial = true
			result.Diffs = append(
				result.Diffs,
				ProfileDifference{Path: path, Expected: want, Actual: got, Policy: "SHOULD"},
			)
		}
	}

	for _, diff := range result.Diffs {
		if diff.Policy == "MUST" || diff.Policy == "CONSTRAINT" {
			result.Status = "MISMATCH"
			return result
		}
	}
	if unsupported {
		result.Status = "UNSUPPORTED"
	} else if partial {
		result.Status = "PARTIAL_MATCH"
	}

	return result
}

func constraintExpectation(constraint ClientProfileConstraint) any {
	expected := map[string]any{"operator": constraint.Operator}
	if len(constraint.Value) > 0 {
		expected["value"] = constraint.Value
	}
	if len(constraint.Values) > 0 {
		expected["values"] = constraint.Values
	}
	return expected
}

func profileConstraintMatches(constraint ClientProfileConstraint, actual any, exists bool) bool {
	switch constraint.Operator {
	case "present":
		return exists
	case "equals":
		if !exists {
			return false
		}
		var expected any
		return json.Unmarshal(constraint.Value, &expected) == nil && reflect.DeepEqual(expected, actual)
	case "one_of":
		if !exists {
			return false
		}
		for _, encoded := range constraint.Values {
			var allowed any
			if json.Unmarshal(encoded, &allowed) == nil && reflect.DeepEqual(allowed, actual) {
				return true
			}
		}
	}
	return false
}

func valueAtJSONPointer(document any, path string) (any, bool) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil, false
	}
	current := document
	for _, encoded := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		key := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = value[key]
			if !ok {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(key)
			if err != nil || index < 0 || index >= len(value) || strconv.Itoa(index) != key {
				return nil, false
			}
			current = value[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func profileField(profile ClientProfile, actual Fingerprint, path string) (expected, observed any, supported bool) {
	switch path {
	case "fields.alpn":
		return profile.Fields.ALPN, actual.ALPN, true
	case "fields.extension_order":
		return profile.Fields.ExtensionOrder, actual.ExtensionOrder, true
	case "fields.cipher_suites":
		return profile.Fields.CipherSuites, actual.CipherSuites, true
	case "fields.supported_versions":
		return profile.Fields.SupportedVersions, actual.SupportedVersions, true
	case "fields.supported_groups":
		return profile.Fields.SupportedGroups, actual.SupportedGroups, true
	case "fields.signature_algorithms":
		return profile.Fields.SignatureAlgorithms, actual.SignatureAlgorithms, true
	default:
		return nil, nil, false
	}
}

// CaptureProfileCheck fingerprints the captured bytes and compares them to a profile.
func CaptureProfileCheck(profile ClientProfile, capture *CaptureConn) (result ProfileCheckResult, err error) {
	results, err := CaptureProfileChecks(profile, capture)
	if len(results) == 0 {
		return ProfileCheckResult{Status: "INCOMPLETE", Expected: profile.Expected}, err
	}
	return results[0], err
}

// CaptureProfileChecks compares every complete ClientHello found on one connection.
func CaptureProfileChecks(profile ClientProfile, capture *CaptureConn) (results []ProfileCheckResult, err error) {
	if capture == nil {
		return []ProfileCheckResult{
				{Status: "INCOMPLETE", Expected: profile.Expected},
			}, fmt.Errorf(
				"ClientHello capture is unavailable",
			)
	}
	count := capture.ClientHelloCount()
	if count == 0 {
		captureErr := capture.CaptureError()
		if captureErr == nil {
			captureErr = errCaptureIncomplete
		}
		return []ProfileCheckResult{{Status: "INCOMPLETE", Expected: profile.Expected, Error: captureErr.Error()}},
			fmt.Errorf("ClientHello was not captured: %w", captureErr)
	}
	for index := 1; index <= count; index++ {
		fingerprint, fingerprintErr := capture.FingerprintAt(index)
		if fingerprintErr != nil {
			results = append(
				results,
				ProfileCheckResult{Status: "INCOMPLETE", Expected: profile.Expected, Error: fingerprintErr.Error()},
			)
			return results, fmt.Errorf("fingerprint captured ClientHello %d: %w", index, fingerprintErr)
		}
		results = append(results, CheckClientProfile(profile, fingerprint))
	}
	if captureErr := capture.CaptureError(); captureErr != nil {
		results = append(
			results,
			ProfileCheckResult{Status: "INCOMPLETE", Expected: profile.Expected, Error: captureErr.Error()},
		)
		return results, fmt.Errorf("ClientHello capture is incomplete: %w", captureErr)
	}

	return results, nil
}

// CaptureObservations fingerprints each complete ClientHello without comparing
// it to a profile. It distinguishes no transmitted bytes from a partial capture.
func CaptureObservations(capture *CaptureConn) (results []ProfileCheckResult) {
	if capture == nil {
		return []ProfileCheckResult{{Status: "NOT_OBSERVED", Error: "ClientHello capture is unavailable"}}
	}
	count := capture.ClientHelloCount()
	if count == 0 {
		status := "NOT_OBSERVED"
		if capture.CapturedBytes() > 0 || capture.CaptureError() != nil {
			status = "INCOMPLETE"
		}
		err := capture.CaptureError()
		check := ProfileCheckResult{Status: status}
		if err != nil {
			check.Error = err.Error()
		} else if status == "INCOMPLETE" {
			check.Error = errCaptureIncomplete.Error()
		}
		return []ProfileCheckResult{check}
	}
	for index := 1; index <= count; index++ {
		fingerprint, err := capture.FingerprintAt(index)
		if err != nil {
			results = append(results, ProfileCheckResult{Status: "INCOMPLETE", Error: err.Error()})
			return results
		}
		results = append(results, ProfileCheckResult{Status: "OBSERVED", Actual: fingerprint})
	}
	if err := capture.CaptureError(); err != nil {
		results = append(results, ProfileCheckResult{Status: "INCOMPLETE", Error: err.Error()})
	}
	return results
}
