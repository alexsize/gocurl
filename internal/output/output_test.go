package output

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
)

type rejectingOutputWriter struct{}

func (rejectingOutputWriter) Write([]byte) (int, error)       { return 0, io.ErrClosedPipe }
func (rejectingOutputWriter) WriteString(string) (int, error) { return 0, io.ErrClosedPipe }

type partialResponseReader struct{ read bool }

func (r *partialResponseReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.ErrUnexpectedEOF
	}
	r.read = true
	return copy(p, "partial"), nil
}

func TestNewOutputTruncatesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "response.json")
	if err := os.WriteFile(path, []byte("old response suffix"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := NewOutput(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer out.dataFileWriter.(*os.File).Close()
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatalf("output file after open = %v, %v; want size 0", info, err)
	}
}

func TestWriteReportsBodyAndDestinationErrors(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header)}
	out := NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, true)
	if err := out.Write(
		resp,
		&partialResponseReader{},
		&config.Config{OutputJSON: true},
	); !errors.Is(
		err,
		io.ErrUnexpectedEOF,
	) {
		t.Fatalf("JSON body error = %v, want unexpected EOF", err)
	}
	out = NewOutputWithWriters(rejectingOutputWriter{}, &bytes.Buffer{}, false, false)
	if err := out.Write(resp, bytes.NewBufferString("body"), &config.Config{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("destination error = %v, want closed pipe", err)
	}
}

func TestErrorJSONIncludesProfileStatusAndExitCode(t *testing.T) {
	data := &bytes.Buffer{}
	out := NewOutputWithWriters(data, &bytes.Buffer{}, false, true)
	err := fmt.Errorf("request failed: %w", utlsengine.NewProfileCheckError("MISMATCH", nil))
	out.Error("%v", err)

	var result map[string]any
	if decodeErr := json.Unmarshal(data.Bytes(), &result); decodeErr != nil {
		t.Fatalf("decode output JSON: %v; body=%s", decodeErr, data.String())
	}
	if result["status"] != "MISMATCH" || result["exit_code"] != float64(4) {
		t.Fatalf("error JSON = %#v, want status MISMATCH and exit_code 4", result)
	}
}

func TestErrorJSONPreservesCaptureStatusExitCodeMatrix(t *testing.T) {
	for _, tc := range []struct {
		status string
		code   int
	}{
		{status: "UNSUPPORTED", code: 2},
		{status: "CONNECTION_ERROR", code: 3},
		{status: "MISMATCH", code: 4},
		{status: "PARTIAL_MATCH", code: 4},
		{status: "INCOMPLETE", code: 5},
		{status: "NOT_OBSERVED", code: 5},
		{status: "REUSED_CONNECTION", code: 5},
	} {
		t.Run(tc.status, func(t *testing.T) {
			data := &bytes.Buffer{}
			out := NewOutputWithWriters(data, &bytes.Buffer{}, false, true)
			out.Error("%v", utlsengine.NewProfileCheckError(tc.status, nil))
			var result map[string]any
			if err := json.Unmarshal(data.Bytes(), &result); err != nil {
				t.Fatalf("decode output JSON: %v; body=%s", err, data.String())
			}
			if result["status"] != tc.status || result["exit_code"] != float64(tc.code) {
				t.Fatalf("error JSON = %#v, want status %s and exit_code %d", result, tc.status, tc.code)
			}
		})
	}
}

func TestResponseJSONUsesSameConnectionReportShapeAcrossTLSLegs(t *testing.T) {
	ctx, _ := utlsengine.NewProfileCheckContext(context.Background())
	profile := utlsengine.ClientProfile{}
	check := utlsengine.ProfileCheckResult{
		Status: "MISMATCH",
		Actual: utlsengine.Fingerprint{JA3: "actual-ja3", JA4: "actual-ja4"},
		Diffs:  []utlsengine.ProfileDifference{{Path: "fields.alpn", Expected: "h2", Actual: "http/1.1"}},
	}
	for _, leg := range []string{"proxy", "target", "gateway"} {
		utlsengine.RecordProfileCheck(ctx, utlsengine.NewConnectionReportForLeg(profile, check, "tls-"+leg, leg, 1, 1))
	}
	request := &http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: "target.example.test", Path: "/"},
		Header: make(http.Header),
	}
	request = request.WithContext(ctx)
	encoded, err := responseToJSON(&http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Request:    request,
	}, nil, &config.Config{OutputJSON: true})
	if err != nil {
		t.Fatalf("responseToJSON() error = %v", err)
	}
	var result struct {
		Connections []map[string]json.RawMessage `json:"connections"`
	}
	if err = json.Unmarshal(encoded, &result); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
	if len(result.Connections) != 3 {
		t.Fatalf(
			"connection reports = %d, want proxy, target, and gateway reports: %s",
			len(result.Connections),
			encoded,
		)
	}
	var wantShape []string
	for index, wantLeg := range []string{"proxy", "target", "gateway"} {
		report := result.Connections[index]
		var gotLeg, status string
		if err = json.Unmarshal(report["leg"], &gotLeg); err != nil {
			t.Fatalf("decode report leg: %v", err)
		}
		if err = json.Unmarshal(report["capture_status"], &status); err != nil {
			t.Fatalf("decode capture status for %s: %v", wantLeg, err)
		}
		if gotLeg != wantLeg || status != "MISMATCH" {
			t.Fatalf("connection report %d = %+v, want leg %s with MISMATCH", index, report, wantLeg)
		}
		keys := make([]string, 0, len(report))
		for key := range report {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if index == 0 {
			wantShape = keys
		} else if !reflect.DeepEqual(keys, wantShape) {
			t.Fatalf("JSON report shape differs by TLS leg: proxy=%v target=%v", wantShape, keys)
		}
		for _, required := range []string{"connection_id", "leg", "attempt", "hello_index", "capture_status", "expected", "actual", "diff"} {
			if _, ok := report[required]; !ok {
				t.Errorf("%s report omits required JSON field %q", wantLeg, required)
			}
		}
	}
}

func TestResponseJSONIncludesRequestMetadataWithoutChangingExistingFields(t *testing.T) {
	requestURL := &url.URL{Scheme: "http", Host: "example.test", Path: "/route", RawQuery: "x=1"}
	req := &http.Request{
		Method: "PATCH", URL: requestURL, Host: "virtual.test", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"X-Repeat": {"one", "two"}}, ContentLength: 9,
		TransferEncoding: []string{"chunked"},
	}
	resp := &http.Response{
		StatusCode: http.StatusNoContent,
		Status:     "204 No Content",
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Request:    req,
	}
	cfg := &config.Config{
		RequestTarget:  "/wire%2Froute?x=1",
		OrderedHeaders: []string{"X-Repeat: one", "X-Repeat: two"},
	}

	encoded, err := responseToJSON(resp, nil, cfg)
	if err != nil {
		t.Fatalf("responseToJSON() error = %v", err)
	}
	var result map[string]any
	if err = json.Unmarshal(encoded, &result); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
	if result["status_code"] != float64(http.StatusNoContent) || result["proto"] != "HTTP/1.1" {
		t.Fatalf("existing response fields changed or missing: %#v", result)
	}
	request, ok := result["request"].(map[string]any)
	if !ok {
		t.Fatalf("request metadata = %#v, want object", result["request"])
	}
	if request["method"] != "PATCH" || request["url"] != "http://example.test/route?x=1" ||
		request["protocol"] != "HTTP/1.1" || request["host"] != "virtual.test" ||
		request["request_target"] != "/wire%2Froute?x=1" || request["content_length"] != float64(9) {
		t.Errorf("request metadata = %#v", request)
	}
	headers, ok := request["headers"].(map[string]any)
	if !ok || fmt.Sprint(headers["X-Repeat"]) != "[one two]" {
		t.Errorf("request headers = %#v, want repeated values", request["headers"])
	}
	if fmt.Sprint(request["configured_header_order"]) != "[X-Repeat: one X-Repeat: two]" {
		t.Errorf("configured header order = %#v", request["configured_header_order"])
	}
	if fmt.Sprint(request["transfer_encoding"]) != "[chunked]" {
		t.Errorf("transfer encoding = %#v", request["transfer_encoding"])
	}
}

func TestResponseJSONRedactsConfiguredRequestHeaders(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			User:   url.UserPassword("alice", "url-secret"),
			Host:   "example.test",
			Path:   "/",
		},
		Header: http.Header{"Authorization": {"Bearer secret"}, "X-Visible": {"visible"}},
	}
	resp := &http.Response{StatusCode: http.StatusOK, Proto: "HTTP/1.1", Request: req}
	cfg := &config.Config{
		JSONRedactHeaders: []string{"authorization"},
		OrderedHeaders:    []string{"Authorization: Bearer secret", "X-Visible: visible"},
	}
	encoded, err := responseToJSON(resp, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("Bearer secret")) || bytes.Contains(encoded, []byte("url-secret")) {
		t.Fatalf("JSON contains redacted authorization data: %s", encoded)
	}
	var result map[string]any
	if err = json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	request := result["request"].(map[string]any)
	headers := request["headers"].(map[string]any)
	if fmt.Sprint(headers["Authorization"]) != "[[REDACTED]]" || fmt.Sprint(headers["X-Visible"]) != "[visible]" {
		t.Errorf("request headers = %#v", headers)
	}
	if request["url"] != "https://example.test/" {
		t.Errorf("request URL = %#v, credentials should be omitted when Authorization is redacted", request["url"])
	}
	if fmt.Sprint(request["configured_header_order"]) != "[Authorization: [REDACTED] X-Visible: visible]" {
		t.Errorf("configured header order = %#v", request["configured_header_order"])
	}
	if fmt.Sprint(request["redacted_header_names"]) != "[Authorization]" {
		t.Errorf("redacted header names = %#v", request["redacted_header_names"])
	}

	req.Header.Del("Authorization")
	encoded, err = responseToJSON(resp, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("url-secret")) {
		t.Fatalf("JSON contains URL credentials used for Basic Auth: %s", encoded)
	}
	if err = json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	request = result["request"].(map[string]any)
	headers = request["headers"].(map[string]any)
	if fmt.Sprint(headers["Authorization"]) != "[[REDACTED]]" {
		t.Errorf("URL-derived Authorization = %#v, want redacted marker", headers["Authorization"])
	}
}
