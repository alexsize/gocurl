package gocurl

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
)

func TestClientDoNativeCipherVectorOnWire(t *testing.T) {
	ciphers := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	request := Request{
		HTTPVersion: "1.1", Insecure: true, TLSMinVersion: "1.2", TLSMaxVersion: "1.2",
		TLSCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}
	hello := captureAPIClientHelloBody(t, request)
	if len(hello) < 35 {
		t.Fatal("truncated ClientHello")
	}
	offset := 35 + int(hello[34])
	if offset+2 > len(hello) {
		t.Fatal("truncated cipher vector")
	}
	length := int(binary.BigEndian.Uint16(hello[offset:]))
	offset += 2
	if length%2 != 0 || offset+length > len(hello) {
		t.Fatal("invalid cipher vector")
	}
	var got []uint16
	for end := offset + length; offset < end; offset += 2 {
		got = append(got, binary.BigEndian.Uint16(hello[offset:]))
	}
	// crypto/tls determines preference order; --ciphers selects a set, unlike
	// the explicitly ordered uTLS profile CipherSuites vector.
	slices.Sort(got)
	slices.Sort(ciphers)
	if !slices.Equal(got, ciphers) {
		t.Errorf("wire cipher list = %v, want exactly %v", got, ciphers)
	}
}

func TestClientDoImportedUnsupportedFieldsReportPartialMatchOnWire(t *testing.T) {
	data, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := utlsengine.DecodeClientProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	padding := uint16(32)
	profile.Fields.PaddingLength = &padding
	profile.Fields.ALPSPolicy = "CUSTOM"
	profile.Fields.CustomALPS = []string{"http/1.1"}
	profile.Policy.ShouldMatch = []string{"fields.alps", "fields.padding_length"}
	data, err = json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "alps-padding.json")
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL: server.URL, HTTPVersion: "1.1", Insecure: true,
		TLSProfile: &TLSProfile{ProfilePath: path, Check: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.Response.StatusCode != http.StatusNoContent || len(result.TLSReports) != 1 {
		t.Fatalf("HTTP response=%d reports=%+v", result.Response.StatusCode, result.TLSReports)
	}
	report := result.TLSReports[0]
	if report.CaptureStatus != "PARTIAL_MATCH" || report.Actual == nil {
		t.Fatalf("unsupported optional fields reported as %s instead of PARTIAL_MATCH", report.CaptureStatus)
	}
	for _, field := range []string{"fields.alps", "fields.padding_length"} {
		if !slices.ContainsFunc(report.Diff, func(diff TLSProfileDifference) bool { return diff.Path == field }) {
			t.Errorf("missing unsupported field %s in report %+v", field, report)
		}
	}
}

func captureAPIClientHelloBody(t *testing.T, request Request) []byte {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	capture := &manualClientHelloListener{Listener: server.Listener, hello: make(chan []byte, 1)}
	server.Listener = capture
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()
	request.URL = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.Response.StatusCode != http.StatusNoContent {
		t.Fatal("missing HTTP response after captured TLS")
	}
	select {
	case body := <-capture.hello:
		return body
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil
	}
}

func TestClientDoRejectsUnsupportedProfileMUSTBeforeNetwork(t *testing.T) {
	data, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := utlsengine.DecodeClientProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"fields.alps", "fields.padding_length"} {
		t.Run(field, func(t *testing.T) {
			profile := base
			profile.Policy.MustMatch = []string{field}
			encoded, marshalErr := json.Marshal(profile)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			path := filepath.Join(t.TempDir(), "unsupported-must.json")
			if writeErr := os.WriteFile(path, encoded, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			var connections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("unsupported MUST sent an HTTP request")
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.Start()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, doErr := NewClient().Do(ctx, Request{
				URL:         strings.Replace(server.URL, "http:", "https:", 1),
				HTTPVersion: "1.1", TLSProfile: &TLSProfile{ProfilePath: path},
			})
			if result != nil {
				_ = result.Close()
				t.Error("unsupported MUST returned a Result")
			}
			var unsupported *utlsengine.UnsupportedProfileError
			if !errors.As(doErr, &unsupported) || unsupported.Field != field {
				t.Errorf("error = %v, want typed UNSUPPORTED for %s", doErr, field)
			}
			if connections.Load() != 0 {
				t.Errorf("unsupported MUST opened %d connections", connections.Load())
			}
		})
	}
}
