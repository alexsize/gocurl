package gocurl

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestClientDoBodyLengthZeroNegativeAndNilSemanticsOnWire(t *testing.T) {
	payload := []byte{0, 255, 13, 10, 128, 1}
	for _, tc := range []struct {
		name                 string
		body                 bool
		declared, wantLength int64
		chunked              bool
	}{
		{name: "known", body: true, declared: 6, wantLength: 6},
		{name: "zero-is-unknown", body: true, wantLength: -1, chunked: true},
		{name: "negative-is-unknown", body: true, declared: -1, wantLength: -1, chunked: true},
		{name: "minimum-is-unknown", body: true, declared: -1 << 63, wantLength: -1, chunked: true},
		{name: "nil-body-ignores-positive-length", declared: 6},
		{name: "nil-body-ignores-negative-length", declared: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read wire body: %v", err)
				}
				want := payload
				if !tc.body {
					want = nil
				}
				if !bytes.Equal(got, want) || r.ContentLength != tc.wantLength ||
					slices.Contains(r.TransferEncoding, "chunked") != tc.chunked {
					t.Errorf("wire body=%v length=%d transfer=%v; want body=%v length=%d chunked=%t",
						got, r.ContentLength, r.TransferEncoding, want, tc.wantLength, tc.chunked)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			request := Request{URL: server.URL, HTTPVersion: "1.1", Method: http.MethodPost, ContentLength: tc.declared}
			if tc.body {
				request.Body = bytes.NewReader(payload)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := NewClient().Do(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if result.Response.StatusCode != http.StatusNoContent {
				t.Fatal("missing body fixture response")
			}
		})
	}
}

func TestClientDoWildcardResolvePreservesHostAndSNI(t *testing.T) {
	const hostname = "wildcard-api.example.test"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != hostname {
			t.Errorf("wire TLS SNI: %+v", r.TLS)
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || host != hostname {
			t.Errorf("wire Host=%q error=%v", r.Host, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL:      "https://" + net.JoinHostPort(hostname, port),
		Insecure: true, HTTPVersion: "1.1", Resolve: map[string][]string{"*": {"127.0.0.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.Response.StatusCode != http.StatusNoContent {
		t.Fatal("wildcard did not reach local target")
	}
}
