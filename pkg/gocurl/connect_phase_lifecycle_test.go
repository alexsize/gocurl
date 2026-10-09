package gocurl

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestClientDoCancellationClosesTargetTLSConnection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request Request
	}{
		{name: "standard", request: Request{HTTPVersion: "1.1"}},
		{name: "pq", request: Request{PostQuantum: true}},
		{name: "utls", request: Request{HTTPVersion: "1.1", TLSProfile: &TLSProfile{
			ClientHello: &TLSClientHello{Preset: "Chrome-120", ALPN: []string{"http/1.1"}},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, helloRead, closed := stalledTargetTLS(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := tc.request
			request.URL, request.Insecure = url, true
			done := make(chan error, 1)
			go func() {
				result, err := NewClient().Do(ctx, request)
				if result != nil {
					_ = result.Close()
				}
				done <- err
			}()
			select {
			case err := <-helloRead:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("ClientHello not sent")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Do() = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Do() did not honor cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("target connection remained open after cancellation")
			}
		})
	}
}

func TestClientDoConnectTimeoutDoesNotLimitResponse(t *testing.T) {
	for _, version := range []string{"1.1", "2", "3"} {
		t.Run(version, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(1200 * time.Millisecond):
					_, _ = io.WriteString(w, "ok")
				case <-r.Context().Done():
				}
			})
			target := httptest.NewUnstartedServer(handler)
			target.EnableHTTP2 = true
			target.StartTLS()
			defer target.Close()
			url := target.URL
			if version == "3" {
				packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = packetConn.Close() }()
				server := &http3.Server{
					Handler: handler,
					TLSConfig: &tls.Config{
						Certificates: target.TLS.Certificates,
						NextProtos:   []string{"h3"},
					},
				}
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					_ = server.Serve(packetConn)
				}()
				defer func() {
					_ = server.Close()
					select {
					case <-serverDone:
					case <-time.After(time.Second):
						t.Error("HTTP/3 server did not stop")
					}
				}()
				url = "https://" + packetConn.LocalAddr().String() + "/"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := NewClient().Do(ctx, Request{
				URL: url, HTTPVersion: version, Insecure: true, ConnectTimeout: time.Second,
			})
			if err != nil {
				t.Fatalf("request after successful handshake: %v", err)
			}
			defer func() { _ = result.Close() }()
			body, err := io.ReadAll(result.Response.Body)
			if err != nil || string(body) != "ok" {
				t.Fatalf("response body = %q, err=%v; connection timeout leaked into response", body, err)
			}
		})
	}
}
