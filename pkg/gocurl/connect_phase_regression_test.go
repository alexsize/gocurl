package gocurl

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stalledTargetTLS reads the ClientHello, then waits for the client to close.
func stalledTargetTLS(t *testing.T) (string, <-chan error, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, cancel := context.WithCancel(context.Background())
	helloRead := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			helloRead <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(serverCtx, func() { _ = conn.Close() })
		defer stop()
		var header [5]byte
		_, readErr := io.ReadFull(conn, header[:])
		if readErr == nil && header[0] != 22 {
			readErr = io.ErrUnexpectedEOF
		}
		helloRead <- readErr
		if readErr == nil {
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("stalled TLS fixture did not stop")
		}
	})
	return "https://" + listener.Addr().String() + "/", helloRead, done
}

func TestClientDoConnectTimeoutBoundsTargetTLSHandshakes(t *testing.T) {
	profilePath := filepath.Join("..", "..", "internal", "client", "utlsengine", "testdata", "profile-v1-valid.json")
	for _, tc := range []struct {
		name    string
		request Request
	}{
		{name: "standard-http1", request: Request{HTTPVersion: "1.1"}},
		{name: "standard-http2", request: Request{HTTPVersion: "2"}},
		{name: "manual-utls", request: Request{HTTPVersion: "1.1", TLSProfile: &TLSProfile{
			ClientHello: &TLSClientHello{Preset: "Chrome-120", ALPN: []string{"http/1.1"}},
		}}},
		{name: "imported-utls", request: Request{TLSProfile: &TLSProfile{ProfilePath: profilePath, Check: true}}},
		{name: "post-quantum", request: Request{PostQuantum: true}},
		{name: "ech-grease", request: Request{ECHGrease: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, helloRead, closed := stalledTargetTLS(t)
			request := tc.request
			request.URL = url
			request.Insecure = true
			request.ConnectTimeout = time.Second
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			started := time.Now()
			result, err := NewClient().Do(ctx, request)
			if result != nil {
				_ = result.Close()
			}
			elapsed := time.Since(started)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Do() = %v, want connection deadline exceeded", err)
			}
			if elapsed < 800*time.Millisecond || elapsed > 2500*time.Millisecond {
				t.Fatalf("Do() took %v, want approximately one second", elapsed)
			}
			select {
			case readErr := <-helloRead:
				if readErr != nil {
					t.Fatalf("read target ClientHello: %v", readErr)
				}
			case <-time.After(time.Second):
				t.Fatal("target ClientHello was not sent")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("target connection was not closed after timeout")
			}
		})
	}
}

func TestClientDoConnectTimeoutBoundsQUICHandshake(t *testing.T) {
	for _, length := range []int{0, 8} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			started := time.Now()
			result, err := NewClient().Do(ctx, Request{
				URL: "https://" + listener.LocalAddr().String() + "/", HTTPVersion: "3",
				Insecure: true, ConnectTimeout: time.Second,
				QUICTransport: QUICTransport{ConnectionIDLength: length},
			})
			if result != nil {
				_ = result.Close()
			}
			elapsed := time.Since(started)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Do() = %v, want connection deadline exceeded", err)
			}
			if elapsed < 800*time.Millisecond || elapsed > 2500*time.Millisecond {
				t.Fatalf("Do() took %v, want approximately one second", elapsed)
			}
			if err = listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var packet [1500]byte
			if n, _, readErr := listener.ReadFrom(packet[:]); readErr != nil || n == 0 {
				t.Fatalf("QUIC Initial not received: n=%d err=%v", n, readErr)
			}
		})
	}
}

func TestClientDoRejectsPostQuantumImportedProfileBeforeNetwork(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL: "https://" + listener.Addr().String() + "/", PostQuantum: true,
		TLSProfile: &TLSProfile{ProfilePath: filepath.Join(
			"..", "..", "internal", "client", "utlsengine", "testdata", "profile-v1-valid.json",
		)},
	})
	if result != nil {
		_ = result.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "post-quantum") {
		t.Fatalf("Do() = %v, want post-quantum compatibility error", err)
	}
	if err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if conn != nil {
		_ = conn.Close()
		t.Fatal("incompatible profile opened a target connection")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("Accept() = %v, want no connection", err)
	}
}
