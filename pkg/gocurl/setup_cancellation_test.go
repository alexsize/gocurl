package gocurl

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func silentSetupTCP(t *testing.T) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		var greeting [3]byte
		if _, err = io.ReadFull(conn, greeting[:]); err != nil {
			return
		}
		close(started)
		_, _ = io.Copy(io.Discard, conn)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Error("silent TCP fixture did not stop")
		}
	})
	return listener.Addr().String(), started, closed
}

func runCanceledSetup(t *testing.T, request Request, started, closed <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		result, err := NewClient().Do(ctx, request)
		if result != nil {
			_ = result.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("connection setup did not begin")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Do() = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("setup ignored cancellation")
	}
	if closed != nil {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("setup socket remained open")
		}
	}
}

func TestClientDoCancellationClosesProxySetup(t *testing.T) {
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			addr, started, closed := silentSetupTCP(t)
			runCanceledSetup(t, Request{
				URL:           "http://127.0.0.1:9/",
				HTTPVersion:   "1.1",
				ProxyURL:      scheme + "://" + addr,
				ProxyInsecure: scheme == "https",
			}, started, closed)
		})
	}
}

func TestClientDoCancellationClosesHTTP2ProxyConnect(t *testing.T) {
	started, closed := make(chan struct{}), make(chan struct{})
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		close(started)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		close(closed)
	}))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	runCanceledSetup(t, Request{
		URL: "http://127.0.0.1:9/", ProxyURL: proxy.URL, ProxyInsecure: true, ProxyHTTP2Connect: true,
	}, started, closed)
}

func TestClientDoCancellationInterruptsSplitDelay(t *testing.T) {
	addr, started, closed := silentSetupTCP(t)
	runCanceledSetup(t, Request{
		URL: "https://" + addr + "/", HTTPVersion: "1.1", Insecure: true,
		TLSSplitHello: &TLSSplitHello{FirstChunkSize: 7, Delay: 5 * time.Second},
	}, started, closed)
}

func silentSetupDNS(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		var packet [1500]byte
		if _, _, err := conn.ReadFrom(packet[:]); err == nil {
			close(started)
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Error("DNS fixture did not stop")
		}
	})
	return conn.LocalAddr().String(), started
}

func TestClientDoCancellationInterruptsDNSAndECHDiscovery(t *testing.T) {
	for _, ech := range []bool{false, true} {
		name := "host"
		if ech {
			name = "ech"
		}
		t.Run(name, func(t *testing.T) {
			dnsAddress, started := silentSetupDNS(t)
			request := Request{URL: "http://target.example.test:9/", DNSServers: []string{dnsAddress}}
			var closed <-chan struct{}
			if ech {
				addr, _, targetClosed := silentSetupTCP(t)
				request.URL, request.TLSServerName, request.ECH = "https://"+addr+"/", "target.example.test", true
				request.Insecure, closed = true, targetClosed
			}
			runCanceledSetup(t, request, started, closed)
		})
	}
}

func TestClientDoConnectTimeoutBoundsDNSAndProxySetup(t *testing.T) {
	for _, scheme := range []string{"dns", "http", "https", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			request := Request{
				URL:            "http://127.0.0.1:9/",
				ConnectTimeout: time.Second,
				ProxyInsecure:  scheme == "https",
			}
			if scheme == "dns" {
				addr, _ := silentSetupDNS(t)
				request.URL, request.DNSServers = "http://target.example.test:9/", []string{addr}
			} else {
				addr, _, _ := silentSetupTCP(t)
				request.ProxyURL = scheme + "://" + addr
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			started := time.Now()
			result, err := NewClient().Do(ctx, request)
			if result != nil {
				_ = result.Close()
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Do() = %v, want deadline exceeded", err)
			}
			if elapsed := time.Since(started); elapsed < 800*time.Millisecond || elapsed > 2500*time.Millisecond {
				t.Fatalf("connection timeout took %v, want approximately one second", elapsed)
			}
		})
	}
}
