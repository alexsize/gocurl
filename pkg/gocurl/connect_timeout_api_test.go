package gocurl

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestClientDoConnectTimeoutBoundsHTTPSProxyTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for stalled HTTPS proxy: %v", err)
	}
	defer listener.Close()
	clientHelloRead := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			clientHelloRead <- acceptErr
			return
		}
		defer conn.Close()
		var header [5]byte
		_, readErr := io.ReadFull(conn, header[:])
		if readErr == nil && header[0] != 22 {
			readErr = io.ErrUnexpectedEOF
		}
		clientHelloRead <- readErr
		if readErr == nil {
			_, _ = io.Copy(io.Discard, conn)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	result, doErr := NewClient().Do(ctx, Request{
		URL:            "http://target-that-must-not-be-contacted.example.test/",
		ProxyURL:       "https://" + listener.Addr().String(),
		ProxyInsecure:  true,
		ConnectTimeout: time.Second,
	})
	elapsed := time.Since(started)
	if result != nil {
		_ = result.Close()
	}
	if doErr == nil {
		t.Fatal("Client.Do() succeeded although the HTTPS proxy never completed TLS")
	}
	if elapsed < 800*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("Client.Do() returned after %v with error %v; want the configured ~1s connect timeout", elapsed, doErr)
	}
	select {
	case readErr := <-clientHelloRead:
		if readErr != nil {
			t.Fatalf("read client TLS record at stalled proxy: %v", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not begin the HTTPS proxy TLS handshake")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("stalled HTTPS proxy connection did not close after timeout")
	}
}
