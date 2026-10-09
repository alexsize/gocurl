package gocurl

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientDoTLSSplitHelloOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probe := &tlsSplitProbeListener{Listener: listener, gap: make(chan bool, 1)}
	// #nosec G112 -- Loopback-only fixture closed by test cleanup, not a deployed HTTP server.
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(tls.NewListener(probe, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		}))
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = probe.Close()
		<-serveDone
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL:         "https://" + listener.Addr().String() + "/",
		HTTPVersion: "1.1",
		Insecure:    true,
		TLSSplitHello: &TLSSplitHello{
			FirstChunkSize: 5,
			Delay:          250 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("Client.Do() with split ClientHello: %v", err)
	}
	defer result.Close()
	if got, want := result.Response.StatusCode, http.StatusNoContent; got != want {
		t.Fatalf("response status = %d, want %d", got, want)
	}
	select {
	case gapObserved := <-probe.gap:
		if !gapObserved {
			t.Fatal("server received ClientHello continuation before the configured delay elapsed")
		}
	case <-ctx.Done():
		t.Fatalf("waiting for ClientHello split observation: %v", ctx.Err())
	}
}

type tlsSplitProbeListener struct {
	net.Listener
	gap chan bool
}

func (l *tlsSplitProbeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var header [5]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if header[0] != 22 {
		_ = conn.Close()
		return nil, errors.New("first client TLS record is not a handshake")
	}
	if err = conn.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var next [1]byte
	_, probeErr := conn.Read(next[:])
	gapObserved := false
	var netErr net.Error
	if errors.As(probeErr, &netErr) && netErr.Timeout() {
		gapObserved = true
	} else if probeErr == nil {
		// Preserve a byte received before the probe deadline when replaying the
		// TLS stream below.
		remainder := make([]byte, (int(header[3])<<8|int(header[4]))-1)
		remainder[0] = next[0]
		if _, err = io.ReadFull(conn, remainder[1:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Time{})
		l.gap <- false
		return &tlsSplitReplayConn{
			Conn:   conn,
			reader: io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(remainder), conn),
		}, nil
	} else {
		_ = conn.Close()
		return nil, probeErr
	}
	_ = conn.SetReadDeadline(time.Time{})
	recordRemainder := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err = io.ReadFull(conn, recordRemainder); err != nil {
		_ = conn.Close()
		return nil, err
	}
	select {
	case l.gap <- gapObserved:
	default:
	}
	return &tlsSplitReplayConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(recordRemainder), conn),
	}, nil
}

type tlsSplitReplayConn struct {
	net.Conn
	reader io.Reader
}

func (c *tlsSplitReplayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
