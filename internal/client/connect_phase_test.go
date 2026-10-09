package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
)

func TestConnectionPhaseContextHonorsEarlierDeadlineAndZero(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deadline, _ := parent.Deadline()
	for _, seconds := range []int{0, 120} {
		ctx, stop := connectionPhaseContext(parent, seconds)
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Errorf("connection deadline = %v (%t), want parent deadline %v", got, ok, deadline)
		}
		stop()
	}
	ctx, stop := connectionPhaseContext(context.Background(), 0)
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		t.Fatalf("zero timeout imposed deadline %v", deadline)
	}
}

func TestWatchConnectionContextClosesCanceledConnection(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	stop := watchConnectionContext(ctx, conn)
	cancel()
	stop()
	if _, err := conn.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("canceled pipe write = %v, want io.ErrClosedPipe", err)
	}
}

func TestWatchConnectionContextDetachesAfterHandshake(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	stop := watchConnectionContext(ctx, conn)
	stop()
	cancel()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("successful connection closed after detaching timeout: %v", err)
	}
	read := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := peer.Read(b[:])
		read <- err
	}()
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatalf("successful connection unusable after context cancellation: %v", err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
}

func TestDialTLSContextCanceledBeforeDial(t *testing.T) {
	var dialed atomic.Bool
	d := &clientDialer{
		cfg: &config.Config{},
		out: output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
		dial: func(string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("unexpected dial")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := d.DialTLSContext(ctx, "tcp", "127.0.0.1:1")
	if conn != nil || !errors.Is(err, context.Canceled) || dialed.Load() {
		t.Fatalf("canceled dial = (%v, %v), socket dialed = %t", conn, err, dialed.Load())
	}
	quicConn, err := d.DialQUIC(ctx, "127.0.0.1:1", nil, nil)
	if quicConn != nil || !errors.Is(err, context.Canceled) || dialed.Load() {
		t.Fatalf("canceled QUIC dial = (%v, %v), socket dialed = %t", quicConn, err, dialed.Load())
	}
}

type closeTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestDialTLSContextClosesConnectionOnHandshakeFailure(t *testing.T) {
	conn, peer := net.Pipe()
	tracked := &closeTrackedConn{Conn: conn}
	defer func() { _ = tracked.Close(); _ = peer.Close() }()
	d := &clientDialer{
		cfg:       &config.Config{ConnectTimeout: 1},
		out:       output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
		tlsConfig: &tls.Config{InsecureSkipVerify: true},
		dial:      func(string, string) (net.Conn, error) { return tracked, nil },
	}
	_ = peer.Close()
	got, err := d.DialTLSContext(context.Background(), "tcp", "127.0.0.1:1")
	if got != nil || err == nil || !tracked.closed.Load() || d.currentConn() != nil {
		t.Fatalf("failed handshake = (%v, %v), closed=%t last=%v", got, err, tracked.closed.Load(), d.currentConn())
	}
}
