package proxy

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"golang.org/x/net/http2"
)

// h2TunnelConn presents an HTTP/2 CONNECT stream as a full-duplex net.Conn.
type h2TunnelConn struct {
	body      io.ReadCloser
	writer    *io.PipeWriter
	client    *http2.ClientConn
	proxyConn net.Conn
	cancel    context.CancelFunc

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	timer         *time.Timer
	expired       atomic.Bool
	closeOnce     sync.Once
	closeErr      error
}

func (c *h2TunnelConn) Read(p []byte) (int, error) {
	n, err := c.body.Read(p)
	if err != nil && c.expired.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *h2TunnelConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if err != nil && c.expired.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *h2TunnelConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()
		_ = c.writer.Close()
		c.cancel()
		_ = c.body.Close()
		c.closeErr = c.client.Close()
	})
	return c.closeErr
}

func (c *h2TunnelConn) LocalAddr() net.Addr  { return c.proxyConn.LocalAddr() }
func (c *h2TunnelConn) RemoteAddr() net.Addr { return c.proxyConn.RemoteAddr() }

func (c *h2TunnelConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *h2TunnelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.updateDeadlineLocked()
	return nil
}

func (c *h2TunnelConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	c.updateDeadlineLocked()
	return nil
}

func (c *h2TunnelConn) updateDeadlineLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	deadline := c.readDeadline
	if deadline.IsZero() || (!c.writeDeadline.IsZero() && c.writeDeadline.Before(deadline)) {
		deadline = c.writeDeadline
	}
	if deadline.IsZero() {
		return
	}
	delay := time.Until(deadline)
	if delay < 0 {
		delay = 0
	}
	c.timer = time.AfterFunc(delay, func() {
		c.expired.Store(true)
		c.cancel()
	})
}

func (c *h2TunnelConn) ProxyTLSObservations() []utlsengine.ProfileCheckResult {
	if provider, ok := c.proxyConn.(interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	}); ok {
		return provider.ProxyTLSObservations()
	}
	return nil
}
