// Package splittls implements the --tls-split-hello logic and allows splitting
// TLS ClientHello.
package splittls

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ameshkov/gocurl/internal/client/dialer"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/output"
)

// CreateContextDialFunc wraps a context-aware connection for ClientHello splitting.
func CreateContextDialFunc(
	firstChunkSize, delay int,
	base dialer.ContextDialFunc,
	out *output.Output,
) dialer.ContextDialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &splitTLSConn{Conn: conn, baseConn: conn, firstChunkSize: firstChunkSize, delay: delay, out: out}, nil
	}
}

// CreateDialFunc creates a dialFunc that splits the TLS ClientHello in two
// parts.
func CreateDialFunc(
	firstChunkSize int,
	delay int,
	baseDial dialer.DialFunc,
	out *output.Output,
) (f dialer.DialFunc) {
	out.Debug(
		"Splitting TLS ClientHello is enabled. First chunk size is %d, delay is %d",
		firstChunkSize,
		delay,
	)

	return func(network, addr string) (conn net.Conn, err error) {
		conn, err = baseDial(network, addr)
		if err != nil {
			return nil, err
		}

		return &splitTLSConn{
			Conn:           conn,
			baseConn:       conn,
			firstChunkSize: firstChunkSize,
			delay:          delay,
			out:            out,
		}, nil
	}
}

// splitTLSConn is the implementation of net.Conn which only purpose is wait for
// the ClientHello packet and split it in two parts when it is written.
type splitTLSConn struct {
	net.Conn
	writeMu   sync.Mutex
	closeInit sync.Once
	closeOnce sync.Once
	closeCh   chan struct{}

	// baseConn is the underlying TCP connection.
	baseConn net.Conn

	// firstChunkSize is the size of the first chunk of ClientHello.
	firstChunkSize int

	// delay is time to wait in milliseconds before sending the second part.
	delay int

	// out is required for debug-level logging.
	out *output.Output

	// writeCnt is the number of Write calls.
	writeCnt int

	// splitDone is set to true when we encounter the first TLS packet and
	// split it OR if there were more than 5 packets send through the
	// connection. Why 2? We assume that the first packet can be proxy
	// authorization and the second must be ClientHello in this case.
	splitDone bool
}

// type check
var _ net.Conn = (*splitTLSConn)(nil)

// isClientHello checks if the packet is ClientHello.
func (c *splitTLSConn) isClientHello(b []byte) (ok bool) {
	if c.writeCnt > 5 || c.splitDone || len(b) < 6 {
		return false
	}

	// Check if the record type is handshake (0x16)
	if b[0] != 0x16 {
		return false
	}

	// Check for TLS version
	if b[1] != 0x03 {
		return false
	}

	// Check if the message type is ClientHello (0x01)
	if b[5] != 0x01 {
		return false
	}

	return true
}

// Write implements net.Conn for *splitTLSConn. Its purpose is to wait until
// the first TLS packet (ClientHello) and then apply the split logic.
func (c *splitTLSConn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.writeCnt++

	if c.isClientHello(b) {
		c.out.Debug("Found ClientHello, splitting it into parts")
		if c.firstChunkSize >= len(b) {
			return 0, fmt.Errorf(
				"TLS ClientHello split size %d must be smaller than the ClientHello write size %d",
				c.firstChunkSize,
				len(b),
			)
		}

		chunks := [][]byte{
			b[:c.firstChunkSize],
			b[c.firstChunkSize:],
		}

		for i, chunk := range chunks {
			for len(chunk) > 0 {
				var written int
				written, err = c.baseConn.Write(chunk)
				n += written
				chunk = chunk[written:]
				if err != nil {
					return n, err
				}
				if written == 0 {
					return n, io.ErrShortWrite
				}
			}
			if c.delay > 0 && i < len(chunks)-1 {
				timer := time.NewTimer(time.Duration(c.delay) * time.Millisecond)
				select {
				case <-timer.C:
				case <-c.closeDone():
					timer.Stop()
					return n, net.ErrClosed
				}
			}
		}

		return n, err
	}

	return c.baseConn.Write(b)
}

func (c *splitTLSConn) closeDone() <-chan struct{} {
	c.closeInit.Do(func() { c.closeCh = make(chan struct{}) })
	return c.closeCh
}

// Close interrupts the artificial split delay as well as network I/O.
func (c *splitTLSConn) Close() error {
	c.closeDone()
	c.closeOnce.Do(func() { close(c.closeCh) })
	return c.Conn.Close()
}

// ProxyTLSObservations forwards metadata recorded by an HTTPS proxy dialer.
func (c *splitTLSConn) ProxyTLSObservations() []utlsengine.ProfileCheckResult {
	provider, ok := c.Conn.(interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	})
	if !ok {
		return nil
	}
	return provider.ProxyTLSObservations()
}
