package dialer

import (
	"context"
	"net"
)

// ContextDialFunc opens a connection with cancellation and a shared deadline.
type ContextDialFunc func(context.Context, string, string) (net.Conn, error)

// Dial implements Dialer for legacy callers.
func (f ContextDialFunc) Dial(network, addr string) (net.Conn, error) {
	return f(context.Background(), network, addr)
}

// DialContext implements the context-aware dialer interface.
func (f ContextDialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// DialContext uses a context-aware dialer when available. Legacy external
// dialers retain their original synchronous behavior.
func DialContext(ctx context.Context, d Dialer, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d, ok := d.(interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}); ok {
		return d.DialContext(ctx, network, addr)
	}
	return d.Dial(network, addr)
}

// WatchContext closes conn when ctx ends. Stop waits for an active callback.
func WatchContext(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}
}
