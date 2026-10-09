package client

import (
	"context"
	"net"
	"time"
)

// connectionRequestContextKey retains request cancellation when net/http strips
// cancellation and deadlines from the context passed to a custom TLS dialer.
type connectionRequestContextKey struct{}

// connectionPhaseContext limits connection establishment, not response I/O.
// The caller must cancel it only after detaching connection cancellation.
func connectionPhaseContext(ctx context.Context, seconds int) (context.Context, context.CancelFunc) {
	requestCtx, _ := ctx.Value(connectionRequestContextKey{}).(context.Context)
	var cancel context.CancelFunc
	if seconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	if requestCtx == nil {
		return ctx, cancel
	}
	if deadline, ok := requestCtx.Deadline(); ok {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithDeadline(ctx, deadline)
		cancelParent := cancel
		cancel = func() { cancelDeadline(); cancelParent() }
	}
	// The inherited deadline has its own timer.  Do not turn its expiration
	// into context.Canceled by racing it with an explicit cancel callback.
	stop := context.AfterFunc(requestCtx, func() {
		if requestCtx.Err() == context.Canceled {
			cancel()
		}
	})
	if requestCtx.Err() == context.Canceled {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

// watchConnectionContext interrupts TLS engines that do not accept a context.
// Its stop function waits for an already-started callback before returning.
func watchConnectionContext(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

// connectionPhaseError preserves cancellation instead of a socket-close error.
func connectionPhaseError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}
