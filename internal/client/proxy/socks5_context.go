package proxy

import (
	"context"
	"errors"
	"net"
	"time"
)

// socksContextError handles a socket deadline firing before the context timer.
// Independent socket timeouts remain unchanged until the context deadline expires.
func socksContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	var timeout net.Error
	if err != nil && errors.As(err, &timeout) && timeout.Timeout() {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return err
}
