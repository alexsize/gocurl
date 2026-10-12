package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

// delayedDeadlineContext models a timer callback that has not yet published Err.
type delayedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c delayedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestSOCKSContextErrorPreservesDeadlineCauseBeforeTimerCallback(t *testing.T) {
	past := delayedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
	future := delayedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(time.Hour)}
	wrappedTimeout := fmt.Errorf("SOCKS greeting read: %w", os.ErrDeadlineExceeded)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		err, want error
	}{
		{"delayed-timer", past, wrappedTimeout, context.DeadlineExceeded},
		{"bare-timeout", past, os.ErrDeadlineExceeded, context.DeadlineExceeded},
		{"independent-timeout", future, wrappedTimeout, wrappedTimeout},
		{"no-context-deadline", context.Background(), wrappedTimeout, wrappedTimeout},
		{"unrelated-error", past, io.EOF, io.EOF},
		{"successful-dial", past, nil, nil},
		{"explicit-cancel-wins", cancelled, wrappedTimeout, context.Canceled},
		{"cancelled-success", cancelled, nil, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := socksContextError(tc.ctx, tc.err)
			if !errors.Is(got, tc.want) {
				t.Errorf("error = %v, want %v", got, tc.want)
			}
		})
	}
}
