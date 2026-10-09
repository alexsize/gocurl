package client

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConnectionPhaseContextRestoresRequestDeadline(t *testing.T) {
	requestCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	dialCtx := context.WithValue(context.WithoutCancel(requestCtx), connectionRequestContextKey{}, requestCtx)
	ctx, stop := connectionPhaseContext(dialCtx, 1)
	defer stop()
	want, _ := requestCtx.Deadline()
	got, ok := ctx.Deadline()
	if !ok || !got.Equal(want) {
		t.Fatalf("restored deadline = %v (%t), want %v", got, ok, want)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("restored deadline error = %v, want DeadlineExceeded", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("detached transport context lost request deadline")
	}
}

func TestConnectionPhaseContextRestoresRequestCancellation(t *testing.T) {
	requestCtx, cancel := context.WithCancel(context.Background())
	dialCtx := context.WithValue(context.WithoutCancel(requestCtx), connectionRequestContextKey{}, requestCtx)
	ctx, stop := connectionPhaseContext(dialCtx, 0)
	defer stop()
	cancel()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("restored cancellation error = %v, want Canceled", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("detached transport context lost request cancellation")
	}
}
