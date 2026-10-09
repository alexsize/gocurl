package client

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestQUICClientHelloCapturePreservesCallbackAndCopiesBytes(t *testing.T) {
	calls := 0
	cfg := &quic.Config{ClientHelloCallback: func(hello []byte) {
		calls++
		hello[0] = 9
	}}
	captured, hellos := captureQUICClientHellos(cfg, true)
	if captured == cfg {
		t.Fatal("observation mutated the caller's QUIC config")
	}
	hello := []byte{1, 2, 3}
	captured.ClientHelloCallback(hello)
	hello[1] = 8
	got := drainQUICClientHellos(hellos)
	if calls != 1 || len(got) != 1 || !bytes.Equal(got[0], []byte{9, 2, 3}) {
		t.Fatalf("calls=%d, captured=%v; want prior callback before independent copy", calls, got)
	}
	cfg.ClientHelloCallback([]byte{1})
	if calls != 2 || len(hellos) != 0 {
		t.Fatal("original config acquired the observation callback")
	}
}

func TestQUICClientHelloCaptureDoesNotBlockWhenFull(t *testing.T) {
	calls := 0
	cfg, hellos := captureQUICClientHellos(&quic.Config{ClientHelloCallback: func([]byte) { calls++ }}, true)
	for i := range 8 {
		cfg.ClientHelloCallback([]byte{byte(i)})
	}
	got := drainQUICClientHellos(hellos)
	if calls != 8 || len(got) != 4 {
		t.Fatalf("callbacks=%d, captures=%d; want 8 callbacks and 4 retained hellos", calls, len(got))
	}
	for i, hello := range got {
		if !bytes.Equal(hello, []byte{byte(i)}) {
			t.Fatalf("capture[%d]=%v, want oldest queued hello", i, hello)
		}
	}
}

func TestQUICClientHelloCaptureDisabledPreservesConfig(t *testing.T) {
	for _, original := range []*quic.Config{nil, {}} {
		cfg, hellos := captureQUICClientHellos(original, false)
		if cfg != original || len(drainQUICClientHellos(hellos)) != 0 {
			t.Fatal("disabled observation changed config or recorded a hello")
		}
	}
	cfg, hellos := captureQUICClientHellos(nil, true)
	cfg.ClientHelloCallback([]byte{1})
	if len(drainQUICClientHellos(hellos)) != 1 {
		t.Fatal("nil config did not enable observation")
	}
}

func TestQUICFirstWriteObservationWithoutConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	firstWrite := make(chan struct{})
	if waitQUICFirstWrite(ctx, nil, firstWrite) {
		t.Fatal("unwritten packet reported as sent")
	}
	close(firstWrite)
	if !waitQUICFirstWrite(ctx, nil, firstWrite) {
		t.Fatal("completed packet write was lost after context cancellation")
	}
}

func TestQUICHandshakeWaitPreservesPhaseErrors(t *testing.T) {
	want := errors.New("dial failure")
	if got := waitQUICHandshake(context.Background(), nil, want); got != want {
		t.Fatalf("dial error=%v, want %v", got, want)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := waitQUICHandshake(ctx, nil, nil); !errors.Is(got, context.Canceled) {
		t.Fatalf("phase error=%v, want cancellation", got)
	}
}
