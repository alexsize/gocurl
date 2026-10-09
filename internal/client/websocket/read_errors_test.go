package websocket

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/ameshkov/gocurl/internal/output"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type frameErrorReader struct{ err error }

func (r frameErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadPreservesFrameHeaderErrors(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}
	for _, tc := range []struct {
		name   string
		source io.Reader
		want   error
	}{
		{"timeout", frameErrorReader{timeout}, timeout},
		{"truncated header", bytes.NewReader([]byte{0x81}), io.ErrUnexpectedEOF},
		{"masked server frame", bytes.NewReader([]byte{0x81, 0x80, 0, 0, 0, 0}), ws.ErrProtocolMaskUnexpected},
		{"clean EOF", bytes.NewReader(nil), io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &wsConn{
				r:   wsutil.NewReader(tc.source, ws.StateClientSide),
				out: output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
			}
			n, err := conn.Read(make([]byte, 16))
			if n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("Read() = %d, %v; want 0, %v", n, err, tc.want)
			}
		})
	}
}

func TestReadPreservesMessageBoundaries(t *testing.T) {
	var wire bytes.Buffer
	for _, message := range []string{"first", "second"} {
		if err := ws.WriteFrame(&wire, ws.NewTextFrame([]byte(message))); err != nil {
			t.Fatal(err)
		}
	}
	conn := &wsConn{
		r:   wsutil.NewReader(&wire, ws.StateClientSide),
		out: output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
	}
	for _, want := range []string{"first", "second", ""} {
		got, err := io.ReadAll(conn)
		if err != nil || string(got) != want {
			t.Fatalf("ReadAll() = %q, %v; want %q, nil", got, err, want)
		}
	}
}

type failedFrameWriter struct{ err error }

func (w failedFrameWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWritePreservesAcceptedCountOnFragmentFailure(t *testing.T) {
	wantError := errors.New("fragment write failure")
	writer := wsutil.NewWriterSize(failedFrameWriter{wantError}, ws.StateClientSide, ws.OpText, 16)
	if _, err := writer.Write([]byte("seed")); err != nil {
		t.Fatal(err)
	}
	wantAccepted := writer.Available()
	if wantAccepted == 0 {
		t.Fatal("fixture has no remaining buffer capacity")
	}
	conn := &wsConn{
		w:   writer,
		out: output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
	}
	n, err := conn.Write(make([]byte, wantAccepted+1))
	if n != wantAccepted || !errors.Is(err, wantError) {
		t.Fatalf("Write() = %d, %v; want %d, %v", n, err, wantAccepted, wantError)
	}
}
