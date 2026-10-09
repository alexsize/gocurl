package client

import (
	"bytes"
	"io"
	"testing"

	"github.com/ameshkov/gocurl/internal/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func h2StreamFixture(t *testing.T) []byte {
	t.Helper()
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.test"},
		{Name: ":path", Value: "/"},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	var wire bytes.Buffer
	wire.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&wire, nil)
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
	); err != nil {
		t.Fatal(err)
	}
	split := block.Len() / 2
	if err := framer.WriteHeaders(
		http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes()[:split]},
	); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteContinuation(1, true, block.Bytes()[split:]); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteData(1, true, []byte("abcde")); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func rewriteH2StreamForTest(t *testing.T, parts ...[]byte) []byte {
	t.Helper()
	capture := &priorityCaptureConn{}
	conn := &h2PseudoOrderConn{
		Conn:            capture,
		settingsOrder:   []uint16{uint16(http2.SettingInitialWindowSize), uint16(http2.SettingHeaderTableSize)},
		order:           []string{":path", ":scheme", ":authority", ":method"},
		headerFrameSize: 4,
		dataFrameSize:   2,
		framePadding:    2,
		priority:        &config.HTTP2Priority{Weight: 256},
	}
	for _, part := range parts {
		if n, err := conn.Write(part); err != nil || n != len(part) {
			t.Fatalf("Write(%d bytes) = %d, %v", len(part), n, err)
		}
	}
	if len(conn.pending) != 0 || len(conn.block) != 0 || conn.streamID != 0 {
		t.Fatal("complete stream left a pending frame or header block")
	}
	return append([]byte(nil), capture.Bytes()...)
}

func TestH2FramingIndependentOfWriteBoundaries(t *testing.T) {
	wire := h2StreamFixture(t)
	want := rewriteH2StreamForTest(t, wire)
	for split := 0; split <= len(wire); split++ {
		if got := rewriteH2StreamForTest(t, wire[:split], wire[split:]); !bytes.Equal(got, want) {
			t.Fatalf("split at %d changed the rewritten wire stream", split)
		}
	}
	parts := make([][]byte, len(wire))
	for i := range wire {
		parts[i] = wire[i : i+1]
	}
	if got := rewriteH2StreamForTest(t, parts...); !bytes.Equal(got, want) {
		t.Fatal("single-byte writes changed the rewritten wire stream")
	}
	verifyH2StreamForTest(t, want)
}

func verifyH2StreamForTest(t *testing.T, wire []byte) {
	t.Helper()
	if !bytes.HasPrefix(wire, []byte(http2.ClientPreface)) {
		t.Fatal("missing client preface")
	}
	framer := http2.NewFramer(nil, bytes.NewReader(wire[len(http2.ClientPreface):]))
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok || settings.NumSettings() != 2 || settings.Setting(0).ID != http2.SettingInitialWindowSize {
		t.Fatalf("settings = %+v", frame)
	}
	frame, err = framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	priority, ok := frame.(*http2.PriorityFrame)
	if !ok || priority.Weight != 255 || priority.StreamID != 1 {
		t.Fatalf("priority = %+v", frame)
	}
	verifyH2HeadersForTest(t, framer)
	var payload []byte
	var endStream bool
	for {
		frame, err = framer.ReadFrame()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, isData := frame.(*http2.DataFrame)
		if !isData || endStream || data.StreamID != 1 || len(data.Data()) > 2 || !data.Flags.Has(http2.FlagDataPadded) {
			t.Fatalf("unexpected DATA framing: %+v", frame)
		}
		payload = append(payload, data.Data()...)
		endStream = data.StreamEnded()
	}
	if string(payload) != "abcde" || !endStream {
		t.Fatalf("payload = %q, END_STREAM = %t", payload, endStream)
	}
}

func verifyH2HeadersForTest(t *testing.T, framer *http2.Framer) {
	t.Helper()
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	headers, ok := frame.(*http2.HeadersFrame)
	if !ok || headers.StreamEnded() || headers.StreamID != 1 || !headers.Flags.Has(http2.FlagHeadersPadded) {
		t.Fatalf("headers = %+v", frame)
	}
	block := append([]byte(nil), headers.HeaderBlockFragment()...)
	complete := headers.HeadersEnded()
	for !complete {
		frame, err = framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		continuation, isContinuation := frame.(*http2.ContinuationFrame)
		if !isContinuation || continuation.StreamID != 1 || len(continuation.HeaderBlockFragment()) > 4 {
			t.Fatalf("continuation = %+v", frame)
		}
		block = append(block, continuation.HeaderBlockFragment()...)
		complete = continuation.HeadersEnded()
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(block)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{":path", ":scheme", ":authority", ":method"}
	if len(fields) != len(want) {
		t.Fatalf("header fields = %+v", fields)
	}
	for i, name := range want {
		if fields[i].Name != name {
			t.Fatalf("header[%d] = %q, want %q", i, fields[i].Name, name)
		}
	}
}

func TestH2RejectsInterruptedContinuation(t *testing.T) {
	for _, wrongStream := range []bool{false, true} {
		var wire bytes.Buffer
		wire.WriteString(http2.ClientPreface)
		framer := http2.NewFramer(&wire, nil)
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1}); err != nil {
			t.Fatal(err)
		}
		if wrongStream {
			if err := framer.WriteContinuation(3, true, nil); err != nil {
				t.Fatal(err)
			}
		} else if err := framer.WritePing(false, [8]byte{}); err != nil {
			t.Fatal(err)
		}
		conn := &h2PseudoOrderConn{Conn: &priorityCaptureConn{}, headerFrameSize: 4}
		if _, err := conn.Write(wire.Bytes()); err == nil {
			t.Fatal("interrupted HEADERS continuation was accepted")
		}
	}
}
