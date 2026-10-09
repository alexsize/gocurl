package splittls

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/output"
)

func TestSplitTLSConnRejectsOversizedFirstChunk(t *testing.T) {
	hello := []byte{0x16, 0x03, 0x03, 0, 4, 0x01, 0, 0}
	base := &writeCaptureConn{}
	conn := &splitTLSConn{
		Conn:           base,
		baseConn:       base,
		firstChunkSize: len(hello),
		out:            output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
	}
	if n, err := conn.Write(hello); err == nil || n != 0 {
		t.Fatalf("Write() = %d, %v; want an error and no bytes written", n, err)
	}
	if len(base.writes) != 0 {
		t.Fatalf("underlying writes = %d, want none", len(base.writes))
	}
}

func TestSplitTLSConnWritesConfiguredChunks(t *testing.T) {
	hello := []byte{0x16, 0x03, 0x03, 0, 4, 0x01, 0, 0}
	base := &writeCaptureConn{}
	conn := &splitTLSConn{
		Conn:           base,
		baseConn:       base,
		firstChunkSize: 3,
		out:            output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
	}
	n, err := conn.Write(hello)
	if err != nil || n != len(hello) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(hello))
	}
	if len(base.writes) != 2 || !bytes.Equal(base.writes[0], hello[:3]) || !bytes.Equal(base.writes[1], hello[3:]) {
		t.Fatalf("underlying writes = %x, want chunks %x and %x", base.writes, hello[:3], hello[3:])
	}
}

func TestSplitTLSConnWritesAllBytesAfterUnderlyingShortWrites(t *testing.T) {
	hello := []byte{0x16, 0x03, 0x03, 0, 4, 0x01, 0, 0}
	base := &writeCaptureConn{maxWrite: 2}
	conn := &splitTLSConn{
		Conn:           base,
		baseConn:       base,
		firstChunkSize: 3,
		out:            output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
	}
	n, err := conn.Write(hello)
	if err != nil || n != len(hello) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(hello))
	}
	var got []byte
	for _, write := range base.writes {
		got = append(got, write...)
	}
	if !bytes.Equal(got, hello) {
		t.Fatalf("underlying bytes = %x, want complete ClientHello %x", got, hello)
	}
}

func TestSplitTLSConnSerializesConcurrentWrites(t *testing.T) {
	const writeCount = 32
	base := &writeCaptureConn{}
	conn := &splitTLSConn{Conn: base, baseConn: base, firstChunkSize: 3}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range writeCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if n, err := conn.Write([]byte{0x17}); err != nil || n != 1 {
				t.Errorf("Write() = %d, %v; want 1, nil", n, err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if len(base.writes) != writeCount {
		t.Fatalf("underlying writes = %d, want %d", len(base.writes), writeCount)
	}
}

type writeCaptureConn struct {
	net.Conn
	writes   [][]byte
	maxWrite int
}

func (c *writeCaptureConn) Write(p []byte) (int, error) {
	if c.maxWrite > 0 && len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestSplitTLSConnForwardsProxyObservations(t *testing.T) {
	want := []utlsengine.ProfileCheckResult{{Status: "OBSERVED"}}
	conn := &splitTLSConn{Conn: proxyObservationConn{checks: want}}
	got := conn.ProxyTLSObservations()
	if len(got) != 1 || got[0].Status != want[0].Status {
		t.Fatalf("ProxyTLSObservations() = %+v, want %+v", got, want)
	}
}

type proxyObservationConn struct {
	net.Conn
	checks []utlsengine.ProfileCheckResult
}

func (c proxyObservationConn) ProxyTLSObservations() []utlsengine.ProfileCheckResult {
	return c.checks
}
