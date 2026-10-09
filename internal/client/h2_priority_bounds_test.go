package client

import (
	"bytes"
	"net"
	"testing"

	"github.com/ameshkov/gocurl/internal/config"
	"golang.org/x/net/http2"
)

type priorityCaptureConn struct {
	net.Conn
	bytes.Buffer
}

func (c *priorityCaptureConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *priorityCaptureConn) Read(p []byte) (int, error)  { return c.Buffer.Read(p) }

func TestWriteH2PriorityFrameWeightBounds(t *testing.T) {
	for _, weight := range []uint16{0, 1, 256, 257, 65535} {
		conn := &priorityCaptureConn{}
		err := writeH2PriorityFrame(conn, 1, &config.HTTP2Priority{Weight: weight})
		if weight == 0 || weight > 256 {
			if err == nil || conn.Len() != 0 {
				t.Fatalf("weight %d: err=%v, bytes=%d; want error before write", weight, err, conn.Len())
			}
			continue
		}
		if err != nil {
			t.Fatalf("weight %d: %v", weight, err)
		}
		frame, err := http2.NewFramer(nil, bytes.NewReader(conn.Bytes())).ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		priority, ok := frame.(*http2.PriorityFrame)
		if !ok || uint16(priority.Weight)+1 != weight {
			t.Fatalf("weight %d: frame=%+v", weight, frame)
		}
	}
}
