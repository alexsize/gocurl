package resolve

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"testing"
)

// TCP and UDP ephemeral allocators do not know about each other's Windows
// exclusions. Random independent candidates avoid walking an excluded range.
func listenDualProtocolDNS(
	listenPacket func(string, string) (net.PacketConn, error),
	listen func(string, string) (net.Listener, error),
) (net.Listener, net.PacketConn, error) {
	var lastErr error
	for range 32 {
		port, err := rand.Int(rand.Reader, big.NewInt(65536-1024))
		if err != nil {
			return nil, nil, err
		}
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(1024+int(port.Int64())))
		packetConn, err := listenPacket("udp", address)
		if err != nil {
			lastErr = err
			continue
		}
		listener, err := listen("tcp", packetConn.LocalAddr().String())
		if err == nil {
			return listener, packetConn, nil
		}
		_ = packetConn.Close()
		lastErr = err
	}
	return nil, nil, fmt.Errorf("reserve shared DNS UDP/TCP port: %w", lastErr)
}

func TestDualProtocolDNSFixtureRetriesAndClosesUDP(t *testing.T) {
	var packets []*fixtureDNSPacketConn
	listenPacket := func(string, string) (net.PacketConn, error) {
		conn := &fixtureDNSPacketConn{}
		packets = append(packets, conn)
		return conn, nil
	}
	want := errors.New("TCP port occupied")
	for _, exhausted := range []bool{false, true} {
		t.Run(fmt.Sprint(exhausted), func(t *testing.T) {
			packets = nil
			attempts := 0
			listen := func(string, string) (net.Listener, error) {
				attempts++
				if exhausted || attempts < 3 {
					return nil, want
				}
				return fixtureDNSListener{}, nil
			}
			listener, packet, err := listenDualProtocolDNS(listenPacket, listen)
			closed := packets
			if exhausted {
				if !errors.Is(err, want) || listener != nil || packet != nil || attempts != 32 {
					t.Fatalf("exhaustion: attempts=%d, listener=%v, UDP=%v, error=%v", attempts, listener, packet, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				defer packet.Close()
				if listener.Addr().String() != packet.LocalAddr().String() || attempts != 3 {
					t.Fatalf("shared port: TCP=%v, UDP=%v, attempts=%d", listener.Addr(), packet.LocalAddr(), attempts)
				}
				closed = packets[:len(packets)-1]
			}
			for _, old := range closed {
				if !old.closed {
					t.Fatal("failed TCP bind leaked UDP socket")
				}
			}
		})
	}
}

type fixtureDNSPacketConn struct {
	net.PacketConn
	closed bool
}

func (*fixtureDNSPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
}

func (c *fixtureDNSPacketConn) Close() error { c.closed = true; return nil }

type fixtureDNSListener struct{ net.Listener }

func (fixtureDNSListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
}

func (fixtureDNSListener) Close() error { return nil }

func TestDualProtocolDNSFixturePreservesUDPBindError(t *testing.T) {
	want := errors.New("UDP allocation failed")
	listener, packet, err := listenDualProtocolDNS(
		func(string, string) (net.PacketConn, error) { return nil, want },
		func(string, string) (net.Listener, error) { t.Fatal("TCP dial after UDP failure"); return nil, nil },
	)
	if listener != nil || packet != nil || !errors.Is(err, want) {
		t.Fatalf("UDP failure: listener=%v, UDP=%v, error=%v", listener, packet, err)
	}
}
