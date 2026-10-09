package client

import (
	"context"
	"fmt"
	"net"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/quic-go/quic-go"
)

type quicDialObservation struct {
	profile             utlsengine.ClientProfile
	profileCheckEnabled bool
	reportingEnabled    bool
	connectionID        string
	attempt             int
}

func (d *clientDialer) newQUICObservation(ctx context.Context) quicDialObservation {
	o := quicDialObservation{}
	o.profileCheckEnabled = d.cfg.TLSProfileCheck || d.cfg.TLSProfileStrict
	o.reportingEnabled = d.cfg.OutputJSON || o.profileCheckEnabled
	if d.cfg.TLSProfileDocument != nil {
		o.profile = *d.cfg.TLSProfileDocument
	}
	if o.reportingEnabled {
		o.connectionID = utlsengine.NewConnectionID()
		o.attempt = utlsengine.BeginProfileCheckAttempt(ctx)
	}
	return o
}

func captureQUICClientHellos(cfg *quic.Config, enabled bool) (*quic.Config, chan []byte) {
	hellos := make(chan []byte, 4)
	if !enabled {
		return cfg, hellos
	}
	captured := &quic.Config{}
	if cfg != nil {
		captured = cfg.Clone()
	}
	previousCallback := captured.ClientHelloCallback
	captured.ClientHelloCallback = func(hello []byte) {
		if previousCallback != nil {
			previousCallback(hello)
		}
		select {
		case hellos <- append([]byte(nil), hello...):
		default:
		}
	}
	return captured, hellos
}

func quicPacketConnection(conn net.Conn, addr string) (net.PacketConn, *net.UDPAddr, error) {
	packetConn, ok := conn.(net.PacketConn)
	if !ok {
		return nil, nil, fmt.Errorf("dialer returned not a PacketConn for %s", addr)
	}
	udpAddr, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("dialer returned not a UDPAddr for %s", addr)
	}
	return packetConn, udpAddr, nil
}

func (d *clientDialer) recordQUICOpenFailure(ctx context.Context, err error, o quicDialObservation) {
	d.recordQUICClientHello(ctx, o.profile, nil, false, err, o.connectionID, o.attempt, 1,
		o.profileCheckEnabled, o.reportingEnabled)
}

func (d *clientDialer) dialEarlyQUIC(ctx context.Context, packetConn net.PacketConn, addr *net.UDPAddr,
	cfg *quic.Config,
) (*quic.Conn, error) {
	if length := d.cfg.QUICTransport.ConnectionIDLength; length != 0 {
		transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: length}
		conn, err := transport.DialEarly(ctx, addr, d.tlsConfig, cfg)
		if err != nil {
			_ = transport.Close()
		} else {
			go func() {
				<-conn.Context().Done()
				_ = transport.Close()
			}()
		}
		return conn, err
	}
	return quic.DialEarly(ctx, packetConn, addr, d.tlsConfig, cfg)
}

// DialEarly can return before handshake completion; the connection-phase
// deadline covers this wait even when observation is disabled.
func waitQUICHandshake(ctx context.Context, conn *quic.Conn, err error) error {
	if conn != nil && err == nil {
		select {
		case <-conn.HandshakeComplete():
		case <-conn.Context().Done():
			select {
			case <-conn.HandshakeComplete():
			default:
				err = conn.Context().Err()
			}
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	return connectionPhaseError(ctx, err)
}

func drainQUICClientHellos(hellos <-chan []byte) [][]byte {
	var result [][]byte
	for {
		select {
		case hello := <-hellos:
			result = append(result, hello)
		default:
			return result
		}
	}
}

func waitQUICFirstWrite(ctx context.Context, conn *quic.Conn, firstWrite <-chan struct{}) bool {
	select {
	case <-firstWrite:
		return true
	default:
	}
	if conn == nil {
		return false
	}
	select {
	case <-firstWrite:
		return true
	case <-conn.Context().Done():
	case <-ctx.Done():
	}
	select {
	case <-firstWrite:
		return true
	default:
		return false
	}
}

func (d *clientDialer) reportQUICHandshake(ctx context.Context, conn *quic.Conn,
	hellos [][]byte, packetSent bool, err error, o quicDialObservation,
) error {
	if len(hellos) == 0 {
		hellos = append(hellos, nil)
	}
	strictFailure := ""
	for i, hello := range hellos {
		check := d.recordQUICClientHello(ctx, o.profile, hello, packetSent, err,
			o.connectionID, o.attempt, i+1, o.profileCheckEnabled, true)
		if strictFailure == "" && check.Status != "MATCH" {
			strictFailure = check.Status
		}
	}
	if d.cfg.TLSProfileStrict && strictFailure != "" {
		if conn != nil {
			_ = conn.CloseWithError(0, "TLS ClientHello profile check failed")
		}
		return utlsengine.NewProfileCheckError(strictFailure, nil)
	}
	return nil
}
