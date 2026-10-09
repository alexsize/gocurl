package gocurl

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/testutil"

	"github.com/quic-go/quic-go/http3"
	"github.com/txthinking/socks5"
)

func TestClientDoHTTP3ThroughSOCKS5AndSOCKS5H(t *testing.T) {
	for _, tc := range []struct {
		name       string
		scheme     string
		targetHost string
		wantATYP   byte
	}{
		{name: "SOCKS5 local DNS", scheme: "socks5", wantATYP: socks5.ATYPIPv4},
		{name: "SOCKS5H proxy DNS", scheme: "socks5h", targetHost: "api-quic-target.test", wantATYP: socks5.ATYPDomain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
			certificate := certificateServer.TLS.Certificates[0]
			certificateServer.Close()

			packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("ListenPacket() error = %v", err)
			}
			requests := make(chan string, 1)
			server := &http3.Server{
				TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests <- r.Proto + " " + r.URL.Path
					_, _ = io.WriteString(w, "API HTTP/3 through SOCKS ok")
				}),
			}
			go func() { _ = server.Serve(packetConn) }()
			t.Cleanup(func() {
				_ = server.Close()
				_ = packetConn.Close()
			})

			target := packetConn.LocalAddr().(*net.UDPAddr)
			proxyAddr, observedATYP, relayErrors := startAPIQUICSOCKSRelay(t, target, tc.targetHost)
			targetHost := target.IP.String()
			if tc.targetHost != "" {
				targetHost = tc.targetHost
			}
			targetURL := "https://" + net.JoinHostPort(targetHost, fmt.Sprint(target.Port)) + "/api-quic-socks"

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			result, err := NewClient().Do(ctx, Request{
				URL:         targetURL,
				ProxyURL:    tc.scheme + "://" + proxyAddr.String(),
				HTTPVersion: "3",
				Insecure:    true,
			})
			if err != nil {
				select {
				case relayErr := <-relayErrors:
					t.Fatalf("Do() over %s failed: %v (SOCKS relay: %v)", tc.scheme, err, relayErr)
				default:
					t.Fatalf("Do() over %s failed: %v", tc.scheme, err)
				}
			}
			defer func() { _ = result.Close() }()
			body, err := io.ReadAll(result.Response.Body)
			if err != nil {
				t.Fatalf("read HTTP/3 response: %v", err)
			}
			if result.Response.ProtoMajor != 3 || result.Response.StatusCode != http.StatusOK ||
				string(body) != "API HTTP/3 through SOCKS ok" {
				t.Fatalf(
					"response = %s %d %q; want HTTP/3 200 and expected body",
					result.Response.Proto,
					result.Response.StatusCode,
					body,
				)
			}
			assertAPIQUICSOCKSTLSReport(t, result, tc.scheme)
			select {
			case got := <-observedATYP:
				if got != tc.wantATYP {
					t.Fatalf("SOCKS UDP destination ATYP = %d, want %d", got, tc.wantATYP)
				}
			case relayErr := <-relayErrors:
				t.Fatalf("SOCKS UDP relay failed: %v", relayErr)
			case <-ctx.Done():
				t.Fatal("timed out waiting for the SOCKS UDP datagram")
			}
			select {
			case got := <-requests:
				if got != "HTTP/3.0 /api-quic-socks" {
					t.Fatalf("target observed %q, want HTTP/3.0 /api-quic-socks", got)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for HTTP/3 request at target")
			}
		})
	}
}

func startAPIQUICSOCKSRelay(
	t *testing.T,
	target *net.UDPAddr,
	targetHost string,
) (*net.TCPAddr, <-chan byte, <-chan error) {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS control connection: %v", err)
	}
	udpRelay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = tcpListener.Close()
		t.Fatalf("listen for SOCKS UDP relay: %v", err)
	}
	t.Cleanup(func() {
		_ = tcpListener.Close()
		_ = udpRelay.Close()
	})
	observedATYP := make(chan byte, 1)
	relayErrors := make(chan error, 1)
	go func() {
		control, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			relayErrors <- acceptErr
			return
		}
		defer control.Close()
		greeting := make([]byte, 2)
		if _, acceptErr = io.ReadFull(control, greeting); acceptErr != nil {
			relayErrors <- acceptErr
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, acceptErr = io.ReadFull(control, methods); acceptErr != nil {
			relayErrors <- acceptErr
			return
		}
		if _, acceptErr = control.Write([]byte{5, 0}); acceptErr != nil {
			relayErrors <- acceptErr
			return
		}
		request := make([]byte, 4)
		if _, acceptErr = io.ReadFull(control, request); acceptErr != nil {
			relayErrors <- acceptErr
			return
		}
		if request[1] != socks5.CmdUDP || request[3] != socks5.ATYPIPv4 {
			relayErrors <- fmt.Errorf("SOCKS UDP ASSOCIATE request = %v", request)
			return
		}
		address := make([]byte, net.IPv4len+2)
		if _, acceptErr = io.ReadFull(control, address); acceptErr != nil {
			relayErrors <- acceptErr
			return
		}
		bound := udpRelay.LocalAddr().(*net.UDPAddr)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, testutil.Uint16(bound.Port))
		reply := append([]byte{5, 0, 0, socks5.ATYPIPv4}, net.ParseIP("127.0.0.1").To4()...)
		reply = append(reply, port...)
		if _, acceptErr = control.Write(reply); acceptErr != nil {
			relayErrors <- acceptErr
			return
		}
		serveAPIQUICSOCKSUDP(udpRelay, target, targetHost, observedATYP, relayErrors)
	}()
	return tcpListener.Addr().(*net.TCPAddr), observedATYP, relayErrors
}

func serveAPIQUICSOCKSUDP(
	relay *net.UDPConn,
	target *net.UDPAddr,
	targetHost string,
	observedATYP chan<- byte,
	relayErrors chan<- error,
) {
	buffer := make([]byte, 65535)
	var client *net.UDPAddr
	for {
		_ = relay.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, source, err := relay.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return
			}
			relayErrors <- err
			return
		}
		if source.IP.Equal(target.IP) && source.Port == target.Port {
			if client == nil {
				relayErrors <- fmt.Errorf("received QUIC response before SOCKS client datagram")
				return
			}
			port := make([]byte, 2)
			binary.BigEndian.PutUint16(port, testutil.Uint16(source.Port))
			response := socks5.NewDatagram(socks5.ATYPIPv4, source.IP.To4(), port, buffer[:n]).Bytes()
			if _, err = relay.WriteToUDP(response, client); err != nil {
				relayErrors <- err
				return
			}
			continue
		}
		datagram, parseErr := socks5.NewDatagramFromBytes(buffer[:n])
		if parseErr != nil {
			relayErrors <- fmt.Errorf("parse SOCKS UDP packet: %w", parseErr)
			return
		}
		if targetHost != "" {
			host, port, splitErr := net.SplitHostPort(datagram.Address())
			if splitErr != nil || host != targetHost || port != fmt.Sprint(target.Port) ||
				datagram.Atyp != socks5.ATYPDomain {
				relayErrors <- fmt.Errorf("SOCKS5H destination = %q (ATYP %d), want %s:%d as domain", datagram.Address(), datagram.Atyp, targetHost, target.Port)
				return
			}
		} else if datagram.Atyp != socks5.ATYPIPv4 || datagram.Address() != target.String() {
			relayErrors <- fmt.Errorf("SOCKS5 destination = %q (ATYP %d), want %s as IPv4", datagram.Address(), datagram.Atyp, target)
			return
		}
		select {
		case observedATYP <- datagram.Atyp:
		default:
		}
		client = source
		if _, err = relay.WriteToUDP(datagram.Data, target); err != nil {
			relayErrors <- err
			return
		}
	}
}

func assertAPIQUICSOCKSTLSReport(t *testing.T, result *Result, scheme string) {
	t.Helper()
	if len(result.TLSReports) != 1 ||
		result.TLSReports[0].Leg != "target" ||
		result.TLSReports[0].CaptureStatus != "OBSERVED" ||
		result.TLSReports[0].Actual == nil ||
		result.TLSReports[0].Actual.JA3 == "" ||
		result.TLSReports[0].Actual.JA4 == "" ||
		len(result.TLSReports[0].Actual.ALPN) != 1 ||
		result.TLSReports[0].Actual.ALPN[0] != "h3" {
		t.Fatalf(
			"HTTP/3 TLS report through %s = %+v; want observed target JA3/JA4 with h3 ALPN",
			scheme,
			result.TLSReports,
		)
	}
}
