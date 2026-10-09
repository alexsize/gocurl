package client

import (
	"bufio"
	"bytes"
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

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/quic-go/quic-go/http3"
	"github.com/txthinking/socks5"
)

func TestHTTP3RequestThroughSOCKS5UDPAssociate(t *testing.T) {
	runHTTP3RequestThroughSOCKS(t, "socks5", "")
}

func TestHTTP3RequestThroughSOCKS5HUDPAssociate(t *testing.T) {
	runHTTP3RequestThroughSOCKS(t, "socks5h", "quic-target.test")
}

func TestHTTP2RequestThroughSOCKS5AndSOCKS5H(t *testing.T) {
	for _, tt := range []struct {
		name       string
		scheme     string
		targetHost string
		wantATYP   byte
	}{
		{name: "socks5 local DNS", scheme: "socks5", targetHost: "127.0.0.1", wantATYP: 1},
		{name: "socks5h proxy DNS", scheme: "socks5h", targetHost: "h2-target.test", wantATYP: 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requests := make(chan string, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Proto + " " + r.URL.Path
				_, _ = io.WriteString(w, "h2-over-socks-ok")
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			targetURL := "https://" + net.JoinHostPort(tt.targetHost, port) + "/through-socks"

			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for SOCKS5 proxy: %v", err)
			}
			defer func() { _ = proxyListener.Close() }()
			observedATYP := make(chan byte, 1)
			proxyErrors := make(chan error, 1)
			go serveHTTP2SOCKSConnect(proxyListener, server.Listener.Addr().String(), observedATYP, proxyErrors)

			args := []string{
				"--http2",
				"--insecure",
				"--proxy=" + tt.scheme + "://" + proxyListener.Addr().String(),
				targetURL,
			}
			cfg, err := config.ParseConfig(args)
			if err != nil {
				t.Fatalf("parse config: %v", err)
			}
			transport, err := NewTransport(
				cfg,
				output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false),
			)
			if err != nil {
				t.Fatalf("create HTTP/2 transport: %v", err)
			}
			defer func() {
				if conn := transport.Conn(); conn != nil {
					_ = conn.Close()
				}
				if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
					closer.CloseIdleConnections()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				select {
				case proxyErr := <-proxyErrors:
					t.Fatalf("HTTP/2 via %s failed: %v (proxy: %v)", tt.scheme, err, proxyErr)
				default:
					t.Fatalf("HTTP/2 via %s failed: %v", tt.scheme, err)
				}
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read HTTP/2 response: %v", err)
			}
			if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || string(body) != "h2-over-socks-ok" {
				t.Fatalf("response = %s %d body %q", resp.Proto, resp.StatusCode, body)
			}
			assertHTTP2SOCKSAddressType(ctx, t, observedATYP, proxyErrors, tt.wantATYP)
			select {
			case got := <-requests:
				if got != "HTTP/2.0 /through-socks" {
					t.Fatalf("target request = %q, want HTTP/2.0 /through-socks", got)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for target HTTP/2 request")
			}
		})
	}
}

func runHTTP3RequestThroughSOCKS(t *testing.T, scheme, targetHost string) {
	t.Helper()
	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 3 || r.URL.Path != "/through-socks" {
				t.Errorf("request = %s %s, want HTTP/3 /through-socks", r.Proto, r.URL.Path)
			}
			_, _ = io.WriteString(w, "h3-over-socks-ok")
		}),
	}
	defer func() {
		_ = server.Close()
		_ = udpTarget.Close()
	}()
	go func() { _ = server.Serve(udpTarget) }()

	udpTargetAddr := udpTarget.LocalAddr().(*net.UDPAddr)
	proxyAddr, relayErr := startSOCKS5UDPRelay(t, udpTargetAddr, targetHost)
	requestHost := udpTargetAddr.String()
	if targetHost != "" {
		requestHost = net.JoinHostPort(targetHost, fmt.Sprint(udpTargetAddr.Port))
	}
	targetURL := "https://" + requestHost + "/through-socks"
	cfg, err := config.ParseConfig(
		[]string{"--http3", "--insecure", "--json-output", "--proxy=" + scheme + "://" + proxyAddr.String(), targetURL},
	)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	transport, err := NewTransport(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer func() {
		if conn := transport.Conn(); conn != nil {
			_ = conn.Close()
		}
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}()

	requestCtx, _ := utlsengine.NewProfileCheckContext(ctx)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		select {
		case relayFailure := <-relayErr:
			t.Fatalf("HTTP/3 request through SOCKS5 failed: %v (relay: %v)", err, relayFailure)
		default:
			t.Fatalf("HTTP/3 request through SOCKS5 failed: %v", err)
		}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 response: %v", err)
	}
	if resp.ProtoMajor != 3 || resp.StatusCode != http.StatusOK || string(body) != "h3-over-socks-ok" {
		t.Fatalf(
			"response = %s %d body %q; want HTTP/3 200 body %q",
			resp.Proto,
			resp.StatusCode,
			body,
			"h3-over-socks-ok",
		)
	}
	assertSOCKSQUICObservation(requestCtx, t, scheme)
}

func startSOCKS5UDPRelay(
	t *testing.T,
	target *net.UDPAddr,
	targetHost string,
) (proxyAddr *net.TCPAddr, relayErr <-chan error) {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS5 control connection: %v", err)
	}
	udpRelay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = tcpListener.Close()
		t.Fatalf("listen for SOCKS5 UDP relay: %v", err)
	}
	t.Cleanup(func() {
		_ = tcpListener.Close()
		_ = udpRelay.Close()
	})
	errors := make(chan error, 1)
	go func() {
		control, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			errors <- acceptErr
			return
		}
		defer func() { _ = control.Close() }()
		greeting := make([]byte, 2)
		if _, acceptErr = io.ReadFull(control, greeting); acceptErr != nil {
			errors <- acceptErr
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, acceptErr = io.ReadFull(control, methods); acceptErr != nil {
			errors <- acceptErr
			return
		}
		if _, acceptErr = control.Write([]byte{5, 0}); acceptErr != nil {
			errors <- acceptErr
			return
		}
		request := make([]byte, 4)
		if _, acceptErr = io.ReadFull(control, request); acceptErr != nil {
			errors <- acceptErr
			return
		}
		if request[1] != socks5.CmdUDP || request[3] != socks5.ATYPIPv4 {
			errors <- fmt.Errorf("SOCKS5 UDP ASSOCIATE request = %v", request)
			return
		}
		address := make([]byte, net.IPv4len+2)
		if _, acceptErr = io.ReadFull(control, address); acceptErr != nil {
			errors <- acceptErr
			return
		}
		bound := udpRelay.LocalAddr().(*net.UDPAddr)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, testutil.Uint16(bound.Port))
		reply := append([]byte{5, 0, 0, socks5.ATYPIPv4}, net.ParseIP("127.0.0.1").To4()...)
		reply = append(reply, port...)
		if _, acceptErr = control.Write(reply); acceptErr != nil {
			errors <- acceptErr
			return
		}
		serveSOCKS5UDPRelay(udpRelay, target, targetHost, errors)
	}()
	return tcpListener.Addr().(*net.TCPAddr), errors
}

func serveSOCKS5UDPRelay(relay *net.UDPConn, target *net.UDPAddr, targetHost string, relayErr chan<- error) {
	buffer := make([]byte, 65535)
	var client *net.UDPAddr
	for {
		if err := relay.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			relayErr <- err
			return
		}
		n, source, err := relay.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return
			}
			relayErr <- err
			return
		}
		if source.IP.Equal(target.IP) && source.Port == target.Port {
			if client == nil {
				relayErr <- fmt.Errorf("received target response before a SOCKS5 client datagram")
				return
			}
			sourcePort := make([]byte, 2)
			binary.BigEndian.PutUint16(sourcePort, testutil.Uint16(source.Port))
			response := socks5.NewDatagram(socks5.ATYPIPv4, source.IP.To4(), sourcePort, buffer[:n]).Bytes()
			if _, err = relay.WriteToUDP(response, client); err != nil {
				relayErr <- err
				return
			}
			continue
		}
		datagram, parseErr := socks5.NewDatagramFromBytes(buffer[:n])
		if parseErr != nil {
			relayErr <- fmt.Errorf("parse SOCKS5 UDP datagram: %w", parseErr)
			return
		}
		var destination *net.UDPAddr
		var resolveErr error
		if targetHost != "" {
			host, port, splitErr := net.SplitHostPort(datagram.Address())
			if splitErr != nil || host != targetHost || port != fmt.Sprint(target.Port) ||
				datagram.Atyp != socks5.ATYPDomain {
				relayErr <- fmt.Errorf("SOCKS5H UDP destination = %q (ATYP %d); want %s:%d as a domain", datagram.Address(), datagram.Atyp, targetHost, target.Port)
				return
			}
			destination = target // This local relay stands in for the SOCKS proxy's remote DNS result.
		} else {
			destination, resolveErr = net.ResolveUDPAddr("udp", datagram.Address())
		}
		if resolveErr != nil || !destination.IP.Equal(target.IP) || destination.Port != target.Port {
			relayErr <- fmt.Errorf("unexpected SOCKS5 UDP destination %q (resolve error: %v)", datagram.Address(), resolveErr)
			return
		}
		client = source
		if _, err = relay.WriteToUDP(datagram.Data, target); err != nil {
			relayErr <- err
			return
		}
	}
}

func serveHTTP2SOCKSConnect(
	proxyListener net.Listener,
	targetAddress string,
	observedATYP chan<- byte,
	proxyErrors chan<- error,
) {
	client, acceptErr := proxyListener.Accept()
	if acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	defer func() { _ = client.Close() }()
	reader := bufio.NewReader(client)
	greeting := make([]byte, 2)
	if _, acceptErr = io.ReadFull(reader, greeting); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, acceptErr = io.ReadFull(reader, methods); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	if _, acceptErr = client.Write([]byte{5, 0}); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	connect := make([]byte, 4)
	if _, acceptErr = io.ReadFull(reader, connect); acceptErr != nil || connect[1] != 1 {
		if acceptErr == nil {
			acceptErr = fmt.Errorf("SOCKS5 command = %d, want CONNECT", connect[1])
		}
		proxyErrors <- acceptErr
		return
	}
	var addressSize int
	switch connect[3] {
	case 1:
		addressSize = net.IPv4len
	case 3:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			proxyErrors <- readErr
			return
		}
		addressSize = int(length)
	case 4:
		addressSize = net.IPv6len
	default:
		proxyErrors <- fmt.Errorf("unexpected SOCKS5 ATYP %d", connect[3])
		return
	}
	addressAndPort := make([]byte, addressSize+2)
	if _, acceptErr = io.ReadFull(reader, addressAndPort); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	observedATYP <- connect[3]
	upstream, dialErr := net.Dial("tcp", targetAddress)
	if dialErr != nil {
		proxyErrors <- dialErr
		return
	}
	defer func() { _ = upstream.Close() }()
	if _, acceptErr = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	go func() { _, _ = io.Copy(upstream, reader) }()
	_, _ = io.Copy(client, upstream)
}

func assertSOCKSQUICObservation(requestCtx context.Context, t *testing.T, scheme string) {
	t.Helper()
	reports, ok := utlsengine.ProfileCheckReports(requestCtx)
	if !ok || len(reports) != 1 || reports[0].Leg != "target" || reports[0].CaptureStatus != "OBSERVED" ||
		reports[0].Actual == nil || reports[0].Actual.JA3 == "" || reports[0].Actual.JA4 == "" ||
		len(reports[0].Actual.ALPN) != 1 || reports[0].Actual.ALPN[0] != "h3" {
		t.Fatalf(
			"HTTP/3 ClientHello report through %s = %+v, want observed target fingerprint with h3 ALPN",
			scheme,
			reports,
		)
	}
}

func assertHTTP2SOCKSAddressType(
	ctx context.Context,
	t *testing.T,
	observedATYP <-chan byte,
	proxyErrors <-chan error,
	wantATYP byte,
) {
	t.Helper()
	select {
	case got := <-observedATYP:
		if got != wantATYP {
			t.Fatalf("SOCKS5 target ATYP = %d, want %d", got, wantATYP)
		}
	case proxyErr := <-proxyErrors:
		t.Fatalf("read SOCKS5 request: %v", proxyErr)
	case <-ctx.Done():
		t.Fatal("timed out waiting for SOCKS5 CONNECT")
	}
}
