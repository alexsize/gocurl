package resolve

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

type blockingEncryptedUpstream struct {
	started chan struct{}
	release chan struct{}
	done    chan struct{}
	closed  atomic.Bool
}

func (u *blockingEncryptedUpstream) Address() string { return "https://dns.invalid/dns-query" }

func (u *blockingEncryptedUpstream) Close() error { u.closed.Store(true); return nil }

func (u *blockingEncryptedUpstream) Exchange(query *dns.Msg) (*dns.Msg, error) {
	defer close(u.done)
	close(u.started)
	<-u.release
	response := new(dns.Msg)
	response.SetReply(query)
	return response, nil
}

func TestExchangeDNSContextEncryptedCancellationDoesNotCloseSharedUpstream(t *testing.T) {
	u := &blockingEncryptedUpstream{
		started: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{}),
	}
	t.Cleanup(func() {
		close(u.release)
		select {
		case <-u.done:
		case <-time.After(time.Second):
			t.Error("encrypted exchange worker did not finish after release")
		}
	})
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := exchangeDNSContext(ctx, query, u); result <- err }()
	select {
	case <-u.started:
	case <-time.After(time.Second):
		t.Fatal("encrypted exchange did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exchange error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for the encrypted exchange worker")
	}
	if u.closed.Load() {
		t.Fatal("cancelling one query closed the shared upstream")
	}
	select {
	case <-u.done:
		t.Fatal("fixture worker unexpectedly finished before release")
	default:
	}
}

func TestExchangePlainDNSContextCancellationClosesTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixtureCtx, fixtureCancel := context.WithCancel(context.Background())
	started, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(fixtureCtx, func() { _ = conn.Close() })
		defer stop()
		if _, readErr := (&dns.Conn{Conn: conn}).ReadMsg(); readErr != nil {
			return
		}
		close(started)
		_, _ = io.Copy(io.Discard, conn)
	}()
	t.Cleanup(func() {
		fixtureCancel()
		_ = listener.Close()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Error("TCP DNS fixture did not stop")
		}
	})
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, exchangeErr := exchangePlainDNSContext(ctx, query, "tcp", listener.Addr().String())
		result <- exchangeErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TCP DNS query did not start")
	}
	cancel()
	select {
	case err = <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exchange error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP DNS exchange did not cancel")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close the TCP DNS socket")
	}
}

func TestExchangeDNSContextTruncatedUDPUsesTCP(t *testing.T) {
	listener, packetConn, err := listenDualProtocolDNS(net.ListenPacket, net.Listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	t.Cleanup(func() { _ = packetConn.Close() })
	var udpQueries, tcpQueries atomic.Int32
	handlerErrors := make(chan error, 2)
	handler := func(truncated bool, count *atomic.Int32) dns.Handler {
		return dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
			count.Add(1)
			response := new(dns.Msg)
			response.SetReply(query)
			response.Truncated = truncated
			if !truncated {
				response.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.IPv4(192, 0, 2, 10),
				}}
			}
			if writeErr := w.WriteMsg(response); writeErr != nil {
				handlerErrors <- writeErr
			}
		})
	}
	udpServer := &dns.Server{PacketConn: packetConn, Handler: handler(true, &udpQueries)}
	tcpServer := &dns.Server{Listener: listener, Handler: handler(false, &tcpQueries)}
	serverResults := make(chan error, 2)
	go func() { serverResults <- udpServer.ActivateAndServe() }()
	go func() { serverResults <- tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
		_ = packetConn.Close()
		_ = listener.Close()
		for range 2 {
			select {
			case serveErr := <-serverResults:
				if serveErr != nil {
					t.Errorf("DNS fixture: %v", serveErr)
				}
			case <-time.After(time.Second):
				t.Error("DNS fixture did not stop")
			}
		}
	})
	u, err := upstream.AddressToUpstream(listener.Addr().String(), &upstream.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := exchangeDNSContext(ctx, query, u)
	if err != nil {
		t.Fatal(err)
	}
	if response.Truncated || len(response.Answer) != 1 || udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatalf("response = %v, UDP queries = %d, TCP queries = %d", response, udpQueries.Load(), tcpQueries.Load())
	}
	select {
	case err := <-handlerErrors:
		t.Fatal(err)
	default:
	}
}
