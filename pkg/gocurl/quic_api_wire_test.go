package gocurl

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type apiQUICTrace struct {
	parameters chan qlog.ParametersSet
	packetSize chan int
	cidLength  chan int
}

func (trace *apiQUICTrace) AddProducer() qlogwriter.Recorder {
	return &apiQUICRecorder{
		parameters: trace.parameters,
		packetSize: trace.packetSize,
		cidLength:  trace.cidLength,
	}
}

func (*apiQUICTrace) SupportsSchemas(string) bool { return true }

type apiQUICRecorder struct {
	parameters chan qlog.ParametersSet
	packetSize chan int
	cidLength  chan int
}

func (recorder *apiQUICRecorder) RecordEvent(event qlogwriter.Event) {
	if parameters, ok := event.(qlog.ParametersSet); ok && parameters.Initiator == qlog.InitiatorRemote {
		select {
		case recorder.parameters <- parameters:
		default:
		}
	}
	if packet, ok := event.(qlog.PacketReceived); ok && packet.Header.PacketType == qlog.PacketTypeInitial {
		select {
		case recorder.packetSize <- packet.Raw.Length:
		default:
		}
		select {
		case recorder.cidLength <- packet.Header.SrcConnectionID.Len():
		default:
		}
	}
}

func (*apiQUICRecorder) Close() error { return nil }

func TestClientDoQUICTransportParametersOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()

	parameters := make(chan qlog.ParametersSet, 2)
	packetSizes := make(chan int, 4)
	cidLengths := make(chan int, 4)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h3"},
	}, &quic.Config{
		Versions: []quic.Version{quic.Version2},
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &apiQUICTrace{parameters: parameters, packetSize: packetSizes, cidLength: cidLengths}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverDone := make(chan struct{})
	serverErr := make(chan error, 1)
	negotiated := make(chan quic.Version, 1)
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		negotiated <- conn.ConnectionState().Version
		<-ctx.Done()
		serverErr <- conn.CloseWithError(0, "test complete")
	}()

	ackDelayExponent := uint8(0)
	maxAckDelay := time.Duration(0)
	initialBidiLocal, initialBidiRemote, initialUni := uint64(111), uint64(222), uint64(333)
	clientDone := make(chan error, 1)
	go func() {
		result, doErr := NewClient().Do(ctx, Request{
			URL:            "https://" + listener.Addr().String() + "/",
			HTTPVersion:    "3",
			Insecure:       true,
			HTTP3Datagrams: true,
			QUICTransport: QUICTransport{
				InitialStreamReceiveWindow:     65536,
				InitialMaxStreamDataBidiLocal:  &initialBidiLocal,
				InitialMaxStreamDataBidiRemote: &initialBidiRemote,
				InitialMaxStreamDataUni:        &initialUni,
				InitialConnectionReceiveWindow: 262144,
				MaxIdleTimeout:                 7 * time.Second,
				MaxIncomingStreams:             10,
				MaxIncomingUniStreams:          12,
				Version:                        "2",
				InitialPacketSize:              1300,
				ConnectionIDLength:             8,
				ActiveConnectionIDLimit:        4,
				AckDelayExponent:               &ackDelayExponent,
				MaxAckDelay:                    &maxAckDelay,
				MaxUDPPayloadSize:              1350,
				EnableResetStreamAt:            true,
				DisableActiveMigration:         true,
			},
			QUICTransportParameterOrder: []uint64{4, 1, 5},
		})
		if result != nil {
			_ = result.Close()
		}
		clientDone <- doErr
	}()

	assertAPIQUICParameters(ctx, t, parameters, serverErr)
	select {
	case size := <-packetSizes:
		if size != 1300 {
			t.Errorf("initial QUIC datagram size = %d, want 1300", size)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case length := <-cidLengths:
		if length != 8 {
			t.Errorf("client source connection ID length = %d, want 8", length)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case version := <-negotiated:
		if version != quic.Version2 {
			t.Errorf("negotiated QUIC version = %v, want v2", version)
		}
	case err := <-serverErr:
		t.Fatalf("QUIC server ended before version check: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	assertAPIQUICShutdown(t, cancel, clientDone, serverDone, serverErr)
}

func assertAPIQUICParameters(
	ctx context.Context,
	t *testing.T,
	parameters <-chan qlog.ParametersSet,
	serverErr <-chan error,
) {
	t.Helper()
	select {
	case got := <-parameters:
		if got.InitialMaxStreamDataBidiLocal != 111 ||
			got.InitialMaxStreamDataBidiRemote != 222 ||
			got.InitialMaxStreamDataUni != 333 ||
			got.InitialMaxData != 262144 ||
			got.MaxIdleTimeout != 7*time.Second ||
			got.InitialMaxStreamsBidi != 10 || got.InitialMaxStreamsUni != 12 ||
			got.MaxDatagramFrameSize <= 0 || got.ActiveConnectionIDLimit != 4 ||
			got.AckDelayExponent != 0 || got.MaxAckDelay != 0 || got.MaxUDPPayloadSize != 1350 ||
			!got.EnableResetStreamAt || !got.DisableActiveMigration {
			t.Fatalf("QUIC transport parameters received from public API = %+v", got)
		}
	case err := <-serverErr:
		t.Fatalf("QUIC server ended before receiving parameters: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func assertAPIQUICShutdown(
	t *testing.T,
	cancel context.CancelFunc,
	clientDone <-chan error,
	serverDone <-chan struct{},
	serverErr <-chan error,
) {
	t.Helper()
	cancel()
	select {
	case doErr := <-clientDone:
		if doErr == nil {
			t.Error("Client.Do() succeeded although the server did not return an HTTP/3 response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Do() did not stop after context cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("QUIC server did not stop after context cancellation")
	}
	select {
	case closeErr := <-serverErr:
		if closeErr != nil {
			t.Errorf("close QUIC test connection: %v", closeErr)
		}
	default:
		t.Error("QUIC server did not report connection shutdown")
	}
}
