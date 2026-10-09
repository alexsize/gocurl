package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestQUICParserPreservesErrorPrecedence(t *testing.T) {
	for _, tc := range []struct {
		opts Options
		want string
	}{
		{Options{QUICInitialStreamWindow: "0", QUICInitialMaxStreamDataBidiLocal: "-1"}, "--quic-initial-stream-window"},
		{Options{QUICInitialMaxStreamDataBidiLocal: "-1", QUICInitialMaxStreamDataBidiRemote: "-1"}, "--quic-initial-max-stream-data-bidi-local"},
		{Options{QUICInitialMaxStreamDataBidiRemote: "-1", QUICInitialMaxStreamDataUni: "-1"}, "--quic-initial-max-stream-data-bidi-remote"},
		{Options{QUICInitialMaxStreamDataUni: "-1", QUICInitialConnectionWindow: "0"}, "--quic-initial-max-stream-data-uni"},
		{Options{QUICInitialConnectionWindow: "0", QUICMaxIdleTimeoutMS: "-1"}, "--quic-initial-connection-window"},
		{Options{QUICMaxIdleTimeoutMS: "-1", QUICMaxIncomingStreams: "0"}, "--quic-max-idle-timeout-ms"},
		{Options{QUICMaxIncomingStreams: "0", QUICMaxIncomingUniStreams: "2"}, "--quic-max-incoming-streams"},
		{Options{QUICMaxIncomingUniStreams: "2", QUICVersion: "3"}, "--quic-max-incoming-uni-streams"},
		{Options{QUICVersion: "3", QUICInitialPacketSize: "1199"}, "--quic-version"},
		{Options{QUICInitialPacketSize: "1199", QUICConnectionIDLength: "0"}, "--quic-initial-packet-size"},
		{Options{QUICConnectionIDLength: "0", QUICActiveConnectionIDLimit: "1"}, "--quic-connection-id-length"},
		{Options{QUICActiveConnectionIDLimit: "1", QUICAckDelayExponent: "21"}, "--quic-active-connection-id-limit"},
		{Options{QUICAckDelayExponent: "21", QUICMaxAckDelayMS: "16384"}, "--quic-ack-delay-exponent"},
		{Options{QUICMaxAckDelayMS: "16384", QUICMaxUDPPayloadSize: "1199"}, "--quic-max-ack-delay-ms"},
	} {
		_, err := parseQUICTransport(&tc.opts)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want+" ") {
			t.Fatalf("parseQUICTransport(%+v) = %v, want first error %s", tc.opts, err, tc.want)
		}
	}
}

func TestQUICParserPreservesPartialResults(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want QUICTransport
	}{
		{
			"stream data failure",
			Options{QUICInitialStreamWindow: "9", QUICInitialMaxStreamDataBidiLocal: "0", QUICInitialMaxStreamDataBidiRemote: "1", QUICInitialMaxStreamDataUni: "-1"},
			QUICTransport{InitialStreamReceiveWindow: 9, InitialMaxStreamDataBidiLocalSet: true, InitialMaxStreamDataBidiRemote: 1, InitialMaxStreamDataBidiRemoteSet: true},
		},
		{
			"idle timeout failure",
			Options{QUICInitialStreamWindow: "10", QUICInitialConnectionWindow: "20", QUICMaxIdleTimeoutMS: "-1"},
			QUICTransport{InitialStreamReceiveWindow: 10, InitialConnectionReceiveWindow: 20},
		},
		{
			"version failure",
			Options{QUICMaxIdleTimeoutMS: "1", QUICMaxIncomingStreams: "2", QUICMaxIncomingUniStreams: "3", QUICVersion: "3"},
			QUICTransport{MaxIdleTimeout: time.Millisecond, MaxIncomingStreams: 2, MaxIncomingUniStreams: 3},
		},
		{
			"packet size failure",
			Options{QUICVersion: "2", QUICInitialPacketSize: "1199"},
			QUICTransport{Version: "2"},
		},
		{
			"ACK failure",
			Options{QUICInitialPacketSize: "1200", QUICConnectionIDLength: "8", QUICActiveConnectionIDLimit: "4", QUICAckDelayExponent: "21", QUICResetStreamAt: true},
			QUICTransport{InitialPacketSize: 1200, ConnectionIDLength: 8, ActiveConnectionIDLimit: 4},
		},
		{
			"payload failure after explicit zero ACK settings",
			Options{QUICAckDelayExponent: "0", QUICMaxAckDelayMS: "0", QUICMaxUDPPayloadSize: "1199", QUICDisableActiveMigration: true},
			QUICTransport{AckDelayExponentSet: true, MaxAckDelaySet: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseQUICTransport(&tc.opts)
			if err == nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("partial QUIC transport = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}
