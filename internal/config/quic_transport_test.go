package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseQUICTransport(t *testing.T) {
	cfg, err := ParseConfig([]string{
		"--http3",
		"--quic-initial-stream-window=65536",
		"--quic-initial-max-stream-data-bidi-local=111",
		"--quic-initial-max-stream-data-bidi-remote=222",
		"--quic-initial-max-stream-data-uni=333",
		"--quic-initial-connection-window=262144",
		"--quic-max-idle-timeout-ms=7000",
		"--quic-max-incoming-streams=10",
		"--quic-max-incoming-uni-streams=12",
		"--quic-version=2",
		"--quic-initial-packet-size=1300",
		"--quic-connection-id-length=8",
		"--quic-reset-stream-at",
		"--quic-disable-active-migration",
		"--quic-active-connection-id-limit=4",
		"--quic-ack-delay-exponent=0",
		"--quic-max-ack-delay-ms=0",
		"--quic-max-udp-payload-size=1350",
		"https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.QUICTransport; got != (QUICTransport{
		InitialStreamReceiveWindow:    65536,
		InitialMaxStreamDataBidiLocal: 111, InitialMaxStreamDataBidiLocalSet: true,
		InitialMaxStreamDataBidiRemote: 222, InitialMaxStreamDataBidiRemoteSet: true,
		InitialMaxStreamDataUni: 333, InitialMaxStreamDataUniSet: true,
		InitialConnectionReceiveWindow: 262144,
		MaxIdleTimeout:                 7 * time.Second, MaxIncomingStreams: 10, MaxIncomingUniStreams: 12,
		Version: "2", InitialPacketSize: 1300, ConnectionIDLength: 8, ActiveConnectionIDLimit: 4, AckDelayExponentSet: true, MaxAckDelaySet: true, MaxUDPPayloadSize: 1350, EnableResetStreamAt: true, DisableActiveMigration: true,
	}) {
		t.Fatalf("QUICTransport = %+v", got)
	}
}

func TestParseQUICStreamWindowExplicitZero(t *testing.T) {
	cfg, err := ParseConfig([]string{
		"--http3", "--quic-initial-max-stream-data-bidi-local=0", "https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.QUICTransport; got.InitialMaxStreamDataBidiLocal != 0 || !got.InitialMaxStreamDataBidiLocalSet {
		t.Fatalf("explicit zero bidi-local window = %+v", got)
	}
}

func TestParseQUICTransportRejectsInvalid(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--quic-initial-stream-window=65536"}, "require --http3"},
		{[]string{"--http3", "--quic-initial-stream-window=0"}, "--quic-initial-stream-window"},
		{[]string{"--http3", "--quic-initial-connection-window=4611686018427387904"}, "--quic-initial-connection-window"},
		{[]string{"--http3", "--quic-max-idle-timeout-ms=-1"}, "--quic-max-idle-timeout-ms"},
		{[]string{"--http3", "--quic-max-incoming-streams=0"}, "--quic-max-incoming-streams"},
		{[]string{"--http3", "--quic-max-incoming-uni-streams=2"}, "at least 3"},
		{[]string{"--http3", "--quic-version=3"}, "--quic-version"},
		{[]string{"--http3", "--quic-initial-packet-size=1199"}, "1200..1452"},
		{[]string{"--http3", "--quic-initial-packet-size=1453"}, "--quic-initial-packet-size"},
		{[]string{"--quic-connection-id-length=8"}, "require --http3"},
		{[]string{"--http3", "--quic-connection-id-length=0"}, "--quic-connection-id-length"},
		{[]string{"--http3", "--quic-connection-id-length=21"}, "--quic-connection-id-length"},
		{[]string{"--quic-reset-stream-at"}, "require --http3"},
		{[]string{"--quic-disable-active-migration"}, "require --http3"},
		{[]string{"--http3", "--quic-active-connection-id-limit=1"}, "must be 2..4"},
		{[]string{"--http3", "--quic-active-connection-id-limit=5"}, "--quic-active-connection-id-limit"},
		{[]string{"--http3", "--quic-ack-delay-exponent=21"}, "0..20"},
		{[]string{"--http3", "--quic-ack-delay-exponent=-1"}, "0..20"},
		{[]string{"--quic-ack-delay-exponent=0"}, "require --http3"},
		{[]string{"--quic-active-connection-id-limit=6"}, "require --http3"},
		{[]string{"--http3", "--quic-max-ack-delay-ms=16384"}, "0..16383"},
		{[]string{"--http3", "--quic-max-ack-delay-ms=-1"}, "0..16383"},
		{[]string{"--quic-max-ack-delay-ms=0"}, "require --http3"},
		{[]string{"--http3", "--quic-max-udp-payload-size=1199"}, "1200..1452"},
		{[]string{"--http3", "--quic-max-udp-payload-size=1453"}, "1..1452"},
		{[]string{"--quic-max-udp-payload-size=1350"}, "require --http3"},
		{[]string{"--http3", "--quic-initial-max-stream-data-bidi-local=4611686018427387904"}, "0..4611686018427387903"},
		{[]string{"--quic-initial-max-stream-data-bidi-remote=0"}, "require --http3"},
		{[]string{"--h3-datagrams"}, "--h3-datagrams"},
	} {
		args := append(append([]string{}, tc.args...), "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseConfig(%q) = %v, want %q", args, err, tc.want)
		}
	}
}

func TestParseQUICTransportParameterOrder(t *testing.T) {
	cfg, err := ParseConfig([]string{
		"--http3", "--quic-transport-parameter-order=0x4,1,0x3", "https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{4, 1, 3}; !slices.Equal(cfg.QUICTransportParameterOrder, want) {
		t.Fatalf("transport parameter order = %v, want %v", cfg.QUICTransportParameterOrder, want)
	}
	for _, raw := range []string{"", "1,,2", "1,1", "0x", "4611686018427387904"} {
		if raw == "" {
			continue
		}
		_, err := ParseConfig([]string{"--http3", "--quic-transport-parameter-order=" + raw, "https://example.test/"})
		if err == nil {
			t.Errorf("accepted invalid QUIC transport parameter order %q", raw)
		}
	}
	if _, err := ParseConfig(
		[]string{"--quic-transport-parameter-order=4", "https://example.test/"},
	); err == nil ||
		!strings.Contains(err.Error(), "require --http3") {
		t.Errorf("parameter order without --http3 error = %v", err)
	}
}
