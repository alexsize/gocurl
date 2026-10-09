package config

import (
	"math"
	"strconv"
	"testing"
	"time"
)

func TestQUICConversionsPreserveUpperBounds(t *testing.T) {
	maxMilliseconds := uint64(math.MaxInt64) / uint64(time.Millisecond)
	maxStreams := uint64(1 << 60)
	got, err := parseQUICTransport(&Options{
		QUICMaxIdleTimeoutMS:      strconv.FormatUint(maxMilliseconds, 10),
		QUICMaxIncomingStreams:    strconv.FormatUint(maxStreams, 10),
		QUICMaxIncomingUniStreams: strconv.FormatUint(maxStreams, 10),
		QUICInitialPacketSize:     "1452",
		QUICConnectionIDLength:    "20",
		QUICMaxUDPPayloadSize:     "1452",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxIdleTimeout != math.MaxInt64-math.MaxInt64%time.Millisecond ||
		got.MaxIncomingStreams != 1<<60 || got.MaxIncomingUniStreams != 1<<60 ||
		got.InitialPacketSize != 1452 || got.ConnectionIDLength != 20 || got.MaxUDPPayloadSize != 1452 {
		t.Fatalf("upper bounds truncated or wrapped: %+v", got)
	}
}

func TestQUICConversionsRejectOverflowBeforeConversion(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"idle duration", Options{QUICMaxIdleTimeoutMS: strconv.FormatUint(uint64(math.MaxInt64)/uint64(time.Millisecond)+1, 10)}},
		{"bidi streams", Options{QUICMaxIncomingStreams: "1152921504606846977"}},
		{"uni streams", Options{QUICMaxIncomingUniStreams: "1152921504606846977"}},
		{"packet size", Options{QUICInitialPacketSize: "65536"}},
		{"connection ID", Options{QUICConnectionIDLength: "4294967296"}},
		{"UDP payload", Options{QUICMaxUDPPayloadSize: "65536"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parseQUICTransport(&tc.opts); err == nil {
				t.Fatalf("accepted overflowing %s: %+v", tc.name, got)
			}
		})
	}
}
