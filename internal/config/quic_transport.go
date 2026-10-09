package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// QUICTransport contains configurable client transport parameters. Unset values
// retain quic-go defaults; stream-data and ACK-delay options can explicitly be zero.
type QUICTransport struct {
	InitialStreamReceiveWindow        uint64
	InitialMaxStreamDataBidiLocal     uint64
	InitialMaxStreamDataBidiLocalSet  bool
	InitialMaxStreamDataBidiRemote    uint64
	InitialMaxStreamDataBidiRemoteSet bool
	InitialMaxStreamDataUni           uint64
	InitialMaxStreamDataUniSet        bool
	InitialConnectionReceiveWindow    uint64
	MaxIdleTimeout                    time.Duration
	MaxIncomingStreams                int64
	MaxIncomingUniStreams             int64
	Version                           string
	InitialPacketSize                 uint16
	ConnectionIDLength                int
	ActiveConnectionIDLimit           uint64
	AckDelayExponent                  uint8
	AckDelayExponentSet               bool
	MaxAckDelay                       time.Duration
	MaxAckDelaySet                    bool
	MaxUDPPayloadSize                 uint16
	EnableResetStreamAt               bool
	// DisableActiveMigration advertises the standard QUIC transport parameter.
	DisableActiveMigration bool
}

func parsePositiveQUICOption(name, raw string, upperBound uint64) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 || value > upperBound {
		return 0, fmt.Errorf("%s must be an integer in 1..%d", name, upperBound)
	}
	return value, nil
}

func parseQUICTransport(opts *Options) (QUICTransport, error) {
	var result QUICTransport
	for _, parse := range []func(*Options, *QUICTransport) error{
		parseQUICReceiveWindows,
		parseQUICIdleAndStreamLimits,
		parseQUICPacketAndConnectionIDs,
		parseQUICAckAndPayload,
	} {
		if err := parse(opts, &result); err != nil {
			return result, err
		}
	}
	return result, nil
}

func parseQUICTransportParameterOrder(raw string) ([]uint64, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	order := make([]uint64, 0, len(parts))
	seen := make(map[uint64]bool, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("--quic-transport-parameter-order contains an empty ID")
		}
		base := 10
		valueText := part
		if strings.HasPrefix(strings.ToLower(part), "0x") {
			base, valueText = 16, part[2:]
		}
		value, err := strconv.ParseUint(valueText, base, 62)
		if err != nil {
			return nil, fmt.Errorf("invalid QUIC transport parameter ID %q", part)
		}
		if seen[value] {
			return nil, fmt.Errorf("duplicate QUIC transport parameter ID %q", part)
		}
		seen[value] = true
		order = append(order, value)
	}
	return order, nil
}
