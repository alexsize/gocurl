package config

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

func parseQUICReceiveWindows(opts *Options, result *QUICTransport) error {
	var err error
	result.InitialStreamReceiveWindow, err = parsePositiveQUICOption(
		"--quic-initial-stream-window",
		opts.QUICInitialStreamWindow,
		1<<62-1,
	)
	if err != nil {
		return err
	}
	for _, setting := range []struct {
		name  string
		raw   string
		value *uint64
		set   *bool
	}{
		{"--quic-initial-max-stream-data-bidi-local", opts.QUICInitialMaxStreamDataBidiLocal, &result.InitialMaxStreamDataBidiLocal, &result.InitialMaxStreamDataBidiLocalSet},
		{"--quic-initial-max-stream-data-bidi-remote", opts.QUICInitialMaxStreamDataBidiRemote, &result.InitialMaxStreamDataBidiRemote, &result.InitialMaxStreamDataBidiRemoteSet},
		{"--quic-initial-max-stream-data-uni", opts.QUICInitialMaxStreamDataUni, &result.InitialMaxStreamDataUni, &result.InitialMaxStreamDataUniSet},
	} {
		if setting.raw == "" {
			continue
		}
		value, parseErr := strconv.ParseUint(setting.raw, 10, 64)
		if parseErr != nil || value > 1<<62-1 {
			return fmt.Errorf("%s must be an integer in 0..%d", setting.name, uint64(1<<62-1))
		}
		*setting.value = value
		*setting.set = true
	}
	result.InitialConnectionReceiveWindow, err = parsePositiveQUICOption(
		"--quic-initial-connection-window",
		opts.QUICInitialConnectionWindow,
		1<<62-1,
	)
	if err != nil {
		return err
	}
	return nil
}

func parseQUICIdleAndStreamLimits(opts *Options, result *QUICTransport) error {
	ms, err := parsePositiveQUICOption(
		"--quic-max-idle-timeout-ms",
		opts.QUICMaxIdleTimeoutMS,
		math.MaxInt64/uint64(time.Millisecond),
	)
	if err != nil {
		return err
	}
	result.MaxIdleTimeout = time.Duration(
		ms,
	) * time.Millisecond // #nosec G115 -- parsePositiveQUICOption bounds ms to MaxInt64/Millisecond above.
	streams, err := parsePositiveQUICOption("--quic-max-incoming-streams", opts.QUICMaxIncomingStreams, 1<<60)
	if err != nil {
		return err
	}
	result.MaxIncomingStreams = int64(
		streams,
	) // #nosec G115 -- parsePositiveQUICOption bounds streams to 1<<60, below MaxInt64.
	uniStreams, err := parsePositiveQUICOption("--quic-max-incoming-uni-streams", opts.QUICMaxIncomingUniStreams, 1<<60)
	if err != nil {
		return err
	}
	if opts.QUICMaxIncomingUniStreams != "" && uniStreams < 3 {
		return fmt.Errorf(
			"--quic-max-incoming-uni-streams must be at least 3 for HTTP/3 control and QPACK streams",
		)
	}
	result.MaxIncomingUniStreams = int64(
		uniStreams,
	) // #nosec G115 -- parsePositiveQUICOption bounds uniStreams to 1<<60, below MaxInt64.
	if opts.QUICVersion != "" && opts.QUICVersion != "1" && opts.QUICVersion != "2" {
		return fmt.Errorf("--quic-version must be 1 or 2")
	}
	result.Version = opts.QUICVersion
	return nil
}

func parseQUICPacketAndConnectionIDs(opts *Options, result *QUICTransport) error {
	packetSize, err := parsePositiveQUICOption("--quic-initial-packet-size", opts.QUICInitialPacketSize, 1452)
	if err != nil {
		return err
	}
	if opts.QUICInitialPacketSize != "" && packetSize < 1200 {
		return fmt.Errorf("--quic-initial-packet-size must be 1200..1452")
	}
	result.InitialPacketSize = uint16(
		packetSize,
	) // #nosec G115 -- parsePositiveQUICOption bounds packetSize to 1452, below MaxUint16.
	cidLength, err := parsePositiveQUICOption("--quic-connection-id-length", opts.QUICConnectionIDLength, 20)
	if err != nil {
		return err
	}
	result.ConnectionIDLength = int(
		cidLength,
	) // #nosec G115 -- parsePositiveQUICOption bounds cidLength to 20, safe even on 32-bit targets.
	// quic-go's connection ID manager supports at most four active IDs.
	activeConnectionIDs, err := parsePositiveQUICOption(
		"--quic-active-connection-id-limit",
		opts.QUICActiveConnectionIDLimit,
		4,
	)
	if err != nil {
		return err
	}
	if opts.QUICActiveConnectionIDLimit != "" && activeConnectionIDs < 2 {
		return fmt.Errorf("--quic-active-connection-id-limit must be 2..4 (current transport limit)")
	}
	result.ActiveConnectionIDLimit = activeConnectionIDs
	return nil
}

func parseQUICAckAndPayload(opts *Options, result *QUICTransport) error {
	if opts.QUICAckDelayExponent != "" {
		exponent, parseErr := strconv.ParseUint(opts.QUICAckDelayExponent, 10, 8)
		if parseErr != nil || exponent > 20 {
			return fmt.Errorf("--quic-ack-delay-exponent must be an integer in 0..20")
		}
		result.AckDelayExponent = uint8(exponent)
		result.AckDelayExponentSet = true
	}
	if opts.QUICMaxAckDelayMS != "" {
		maxAckDelayMS, parseErr := strconv.ParseUint(opts.QUICMaxAckDelayMS, 10, 16)
		if parseErr != nil || maxAckDelayMS > 16383 {
			return fmt.Errorf("--quic-max-ack-delay-ms must be an integer in 0..16383")
		}
		result.MaxAckDelay = time.Duration(maxAckDelayMS) * time.Millisecond
		result.MaxAckDelaySet = true
	}
	maxUDPPayloadSize, err := parsePositiveQUICOption("--quic-max-udp-payload-size", opts.QUICMaxUDPPayloadSize, 1452)
	if err != nil {
		return err
	}
	if opts.QUICMaxUDPPayloadSize != "" && maxUDPPayloadSize < 1200 {
		return fmt.Errorf("--quic-max-udp-payload-size must be 1200..1452 for this transport")
	}
	result.MaxUDPPayloadSize = uint16(
		maxUDPPayloadSize,
	) // #nosec G115 -- parsePositiveQUICOption bounds the payload size to 1452, below MaxUint16.
	result.EnableResetStreamAt = opts.QUICResetStreamAt
	result.DisableActiveMigration = opts.QUICDisableActiveMigration
	return nil
}
