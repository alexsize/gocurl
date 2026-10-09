package quic

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// Clone clones a Config.
func (c *Config) Clone() *Config {
	copy := *c
	return &copy
}

func (c *Config) handshakeTimeout() time.Duration {
	return 2 * c.HandshakeIdleTimeout
}

func (c *Config) maxRetryTokenAge() time.Duration {
	return c.handshakeTimeout()
}

func validateConfig(config *Config) error {
	if config == nil {
		return nil
	}
	if config.AckDelayExponentSet && config.AckDelayExponent > protocol.MaxAckDelayExponent {
		return fmt.Errorf("invalid ack_delay_exponent: %d (maximum %d)", config.AckDelayExponent, protocol.MaxAckDelayExponent)
	}
	if config.MaxAckDelaySet && (config.MaxAckDelay < 0 || config.MaxAckDelay%time.Millisecond != 0 || config.MaxAckDelay > protocol.MaxMaxAckDelay) {
		return fmt.Errorf("invalid max_ack_delay: must be a whole number of milliseconds in 0..%d", protocol.MaxMaxAckDelay/time.Millisecond)
	}
	if config.MaxUDPPayloadSize != 0 && (config.MaxUDPPayloadSize < uint16(protocol.MinInitialPacketSize) || config.MaxUDPPayloadSize > uint16(protocol.MaxPacketBufferSize)) {
		return fmt.Errorf("invalid max_udp_payload_size: must be %d..%d", protocol.MinInitialPacketSize, protocol.MaxPacketBufferSize)
	}
	const maxStreams = 1 << 60
	if config.MaxIncomingStreams > maxStreams {
		config.MaxIncomingStreams = maxStreams
	}
	if config.MaxIncomingUniStreams > maxStreams {
		config.MaxIncomingUniStreams = maxStreams
	}
	if config.MaxStreamReceiveWindow > quicvarint.Max {
		config.MaxStreamReceiveWindow = quicvarint.Max
	}
	if config.MaxConnectionReceiveWindow > quicvarint.Max {
		config.MaxConnectionReceiveWindow = quicvarint.Max
	}
	for _, window := range []struct {
		name  string
		value uint64
	}{
		{"initial_max_stream_data_bidi_local", config.InitialMaxStreamDataBidiLocal},
		{"initial_max_stream_data_bidi_remote", config.InitialMaxStreamDataBidiRemote},
		{"initial_max_stream_data_uni", config.InitialMaxStreamDataUni},
	} {
		if window.value > quicvarint.Max {
			return fmt.Errorf("%s exceeds QUIC varint maximum %d", window.name, uint64(quicvarint.Max))
		}
	}
	if config.InitialPacketSize > 0 && config.InitialPacketSize < protocol.MinInitialPacketSize {
		config.InitialPacketSize = protocol.MinInitialPacketSize
	}
	if config.InitialPacketSize > protocol.MaxPacketBufferSize {
		config.InitialPacketSize = protocol.MaxPacketBufferSize
	}
	// check that all QUIC versions are actually supported
	for _, v := range config.Versions {
		if !protocol.IsValidVersion(v) {
			return fmt.Errorf("invalid QUIC version: %s", v)
		}
	}
	return nil
}

// populateConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}
	handshakeIdleTimeout := protocol.DefaultHandshakeIdleTimeout
	if config.HandshakeIdleTimeout != 0 {
		handshakeIdleTimeout = config.HandshakeIdleTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.MaxIdleTimeout != 0 {
		idleTimeout = config.MaxIdleTimeout
	}
	initialStreamReceiveWindow := config.InitialStreamReceiveWindow
	if initialStreamReceiveWindow == 0 {
		initialStreamReceiveWindow = protocol.DefaultInitialMaxStreamData
	}
	initialMaxStreamDataBidiLocal := config.InitialMaxStreamDataBidiLocal
	if !config.InitialMaxStreamDataBidiLocalSet {
		initialMaxStreamDataBidiLocal = initialStreamReceiveWindow
	}
	initialMaxStreamDataBidiRemote := config.InitialMaxStreamDataBidiRemote
	if !config.InitialMaxStreamDataBidiRemoteSet {
		initialMaxStreamDataBidiRemote = initialStreamReceiveWindow
	}
	initialMaxStreamDataUni := config.InitialMaxStreamDataUni
	if !config.InitialMaxStreamDataUniSet {
		initialMaxStreamDataUni = initialStreamReceiveWindow
	}
	maxStreamReceiveWindow := config.MaxStreamReceiveWindow
	if maxStreamReceiveWindow == 0 {
		maxStreamReceiveWindow = protocol.DefaultMaxReceiveStreamFlowControlWindow
	}
	initialConnectionReceiveWindow := config.InitialConnectionReceiveWindow
	if initialConnectionReceiveWindow == 0 {
		initialConnectionReceiveWindow = protocol.DefaultInitialMaxData
	}
	maxConnectionReceiveWindow := config.MaxConnectionReceiveWindow
	if maxConnectionReceiveWindow == 0 {
		maxConnectionReceiveWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindow
	}
	maxIncomingStreams := config.MaxIncomingStreams
	if maxIncomingStreams == 0 {
		maxIncomingStreams = protocol.DefaultMaxIncomingStreams
	} else if maxIncomingStreams < 0 {
		maxIncomingStreams = 0
	}
	maxIncomingUniStreams := config.MaxIncomingUniStreams
	if maxIncomingUniStreams == 0 {
		maxIncomingUniStreams = protocol.DefaultMaxIncomingUniStreams
	} else if maxIncomingUniStreams < 0 {
		maxIncomingUniStreams = 0
	}
	initialPacketSize := config.InitialPacketSize
	if initialPacketSize == 0 {
		initialPacketSize = protocol.InitialPacketSize
	}
	activeConnectionIDLimit := config.ActiveConnectionIDLimit
	if activeConnectionIDLimit == 0 {
		activeConnectionIDLimit = protocol.MaxActiveConnectionIDs
	}
	ackDelayExponent := config.AckDelayExponent
	if !config.AckDelayExponentSet {
		ackDelayExponent = protocol.AckDelayExponent
	}
	maxAckDelay := config.MaxAckDelay
	if !config.MaxAckDelaySet {
		maxAckDelay = protocol.MaxAckDelayInclGranularity
	}
	maxUDPPayloadSize := config.MaxUDPPayloadSize
	if maxUDPPayloadSize == 0 {
		maxUDPPayloadSize = protocol.MaxPacketBufferSize
	}

	return &Config{
		GetConfigForClient:                config.GetConfigForClient,
		Versions:                          versions,
		HandshakeIdleTimeout:              handshakeIdleTimeout,
		MaxIdleTimeout:                    idleTimeout,
		KeepAlivePeriod:                   config.KeepAlivePeriod,
		InitialStreamReceiveWindow:        initialStreamReceiveWindow,
		InitialMaxStreamDataBidiLocal:     initialMaxStreamDataBidiLocal,
		InitialMaxStreamDataBidiLocalSet:  true,
		InitialMaxStreamDataBidiRemote:    initialMaxStreamDataBidiRemote,
		InitialMaxStreamDataBidiRemoteSet: true,
		InitialMaxStreamDataUni:           initialMaxStreamDataUni,
		InitialMaxStreamDataUniSet:        true,
		MaxStreamReceiveWindow:            maxStreamReceiveWindow,
		InitialConnectionReceiveWindow:    initialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:        maxConnectionReceiveWindow,
		AllowConnectionWindowIncrease:     config.AllowConnectionWindowIncrease,
		MaxIncomingStreams:                maxIncomingStreams,
		MaxIncomingUniStreams:             maxIncomingUniStreams,
		TokenStore:                        config.TokenStore,
		EnableDatagrams:                   config.EnableDatagrams,
		InitialPacketSize:                 initialPacketSize,
		ActiveConnectionIDLimit:           activeConnectionIDLimit,
		AckDelayExponent:                  ackDelayExponent,
		AckDelayExponentSet:               true,
		MaxAckDelay:                       maxAckDelay,
		MaxAckDelaySet:                    true,
		MaxUDPPayloadSize:                 maxUDPPayloadSize,
		DisablePathMTUDiscovery:           config.DisablePathMTUDiscovery,
		EnableStreamResetPartialDelivery:  config.EnableStreamResetPartialDelivery,
		DisableActiveMigration:            config.DisableActiveMigration,
		ClientHelloCallback:               config.ClientHelloCallback,
		TransportParameterOrder:           config.TransportParameterOrder,
		Allow0RTT:                         config.Allow0RTT,
		Tracer:                            config.Tracer,
	}
}
