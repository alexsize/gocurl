package client

import (
	"net"

	"github.com/ameshkov/gocurl/internal/config"
)

func applyHTTP2ConnectionProfile(conn net.Conn, cfg *config.Config) net.Conn {
	if len(cfg.HTTP2PseudoOrder) != 0 || len(cfg.HTTP2HeaderOrder) != 0 ||
		len(cfg.HTTP2SettingsOrder) != 0 || cfg.HTTP2DataFrameSize != 0 ||
		cfg.HTTP2HeaderFrameSize != 0 || cfg.HTTP2FramePadding != 0 || cfg.HTTP2Priority != nil {
		return &h2PseudoOrderConn{
			Conn:            conn,
			order:           cfg.HTTP2PseudoOrder,
			headerOrder:     cfg.HTTP2HeaderOrder,
			settingsOrder:   cfg.HTTP2SettingsOrder,
			dataFrameSize:   cfg.HTTP2DataFrameSize,
			headerFrameSize: cfg.HTTP2HeaderFrameSize,
			framePadding:    cfg.HTTP2FramePadding,
			priority:        cfg.HTTP2Priority,
		}
	}

	return conn
}
