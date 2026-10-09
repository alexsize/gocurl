package client

import (
	"net"
	"reflect"
	"testing"

	"github.com/ameshkov/gocurl/internal/config"

	"golang.org/x/net/http2"
)

func TestHTTP2ConnectionProfileLeavesDefaultConnectionUnwrapped(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	for _, cfg := range []*config.Config{
		{},
		{HTTP2PseudoOrder: []string{}, HTTP2SettingsOrder: []uint16{}},
		{HTTP2Settings: config.HTTP2Settings{HeaderTableSize: 8192, MaxFrameSize: 32768}},
	} {
		if got := applyHTTP2ConnectionProfile(conn, cfg); got != conn {
			t.Fatalf("default/settings-only profile wrapped connection as %T", got)
		}
	}
}

func TestHTTP2ConnectionProfileWrapsEveryFramingOption(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.Config
	}{
		{"pseudo order", config.Config{HTTP2PseudoOrder: []string{":method", ":path", ":scheme", ":authority"}}},
		{"header order", config.Config{HTTP2HeaderOrder: []string{"x-first"}}},
		{"settings order", config.Config{HTTP2SettingsOrder: []uint16{uint16(http2.SettingMaxFrameSize)}}},
		{"DATA size", config.Config{HTTP2DataFrameSize: 1024}},
		{"HEADERS size", config.Config{HTTP2HeaderFrameSize: 1024}},
		{"padding", config.Config{HTTP2FramePadding: 8}},
		{"PRIORITY", config.Config{HTTP2Priority: &config.HTTP2Priority{Weight: 256}}},
		{"zero-valued PRIORITY pointer", config.Config{HTTP2Priority: &config.HTTP2Priority{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			got, ok := applyHTTP2ConnectionProfile(conn, &tc.cfg).(*h2PseudoOrderConn)
			if !ok || got.Conn != conn {
				t.Fatalf("profile %s did not wrap the original connection", tc.name)
			}
			if !reflect.DeepEqual(got.order, tc.cfg.HTTP2PseudoOrder) ||
				!reflect.DeepEqual(got.headerOrder, tc.cfg.HTTP2HeaderOrder) ||
				!reflect.DeepEqual(got.settingsOrder, tc.cfg.HTTP2SettingsOrder) ||
				got.dataFrameSize != tc.cfg.HTTP2DataFrameSize || got.headerFrameSize != tc.cfg.HTTP2HeaderFrameSize ||
				got.framePadding != tc.cfg.HTTP2FramePadding || got.priority != tc.cfg.HTTP2Priority {
				t.Fatalf("profile %s lost framing settings: %+v", tc.name, got)
			}
		})
	}
}
