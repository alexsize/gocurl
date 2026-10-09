package config

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// HTTP2Settings contains the subset of HTTP/2 client settings supported by
// x/net/http2. Zero means the library default, not a wire value of zero.
type HTTP2Settings struct {
	HeaderTableSize   uint32
	MaxFrameSize      uint32
	MaxHeaderListSize uint32
}

// HTTP2Priority configures the dependency and weight of the first request stream.
type HTTP2Priority struct {
	Dependency uint32
	Weight     uint16
	Exclusive  bool
}

func parseHTTP2Priority(raw string) (*HTTP2Priority, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("--h2-priority requires dependency:weight:exclusive")
	}
	dependency, err := strconv.ParseUint(parts[0], 10, 31)
	if err != nil || dependency == 1 { // A dedicated connection uses stream 1 for its request.
		return nil, fmt.Errorf("--h2-priority dependency must be a stream ID in 0..2147483647 except 1")
	}
	weight, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || weight < 1 || weight > 256 {
		return nil, fmt.Errorf("--h2-priority weight must be 1..256")
	}
	exclusive, err := strconv.ParseBool(parts[2])
	if err != nil {
		return nil, fmt.Errorf("--h2-priority exclusive must be true or false")
	}
	return &HTTP2Priority{Dependency: uint32(dependency), Weight: uint16(weight), Exclusive: exclusive}, nil
}

func parseHTTP2Settings(headerTable, maxFrame, maxHeaders string) (HTTP2Settings, error) {
	var settings HTTP2Settings
	for _, field := range []struct {
		name, text string
		value      *uint32
		min, max   uint64
	}{
		{"--h2-header-table-size", headerTable, &settings.HeaderTableSize, 1, 1<<32 - 1},
		{"--h2-max-frame-size", maxFrame, &settings.MaxFrameSize, 16384, 16777215},
		{"--h2-max-header-list-size", maxHeaders, &settings.MaxHeaderListSize, 1, 1<<32 - 1},
	} {
		if field.text == "" {
			continue
		}
		value, err := strconv.ParseUint(field.text, 10, 32)
		if err != nil || value < field.min || value > field.max {
			return HTTP2Settings{}, fmt.Errorf("%s must be %d..%d", field.name, field.min, field.max)
		}
		*field.value = uint32(value)
	}
	return settings, nil
}

func parseHTTP2PseudoOrder(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf("--h2-pseudo-order requires method,scheme,authority,path exactly once each")
	}
	seen := map[string]bool{}
	for i, part := range parts {
		name := strings.TrimPrefix(strings.TrimSpace(part), ":")
		switch name {
		case "method", "scheme", "authority", "path":
		default:
			return nil, fmt.Errorf("--h2-pseudo-order contains unknown field %q", part)
		}
		if seen[name] {
			return nil, fmt.Errorf("--h2-pseudo-order contains duplicate field %q", name)
		}
		seen[name] = true
		parts[i] = ":" + name
	}
	return parts, nil
}

func parseHTTP2SettingsOrder(raw string) ([]uint16, error) {
	names := map[string]uint16{
		"HEADER_TABLE_SIZE": 1, "ENABLE_PUSH": 2, "MAX_CONCURRENT_STREAMS": 3,
		"INITIAL_WINDOW_SIZE": 4, "MAX_FRAME_SIZE": 5, "MAX_HEADER_LIST_SIZE": 6,
	}
	parts := strings.Split(raw, ",")
	order := make([]uint16, 0, len(parts))
	seen := map[uint16]bool{}
	for _, part := range parts {
		name := strings.ToUpper(strings.TrimSpace(part))
		id, ok := names[name]
		if !ok {
			return nil, fmt.Errorf("--h2-settings-order contains unknown setting %q", part)
		}
		if seen[id] {
			return nil, fmt.Errorf("--h2-settings-order contains duplicate setting %q", part)
		}
		seen[id] = true
		order = append(order, id)
	}
	return order, nil
}

func parseHTTP2HeaderOrder(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	seen := map[string]bool{}
	for i, part := range parts {
		name := strings.ToLower(strings.TrimSpace(part))
		if !httpguts.ValidHeaderFieldName(name) || strings.HasPrefix(name, ":") {
			return nil, fmt.Errorf("--h2-header-order contains invalid field %q", part)
		}
		if seen[name] {
			return nil, fmt.Errorf("--h2-header-order contains duplicate field %q", part)
		}
		seen[name] = true
		parts[i] = name
	}
	return parts, nil
}

func parseHTTP3AdditionalSettings(entries []string) (map[uint64]uint64, error) {
	settings := make(map[uint64]uint64, len(entries))
	for _, entry := range entries {
		idText, valueText, ok := strings.Cut(entry, "=")
		if !ok || idText == "" || valueText == "" {
			return nil, fmt.Errorf("--h3-setting %q: expected ID=VALUE", entry)
		}
		id, err := strconv.ParseUint(idText, 0, 62)
		if err != nil {
			return nil, fmt.Errorf("--h3-setting %q: invalid ID: %w", entry, err)
		}
		value, err := strconv.ParseUint(valueText, 0, 62)
		if err != nil {
			return nil, fmt.Errorf("--h3-setting %q: invalid VALUE: %w", entry, err)
		}
		// RFC 9114 reserves HTTP/2 IDs 0x2..0x5; the remaining IDs below
		// are defined by HTTP/3, QPACK, Extended CONNECT, or HTTP Datagrams.
		if id <= 8 || id == 0x33 || id == 0x276 || id == 0x2b603742 {
			return nil, fmt.Errorf(
				"--h3-setting %q: standard or reserved setting ID is not an extension setting",
				entry,
			)
		}
		if _, exists := settings[id]; exists {
			return nil, fmt.Errorf("--h3-setting %q: duplicate setting ID", entry)
		}
		settings[id] = value
	}
	return settings, nil
}
