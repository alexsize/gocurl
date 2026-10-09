package config

import (
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func FuzzQUICTransportParameterOrder(f *testing.F) {
	for _, seed := range []string{
		"", "0", "0x0,1,0X2", "4611686018427387903", "4611686018427387904",
		"0x3fffffffffffffff", "0x4000000000000000", "1,0x1", "1,", "-1", "+1", "\xff,\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			t.Skip()
		}
		got, err := parseQUICTransportParameterOrder(raw)
		if err != nil {
			if got != nil {
				t.Fatalf("invalid order returned partial IDs: %v", got)
			}
			return
		}
		if raw == "" {
			if got != nil {
				t.Fatalf("unset order must remain nil: %v", got)
			}
			return
		}
		parts := strings.Split(raw, ",")
		if len(got) != len(parts) {
			t.Fatalf("order lost IDs: %v", got)
		}
		seen := map[uint64]bool{}
		canonical := make([]string, len(got))
		for i, id := range got {
			if id >= 1<<62 || seen[id] {
				t.Fatalf("overflow or duplicate ID: %v", got)
			}
			seen[id] = true
			part := strings.TrimSpace(parts[i])
			base := 10
			if strings.HasPrefix(strings.ToLower(part), "0x") {
				part, base = part[2:], 16
			}
			want, parseErr := strconv.ParseUint(part, base, 62)
			if parseErr != nil || id != want {
				t.Fatalf("ID changed at %d: got=%d, error=%v", i, id, parseErr)
			}
			canonical[i] = strconv.FormatUint(id, 10)
		}
		again, err := parseQUICTransportParameterOrder(strings.Join(canonical, ","))
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("canonical round trip changed order: %v, %v, %v", got, again, err)
		}
	})
}

func FuzzQUICTransportNumericOptions(f *testing.F) {
	fields := []struct {
		name     string
		min, max uint64
	}{
		{"QUICInitialStreamWindow", 1, 1<<62 - 1},
		{"QUICInitialMaxStreamDataBidiLocal", 0, 1<<62 - 1},
		{"QUICInitialMaxStreamDataBidiRemote", 0, 1<<62 - 1},
		{"QUICInitialMaxStreamDataUni", 0, 1<<62 - 1},
		{"QUICInitialConnectionWindow", 1, 1<<62 - 1},
		{"QUICMaxIdleTimeoutMS", 1, uint64(math.MaxInt64) / uint64(time.Millisecond)},
		{"QUICMaxIncomingStreams", 1, 1 << 60},
		{"QUICMaxIncomingUniStreams", 3, 1 << 60},
		{"QUICVersion", 1, 2},
		{"QUICInitialPacketSize", 1200, 1452},
		{"QUICConnectionIDLength", 1, 20},
		{"QUICActiveConnectionIDLimit", 2, 4},
		{"QUICAckDelayExponent", 0, 20},
		{"QUICMaxAckDelayMS", 0, 16383},
		{"QUICMaxUDPPayloadSize", 1200, 1452},
	}
	for i, field := range fields {
		for _, raw := range []string{
			"", "0", "-1", "\xff", "18446744073709551616",
			strconv.FormatUint(field.min, 10), strconv.FormatUint(field.max, 10),
			strconv.FormatUint(field.max+1, 10),
		} {
			f.Add(uint8(i), raw)
		}
	}
	f.Fuzz(func(t *testing.T, selector uint8, raw string) {
		if len(raw) > 8192 {
			t.Skip()
		}
		field := fields[int(selector)%len(fields)]
		opts := Options{}
		reflect.ValueOf(&opts).Elem().FieldByName(field.name).SetString(raw)
		before := opts
		value, parseErr := strconv.ParseUint(raw, 10, 64)
		valid := raw == "" || (parseErr == nil && value >= field.min && value <= field.max)
		// Version is a literal enum, unlike numeric transport parameters.
		if field.name == "QUICVersion" {
			valid = raw == "" || raw == "1" || raw == "2"
		}
		got, err := parseQUICTransport(&opts)
		if (err == nil) != valid {
			t.Fatalf("%s range contract: valid=%t, got=%+v, error=%v", field.name, valid, got, err)
		}
		if !reflect.DeepEqual(opts, before) {
			t.Fatal("parser mutated its input options")
		}
		if err != nil {
			return // Partial output on error is intentionally retained by this parser.
		}
		if raw != "" {
			reflect.ValueOf(&opts).Elem().FieldByName(field.name).SetString(strconv.FormatUint(value, 10))
		}
		again, err := parseQUICTransport(&opts)
		if err != nil || got != again {
			t.Fatalf("canonical round trip changed %s: %+v, %+v, %v", field.name, got, again, err)
		}
	})
}
