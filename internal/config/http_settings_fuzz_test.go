package config

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func FuzzHTTP2SettingsBounds(f *testing.F) {
	for _, seed := range [][3]string{
		{"", "", ""},
		{"1", "16384", "4294967295"},
		{"4294967295", "16777215", "1"},
		{"0", "0", "0"},
		{"4294967296", "16777216", "-1"},
		{"+1", " 16384", "\xff"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, table, frame, headers string) {
		if len(table)+len(frame)+len(headers) > 8192 {
			t.Skip()
		}
		got, err := parseHTTP2Settings(table, frame, headers)
		want := HTTP2Settings{}
		valid := true
		for _, field := range []struct {
			raw      string
			min, max uint64
			value    *uint32
		}{
			{table, 1, 1<<32 - 1, &want.HeaderTableSize},
			{frame, 16384, 16777215, &want.MaxFrameSize},
			{headers, 1, 1<<32 - 1, &want.MaxHeaderListSize},
		} {
			if field.raw == "" {
				continue
			}
			value, parseErr := strconv.ParseUint(field.raw, 10, 32)
			if parseErr != nil || value < field.min || value > field.max {
				valid = false
				continue
			}
			*field.value = uint32(value)
		}
		if (err == nil) != valid {
			t.Fatalf("range contract: valid=%t, got=%+v, error=%v", valid, got, err)
		}
		if valid && got != want {
			t.Fatalf("numeric value changed: got=%+v, want=%+v", got, want)
		}
		if !valid && got != (HTTP2Settings{}) {
			t.Fatalf("failed settings returned partial values: %+v", got)
		}
	})
}

func FuzzHTTP2Orders(f *testing.F) {
	for _, seed := range []string{
		"", "HEADER_TABLE_SIZE,MAX_FRAME_SIZE", " enable_push ,MAX_CONCURRENT_STREAMS,initial_window_size",
		"MAX_FRAME_SIZE,max_frame_size", "HEADER_TABLE_SIZE,", "6,1", "\xff,\x00",
		"method,scheme,authority,path", ":path, :authority,:scheme,:method",
		"method,method,authority,path", "METHOD,scheme,authority,path",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			t.Skip()
		}
		checkFuzzHTTP2SettingsOrder(t, raw)
		checkFuzzHTTP2PseudoOrder(t, raw)
	})
}

func checkFuzzHTTP2SettingsOrder(t *testing.T, raw string) {
	t.Helper()
	names := []string{
		"HEADER_TABLE_SIZE", "ENABLE_PUSH", "MAX_CONCURRENT_STREAMS",
		"INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE",
	}
	var want []uint16
	seen := map[uint16]bool{}
	valid := true
	for _, part := range strings.Split(raw, ",") {
		id := uint16(0)
		for i, name := range names {
			if strings.ToUpper(strings.TrimSpace(part)) == name {
				id = uint16(i + 1)
			}
		}
		if id == 0 || seen[id] {
			valid = false
		}
		seen[id] = true
		want = append(want, id)
	}
	got, err := parseHTTP2SettingsOrder(raw)
	if (err == nil) != valid || (valid && !reflect.DeepEqual(got, want)) || (!valid && got != nil) {
		t.Fatalf("SETTINGS order contract: got=%v, want=%v, valid=%t, error=%v", got, want, valid, err)
	}
}

func checkFuzzHTTP2PseudoOrder(t *testing.T, raw string) {
	t.Helper()
	parts := strings.Split(raw, ",")
	valid := len(parts) == 4
	seen := map[string]bool{}
	want := make([]string, len(parts))
	for i, part := range parts {
		name := strings.TrimPrefix(strings.TrimSpace(part), ":")
		if (name != "method" && name != "scheme" && name != "authority" && name != "path") || seen[name] {
			valid = false
		}
		seen[name], want[i] = true, ":"+name
	}
	got, err := parseHTTP2PseudoOrder(raw)
	if (err == nil) != valid || (valid && !reflect.DeepEqual(got, want)) || (!valid && got != nil) {
		t.Fatalf("pseudo order contract: got=%v, want=%v, valid=%t, error=%v", got, want, valid, err)
	}
}
