package utlsengine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzDecodeClientProfile(f *testing.F) {
	for _, name := range []string{"profile-v1-valid.json", "profile-v1-unsupported.json"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	for _, seed := range []string{"", "null", "{}", "[]", "{} {}", "{\"version\":-1}", "\xff"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		profile, err := DecodeClientProfile(data)
		if err != nil {
			return
		}
		if err = profile.Validate(); err != nil {
			t.Fatalf("decoder accepted an invalid profile: %v", err)
		}
		canonical, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeClientProfile(canonical)
		if err != nil {
			t.Fatalf("canonical profile no longer decodes: %v", err)
		}
		encoded, err := json.Marshal(again)
		if err != nil || !bytes.Equal(encoded, canonical) {
			t.Fatalf("canonical profile changed: error=%v", err)
		}
		// Exercise materialization too; format validity does not imply support.
		_, _, _ = profile.Materialize()
	})
}

func FuzzProfileConstraints(f *testing.F) {
	for _, seed := range []struct {
		path, operator, value string
	}{
		{"/extensions/0", "present", ""},
		{"/alpn", "equals", "[]"},
		{"/a~0b/~1", "one_of", "null"},
		{"/a~2", "equals", "true"},
		{"", "present", ""},
		{"/x", "unsupported", "{}"},
		{"/x", "equals", "\xff"},
	} {
		for mode := uint8(0); mode < 4; mode++ {
			f.Add(seed.path, seed.operator, []byte(seed.value), []byte("0"), mode)
		}
	}
	f.Fuzz(func(t *testing.T, path, operator string, value, other []byte, mode uint8) {
		if len(path)+len(operator)+len(value)+len(other) > 8192 {
			t.Skip()
		}
		constraint := ClientProfileConstraint{Path: path, Operator: operator}
		if mode&1 != 0 {
			constraint.Value = value
		}
		if mode&2 != 0 {
			constraint.Values = []json.RawMessage{value, other}
		}
		valid := strings.HasPrefix(path, "/") && fuzzValidPointer(path)
		switch operator {
		case "present":
			valid = valid && len(constraint.Value) == 0 && len(constraint.Values) == 0
		case "equals":
			valid = valid && json.Valid(constraint.Value) && len(constraint.Values) == 0
		case "one_of":
			valid = valid && len(constraint.Value) == 0 && len(constraint.Values) > 0 &&
				json.Valid(value) && json.Valid(other)
		default:
			valid = false
		}
		if err := validateProfileConstraint(constraint); (err == nil) != valid {
			t.Fatalf("constraint contract: valid=%t, path=%q, operator=%q, error=%v", valid, path, operator, err)
		}
	})
}

func fuzzValidPointer(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] != '~' {
			continue
		}
		i++
		if i == len(path) || (path[i] != '0' && path[i] != '1') {
			return false
		}
	}
	return true
}
