package gocurl

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestAPIParityMatrixCoversPublicRequestTypes(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate parity matrix")
	}
	path := filepath.Join(filepath.Dir(sourceFile), "..", "..", "docs", "API_CLI_PARITY.md")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool)
	for _, typ := range []reflect.Type{
		reflect.TypeOf(Request{}), reflect.TypeOf(Header{}), reflect.TypeOf(HTTP2Settings{}),
		reflect.TypeOf(HTTP2Priority{}), reflect.TypeOf(QUICTransport{}), reflect.TypeOf(TLSSplitHello{}),
		reflect.TypeOf(TLSProfile{}), reflect.TypeOf(TLSClientHello{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			want[typ.Name()+"."+typ.Field(i).Name] = true
		}
	}
	tests := make(map[string]struct{})
	seen := make(map[string]bool)
	reference := regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")
	for _, line := range strings.Split(string(document), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 6 {
			t.Errorf("parity row must have four columns: %s", line)
			continue
		}
		field := strings.Trim(strings.TrimSpace(cells[1]), "`")
		if !want[field] || seen[field] {
			t.Errorf("unknown or duplicate parity field %q", field)
		}
		seen[field] = true
		for _, cell := range cells[2:5] {
			if strings.TrimSpace(cell) == "" {
				t.Errorf("empty evidence for %s", field)
			}
		}
		// Every field needs an actual wire/e2e test, not just a mapping test.
		if !reference.MatchString(cells[3]) {
			t.Errorf("missing wire/e2e test for %s", field)
		}
		for _, match := range reference.FindAllStringSubmatch(line, -1) {
			tests[match[1]] = struct{}{}
		}
	}
	for field := range want {
		if !seen[field] {
			t.Errorf("missing parity evidence for %s", field)
		}
	}
	assertRequestContractTestsExist(t, sourceFile, tests)
}
