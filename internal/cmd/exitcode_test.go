package cmd

import (
	"errors"
	"testing"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
)

func TestWithExitCodePreservesCodedErrors(t *testing.T) {
	original := &ExitCodeError{code: 2, err: errors.New("bad profile")}
	if got := withExitCode(original, 3); got != original {
		t.Fatal("withExitCode() replaced an error that already carried an exit code")
	}

	wrapped := withExitCode(errors.New("connection failed"), 3)
	var coded interface{ ExitCode() int }
	if !errors.As(wrapped, &coded) || coded.ExitCode() != 3 {
		t.Fatalf("wrapped error = %v, want exit code 3", wrapped)
	}
}

func TestWithExitCodePreservesProfileCheckStatusAndCode(t *testing.T) {
	original := utlsengine.NewProfileCheckError("REUSED_CONNECTION", nil)
	wrapped := withExitCode(original, 3)
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	if !errors.As(wrapped, &status) || status.Status() != "REUSED_CONNECTION" ||
		!errors.As(wrapped, &coded) || coded.ExitCode() != 5 {
		t.Fatalf("wrapped error = %v, want REUSED_CONNECTION and exit code 5", wrapped)
	}
}

func TestJSONOutputRequested(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want bool
	}{
		{arg: "--json-output", want: true},
		{arg: "--json-output=true", want: true},
		{arg: "--json-output=1", want: true},
		{arg: "--json-output=false", want: false},
		{arg: "https://example.test", want: false},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			if got := jsonOutputRequested([]string{tc.arg}); got != tc.want {
				t.Fatalf("jsonOutputRequested() = %t, want %t", got, tc.want)
			}
		})
	}
}
