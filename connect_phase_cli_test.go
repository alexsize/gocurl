package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runConnectPhaseCLI(t *testing.T, args []string, wantCode int) (string, string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.CommandContext(ctx, binary, append([]string{"-test.run=^TestCLIHelperProcess$", "--"}, args...)...)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	command.Stdout, command.Stderr = stdout, stderr
	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != wantCode || ctx.Err() != nil {
		t.Fatalf("CLI err=%v, want exit %d; stdout=%q stderr=%q", err, wantCode, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String()
}

func TestCLIRejectsIncompatiblePostQuantumBeforeDial(t *testing.T) {
	for _, mode := range []string{"profile", "http3"} {
		t.Run(mode, func(t *testing.T) {
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tcp.Close() }()
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = udp.Close() }()
			args := []string{"--json-output", "--experiment=pq"}
			addr := tcp.Addr().String()
			if mode == "profile" {
				args = append(
					args,
					"--tls-profile",
					filepath.Join("internal", "client", "utlsengine", "testdata", "profile-v1-valid.json"),
				)
			} else {
				args = append(args, "--http3")
				addr = udp.LocalAddr().String()
			}
			stdout, stderr := runConnectPhaseCLI(t, append(args, "https://"+addr+"/"), 2)
			var result struct {
				Error    string `json:"error"`
				ExitCode int    `json:"exit_code"`
			}
			if err = json.Unmarshal([]byte(stdout), &result); err != nil ||
				result.ExitCode != 2 || !strings.Contains(result.Error, "post-quantum") || stderr != "" {
				t.Fatalf("CLI stdout=%q stderr=%q err=%v, want configuration error", stdout, stderr, err)
			}
			if err = tcp.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			conn, acceptErr := tcp.Accept()
			if conn != nil {
				_ = conn.Close()
				t.Fatal("CLI opened TCP connection for incompatible parameters")
			}
			var timeout net.Error
			if !errors.As(acceptErr, &timeout) || !timeout.Timeout() {
				t.Fatalf("Accept()=%v, want timeout", acceptErr)
			}
			if err = udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var b [1500]byte
			_, _, err = udp.ReadFrom(b[:])
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("UDP ReadFrom()=%v, want no Initial packet", err)
			}
		})
	}
}

func TestCLIConnectTimeoutBoundsTargetHandshake(t *testing.T) {
	for _, mode := range []string{"tls", "quic"} {
		for _, jsonOutput := range []bool{false, true} {
			name := mode + "/text"
			if jsonOutput {
				name = mode + "/json"
			}
			t.Run(name, func(t *testing.T) {
				args := []string{"--connect-timeout", "1", "--insecure"}
				addr := ""
				if mode == "quic" {
					conn, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = conn.Close() }()
					addr = conn.LocalAddr().String()
					args = append(args, "--http3")
				} else {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = listener.Close() }()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					done := make(chan struct{})
					go func() {
						defer close(done)
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						defer func() { _ = conn.Close() }()
						stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
						defer stop()
						_, _ = io.Copy(io.Discard, conn)
					}()
					t.Cleanup(func() {
						cancel()
						_ = listener.Close()
						select {
						case <-done:
						case <-time.After(time.Second):
							t.Error("stalled CLI TLS fixture did not stop")
						}
					})
					addr = listener.Addr().String()
					args = append(args, "--http1.1")
				}
				if jsonOutput {
					args = append(args, "--json-output")
				}
				started := time.Now()
				stdout, stderr := runConnectPhaseCLI(t, append(args, "https://"+addr+"/"), 3)
				if elapsed := time.Since(started); elapsed < 800*time.Millisecond || elapsed > 2500*time.Millisecond {
					t.Fatalf("CLI timeout took %v, want approximately one second", elapsed)
				}
				if jsonOutput {
					var result struct {
						Error    string `json:"error"`
						ExitCode int    `json:"exit_code"`
					}
					if err := json.Unmarshal([]byte(stdout), &result); err != nil || result.ExitCode != 3 ||
						!strings.Contains(result.Error, "deadline exceeded") || stderr != "" {
						t.Fatalf("CLI timeout JSON=%q stderr=%q err=%v", stdout, stderr, err)
					}
				} else if !strings.Contains(stderr, "deadline exceeded") {
					t.Fatalf("CLI stderr=%q, want deadline error", stderr)
				}
			})
		}
	}
}
