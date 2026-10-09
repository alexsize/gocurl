package config

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// validateExactHeaders rejects framing that net/http would silently rewrite
// and ambiguous hop-by-hop fields before the request reaches the network.
func validateExactHeaders(headers http.Header) error {
	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Connection", "TE", "Trailer",
		"Transfer-Encoding", "Upgrade", "Proxy-Authenticate", "Proxy-Authorization",
	} {
		if len(headers.Values(name)) > 1 {
			return fmt.Errorf("--no-default-headers: repeated %s is unsupported", name)
		}
	}
	if headers.Get("Proxy-Authorization") != "" {
		return fmt.Errorf("--no-default-headers: Proxy-Authorization belongs to the proxy, not the target request")
	}
	if headers.Get("Trailer") != "" {
		return fmt.Errorf("--no-default-headers: request Trailer is unsupported")
	}
	lengths := headers.Values("Content-Length")
	if len(lengths) > 1 {
		return fmt.Errorf("--no-default-headers: repeated Content-Length is unsupported")
	}
	if len(lengths) == 1 {
		length := strings.TrimSpace(lengths[0])
		if _, err := strconv.ParseUint(length, 10, 63); err != nil {
			return fmt.Errorf("--no-default-headers: invalid Content-Length %q", length)
		}
	}
	encodings := headers.Values("Transfer-Encoding")
	if len(encodings) == 0 {
		return nil
	}
	if len(lengths) != 0 {
		return fmt.Errorf("--no-default-headers: Content-Length conflicts with Transfer-Encoding")
	}
	if !strings.EqualFold(strings.TrimSpace(encodings[0]), "chunked") {
		return fmt.Errorf("--no-default-headers: only Transfer-Encoding: chunked is supported")
	}
	return nil
}
