package gocurl

import (
	"net/http"
	"sort"
	"strings"
)

type requestMetadataOptions struct {
	redactHeaders         []string
	configuredHeaderOrder []string
	requestTarget         string
}

// RequestMetadata is a JSON-friendly snapshot of the outbound request.
// Headers and configured order are detached copies; the request body is not
// included.
type RequestMetadata struct {
	Method                string      `json:"method"`
	URL                   string      `json:"url"`
	Protocol              string      `json:"protocol"`
	Host                  string      `json:"host"`
	RequestTarget         string      `json:"request_target"`
	Headers               http.Header `json:"headers"`
	ConfiguredHeaderOrder []string    `json:"configured_header_order,omitempty"`
	RedactedHeaderNames   []string    `json:"redacted_header_names,omitempty"`
	ContentLength         int64       `json:"content_length"`
	TransferEncoding      []string    `json:"transfer_encoding,omitempty"`
}

// RequestMetadata returns a detached snapshot of the request associated with
// the response. Headers named in Request.JSONRedactHeaders are replaced with
// "[REDACTED]" in the snapshot only; the actual request and Response.Request
// remain unchanged. It returns nil when no request is associated with Result.
func (r *Result) RequestMetadata() *RequestMetadata {
	if r == nil || r.Response == nil || r.Response.Request == nil {
		return nil
	}

	request := r.Response.Request
	metadata := &RequestMetadata{
		Method:                request.Method,
		Protocol:              r.Response.Proto,
		Host:                  request.Host,
		Headers:               request.Header.Clone(),
		ConfiguredHeaderOrder: append([]string(nil), r.metadata.configuredHeaderOrder...),
		ContentLength:         request.ContentLength,
		TransferEncoding:      append([]string(nil), request.TransferEncoding...),
	}
	if metadata.Headers == nil {
		metadata.Headers = make(http.Header)
	}
	if request.URL != nil {
		metadata.URL = request.URL.String()
		metadata.RequestTarget = request.URL.RequestURI()
		if r.metadata.requestTarget != "" {
			metadata.RequestTarget = r.metadata.requestTarget
		}
	}

	for name := range metadata.Headers {
		if isRequestHeaderRedacted(name, r.metadata.redactHeaders) {
			metadata.Headers[name] = []string{"[REDACTED]"}
			metadata.RedactedHeaderNames = append(metadata.RedactedHeaderNames, name)
		}
	}
	if request.URL != nil && request.URL.User != nil &&
		isRequestHeaderRedacted("Authorization", r.metadata.redactHeaders) {
		parsedURL := *request.URL
		parsedURL.User = nil
		metadata.URL = parsedURL.String()
		if _, exists := metadata.Headers[http.CanonicalHeaderKey("Authorization")]; !exists {
			metadata.Headers.Set("Authorization", "[REDACTED]")
			metadata.RedactedHeaderNames = append(metadata.RedactedHeaderNames, "Authorization")
		}
	}

	for i, line := range metadata.ConfiguredHeaderOrder {
		name, _, ok := strings.Cut(line, ":")
		if ok && isRequestHeaderRedacted(name, r.metadata.redactHeaders) {
			metadata.ConfiguredHeaderOrder[i] = strings.TrimSpace(name) + ": [REDACTED]"
		}
	}
	sort.Strings(metadata.RedactedHeaderNames)
	return metadata
}

func isRequestHeaderRedacted(name string, redactedNames []string) bool {
	for _, redactedName := range redactedNames {
		if strings.EqualFold(name, redactedName) {
			return true
		}
	}
	return false
}
