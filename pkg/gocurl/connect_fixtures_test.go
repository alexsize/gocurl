package gocurl

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func testHTTPConnectHandler(targetAddress string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
			return
		}
		targetConn, dialErr := net.DialTimeout("tcp", targetAddress, time.Second)
		if dialErr != nil {
			http.Error(w, dialErr.Error(), http.StatusBadGateway)
			return
		}
		proxyConn, rw, hijackErr := w.(http.Hijacker).Hijack()
		if hijackErr != nil {
			_ = targetConn.Close()
			return
		}
		defer proxyConn.Close()
		defer targetConn.Close()
		if _, hijackErr = rw.WriteString(
			"HTTP/1.1 200 Connection Established\r\n\r\n",
		); hijackErr != nil ||
			rw.Flush() != nil {
			return
		}
		copyDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(targetConn, rw)
			if closeWriter, ok := targetConn.(interface{ CloseWrite() error }); ok {
				_ = closeWriter.CloseWrite()
			}
			close(copyDone)
		}()
		_, _ = io.Copy(proxyConn, targetConn)
		<-copyDone
	})
}

func testStrictHTTPConnectHandler(
	t *testing.T,
	targetAddress string,
	connects chan<- string,
	done chan<- struct{},
) http.HandlerFunc {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		connects <- r.Host
		clientConn, rw, hijackErr := w.(http.Hijacker).Hijack()
		if hijackErr != nil {
			t.Errorf("proxy Hijack() error: %v", hijackErr)
			return
		}
		defer func() { _ = clientConn.Close() }()
		targetConn, dialErr := net.Dial("tcp", targetAddress)
		if dialErr != nil {
			t.Errorf("proxy dial target: %v", dialErr)
			return
		}
		defer func() { _ = targetConn.Close() }()
		if _, hijackErr = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); hijackErr != nil {
			t.Errorf("write CONNECT response: %v", hijackErr)
			return
		}
		if hijackErr = rw.Flush(); hijackErr != nil {
			t.Errorf("flush CONNECT response: %v", hijackErr)
			return
		}
		copyDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(targetConn, rw)
			if tcpConn, ok := targetConn.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			}
			close(copyDone)
		}()
		_, _ = io.Copy(clientConn, targetConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		<-copyDone
		done <- struct{}{}
	})
}
