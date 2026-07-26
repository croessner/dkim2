package testclient

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestRuntimePublicSocketSmoke exercises the owned dialer, generated client,
// parsed response metadata, and close lifecycle over a real loopback socket.
func TestRuntimePublicSocketSmoke(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan error, 1)
	go serveOneHealthResponse(listener, serverDone)

	options := DefaultOptions()
	options.ServerURL = "http://" + listener.Addr().String()
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatal("construct public-socket runtime")
	}
	defer func() { _ = runtime.Close() }()
	fact, err := runtime.CallHealth(t.Context())
	if err != nil || fact.Health == nil || fact.Status != http.StatusOK {
		t.Fatal("public-socket generated health call failed")
	}
	select {
	case serverErr := <-serverDone:
		if serverErr != nil {
			t.Fatal("public-socket responder failed")
		}
	case <-time.After(time.Second):
		t.Fatal("public-socket responder did not terminate")
	}
}

// serveOneHealthResponse serves one exact daemon-compatible health response.
func serveOneHealthResponse(listener net.Listener, done chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		done <- err
		return
	}
	defer func() { _ = connection.Close() }()
	request, err := http.ReadRequest(bufio.NewReader(connection))
	if err != nil || request.Method != http.MethodGet || request.URL.Path != "/healthz" {
		done <- fmt.Errorf("invalid health request")
		return
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	body := healthResponseBody
	response := "HTTP/1.1 200 OK\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		`ETag: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"` + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, err = connection.Write([]byte(response))
	done <- err
}
