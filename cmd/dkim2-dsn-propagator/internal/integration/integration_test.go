//go:build linux || darwin

// Package integration proves the public adapter boundary end to end.
package integration

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/daemon/wire"
	fixture "github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/integration/generated"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/testsupport"
)

const (
	signedNotification = "Subject: propagated notification\r\n\r\nreport\r\n"
	nextHopRecipient   = "<previous@hop.example>"
	commitToken        = "coordinate-token-0001"
	capabilityHeader   = "X-DKIM2-DSN-Propagate-Capability"
)

// daemonFixture is the strict generated server the adapter talks to.
type daemonFixture struct {
	mu       sync.Mutex
	accept   bool
	commits  int
	requests int
	tenants  []string
}

// PropagateDeliveryStatus answers one propagation request from the contract.
func (d *daemonFixture) PropagateDeliveryStatus(
	_ context.Context,
	request fixture.PropagateDeliveryStatusRequestObject,
) (fixture.PropagateDeliveryStatusResponseObject, error) {
	d.mu.Lock()
	d.requests++
	if request.Body != nil {
		d.tenants = append(d.tenants, request.Body.Context.Tenant)
	}
	accept := d.accept
	d.mu.Unlock()
	if !accept {
		return fixture.PropagateDeliveryStatus200JSONResponse{
			Body: fixture.DSNPropagateResponse{
				ApiVersion:  fixture.V1,
				Draft:       fixture.DraftIetfDkimDkim2Spec06,
				Operation:   fixture.PropagationOperationDeliveryStatusPropagation,
				Result:      fixture.PropagationResultFail,
				Disposition: fixture.PropagationDispositionReject,
				Replay:      fixture.ReplayResult{Class: fixture.FirstSeen},
			},
		}, nil
	}
	recipient, err := wire.NewProtectedString(nextHopRecipient)
	if err != nil {
		return nil, err
	}
	message, err := wire.NewProtectedString(
		base64.StdEncoding.EncodeToString([]byte(signedNotification)),
	)
	if err != nil {
		return nil, err
	}
	token, err := wire.NewProtectedString(commitToken)
	if err != nil {
		return nil, err
	}
	return fixture.PropagateDeliveryStatus200JSONResponse{
		Body: fixture.DSNPropagateResponse{
			ApiVersion:  fixture.V1,
			Draft:       fixture.DraftIetfDkimDkim2Spec06,
			Operation:   fixture.PropagationOperationDeliveryStatusPropagation,
			Result:      fixture.PropagationResultPass,
			Disposition: fixture.PropagationDispositionAccept,
			Replay:      fixture.ReplayResult{Class: fixture.FirstSeen},
			Propagation: &fixture.PropagationOutput{
				NextHopRecipient:     recipient,
				Smtputf8Required:     false,
				EightBitMimeRequired: false,
				CommitToken:          token,
				RawRfc5322Base64:     message,
			},
		},
	}, nil
}

// CommitDeliveryStatusPropagation commits exactly the reserved coordinate.
func (d *daemonFixture) CommitDeliveryStatusPropagation(
	_ context.Context,
	request fixture.CommitDeliveryStatusPropagationRequestObject,
) (fixture.CommitDeliveryStatusPropagationResponseObject, error) {
	if request.Body == nil {
		return nil, io.ErrUnexpectedEOF
	}
	value, err := request.Body.CommitToken.Bytes()
	if err != nil || string(value) != commitToken {
		return fixture.CommitDeliveryStatusPropagation409JSONResponse{}, nil
	}
	d.mu.Lock()
	d.commits++
	d.mu.Unlock()
	return fixture.CommitDeliveryStatusPropagation200JSONResponse{
		Body: fixture.DSNPropagateCommitResponse{
			ApiVersion: fixture.V1,
			Draft:      fixture.DraftIetfDkimDkim2Spec06,
			State:      fixture.PropagationStateCommitted,
		},
	}, nil
}

// observed returns the recorded request, commit, and tenant evidence.
func (d *daemonFixture) observed() (int, int, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.requests, d.commits, append([]string(nil), d.tenants...)
}

// startDaemon serves the strict generated handler on a loopback origin.
func startDaemon(t *testing.T, server *daemonFixture) string {
	t.Helper()
	handler := fixture.HandlerFromMux(
		fixture.NewStrictHandler(server, nil),
		http.NewServeMux(),
	)
	guarded := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get(capabilityHeader) == "" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		serveWithContractHeaders(writer, request, handler)
	})
	httpServer := httptest.NewServer(guarded)
	t.Cleanup(httpServer.Close)
	return httpServer.URL
}

// serveWithContractHeaders completes the declared daemon response headers.
//
// The generated strict server leaves the contract's declared header values to
// the daemon implementation, and the generated client refuses a response whose
// declared headers are empty. The fixture therefore buffers the strict answer
// and supplies the exact header values the contract requires.
func serveWithContractHeaders(
	writer http.ResponseWriter,
	request *http.Request,
	handler http.Handler,
) {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	body := recorder.Body.Bytes()
	for key, values := range recorder.Header() {
		for _, value := range values {
			if value != "" {
				writer.Header().Add(key, value)
			}
		}
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(recorder.Code)
	_, _ = writer.Write(body)
}

// reinjectionListener is a bounded fake submission listener.
type reinjectionListener struct {
	listener net.Listener
	mu       sync.Mutex
	messages []string
	refuse   bool
}

// startReinjection binds one loopback listener that records accepted messages.
func startReinjection(t *testing.T, refuse bool) *reinjectionListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("re-injection listener failed")
	}
	fake := &reinjectionListener{listener: listener, refuse: refuse}
	t.Cleanup(func() { _ = listener.Close() })
	go fake.accept()
	return fake
}

// origin returns the canonical loopback SMTP origin of this listener.
func (l *reinjectionListener) origin() string {
	return "smtp://" + l.listener.Addr().String()
}

// accept serves every connection until the listener closes.
func (l *reinjectionListener) accept() {
	for {
		connection, err := l.listener.Accept()
		if err != nil {
			return
		}
		go l.serve(connection)
	}
}

// serve answers one bounded SMTP conversation and records the message.
func (l *reinjectionListener) serve(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	write := func(line string) {
		_, _ = writer.WriteString(line + "\r\n")
		_ = writer.Flush()
	}
	write("220 listener ready")
	var message strings.Builder
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				if l.refuse {
					write("451 4.3.0 not now")
					continue
				}
				l.record(message.String())
				message.Reset()
				write("250 accepted")
				continue
			}
			content := strings.TrimPrefix(line, ".")
			message.WriteString(content)
			message.WriteString("\r\n")
			continue
		}
		verb, _, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			write("250-listener")
			write("250 8BITMIME")
		case "DATA":
			write("354 send it")
			inData = true
		case "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

// record stores one accepted message.
func (l *reinjectionListener) record(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, message)
}

// accepted returns every message the listener acknowledged.
func (l *reinjectionListener) accepted() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.messages...)
}

// startAdapter composes and starts the complete production adapter graph.
func startAdapter(
	t *testing.T,
	daemonOrigin string,
	reinjectionOrigin string,
	policy string,
) string {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)
	socket := filepath.Join(root, "lmtp.sock")
	protected := filepath.Join(root, "protected")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal("capability directory failed")
	}
	capabilityPath := filepath.Join(protected, "propagate.key")
	value := make([]byte, 32)
	for index := range value {
		value[index] = byte(index + 1)
	}
	if err := os.WriteFile(capabilityPath, value, 0o600); err != nil {
		t.Fatal("capability file failed")
	}
	if err := os.Chmod(protected, 0o500); err != nil {
		t.Fatal("capability directory mode failed")
	}
	t.Cleanup(func() { _ = os.Chmod(protected, 0o700) })
	document := "version: dkim2-dsn-propagator-config-v1\n" +
		"server:\n  socket: " + socket + "\n" +
		"daemon:\n  endpoint: " + daemonOrigin + "\n" +
		"  capability_file: " + capabilityPath + "\n" +
		"reinjection:\n  endpoint: " + reinjectionOrigin + "\n" +
		"propagation:\n  tenant: tenant-a\n  reporting_mta: mta.example\n" +
		"  permanent_failure_reply: " + policy + "\n"
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal("configuration fixture failed")
	}
	snapshot, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("configuration rejected: %v", err)
	}
	application, err := app.New(snapshot, io.Discard)
	if err != nil {
		t.Fatalf("application composition failed: %v", err)
	}
	startContext, cancel := context.WithTimeout(context.Background(), app.StartTimeout)
	defer cancel()
	if err := application.Start(startContext); err != nil {
		t.Fatalf("application start failed: %v", err)
	}
	t.Cleanup(func() {
		stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = application.Stop(stopContext)
	})
	return socket
}

// deliver runs one complete LMTP transaction and returns the final reply.
func deliver(t *testing.T, socket string) string {
	t.Helper()
	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal("dial failed")
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(connection)
	read := func() string {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read failed: %v", readErr)
		}
		return line
	}
	if greeting := read(); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting %q", greeting)
	}
	send := func(line string) {
		if _, writeErr := connection.Write([]byte(line + "\r\n")); writeErr != nil {
			t.Fatal("write failed")
		}
	}
	send("LHLO client.example")
	for {
		line := read()
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	send("MAIL FROM:<>")
	read()
	send("RCPT TO:<bounce+abc@local.example>")
	read()
	send("DATA")
	read()
	send("Subject: received dsn")
	send("")
	send("report")
	send(".")
	final := read()
	send("QUIT")
	return final
}

// TestPropagationAcknowledgedOnlyAfterListenerAndCommit proves the complete
// public adapter path over the generated contract boundary.
func TestPropagationAcknowledgedOnlyAfterListenerAndCommit(t *testing.T) {
	server := &daemonFixture{accept: true}
	listener := startReinjection(t, false)
	socket := startAdapter(t, startDaemon(t, server), listener.origin(), "reject")
	if reply := deliver(t, socket); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("final reply %q", reply)
	}
	requests, commits, tenants := server.observed()
	if requests != 1 || commits != 1 {
		t.Fatalf("requests=%d commits=%d", requests, commits)
	}
	if len(tenants) != 1 || tenants[0] != "tenant-a" {
		t.Fatalf("tenant evidence %v", tenants)
	}
	accepted := listener.accepted()
	if len(accepted) != 1 || accepted[0] != signedNotification {
		t.Fatalf("re-injected message %q", accepted)
	}
}

// TestReinjectionOutageDefers proves nothing is acknowledged or committed
// when the re-injection listener refuses the notification.
func TestReinjectionOutageDefers(t *testing.T) {
	server := &daemonFixture{accept: true}
	listener := startReinjection(t, true)
	socket := startAdapter(t, startDaemon(t, server), listener.origin(), "reject")
	if reply := deliver(t, socket); !strings.HasPrefix(reply, "451 4.4.1 ") {
		t.Fatalf("final reply %q", reply)
	}
	_, commits, _ := server.observed()
	if commits != 0 {
		t.Fatalf("a refused re-injection was committed: %d", commits)
	}
	if len(listener.accepted()) != 0 {
		t.Fatal("a refused listener recorded a message")
	}
}

// TestVerificationFailureRejects proves the default permanent-failure reply.
func TestVerificationFailureRejects(t *testing.T) {
	server := &daemonFixture{accept: false}
	listener := startReinjection(t, false)
	socket := startAdapter(t, startDaemon(t, server), listener.origin(), "reject")
	if reply := deliver(t, socket); !strings.HasPrefix(reply, "550 5.7.1 ") {
		t.Fatalf("final reply %q", reply)
	}
	if len(listener.accepted()) != 0 {
		t.Fatal("a rejected notification was re-injected")
	}
}

// TestVerificationFailureDiscardPolicy proves the only adapter policy knob.
func TestVerificationFailureDiscardPolicy(t *testing.T) {
	server := &daemonFixture{accept: false}
	listener := startReinjection(t, false)
	socket := startAdapter(t, startDaemon(t, server), listener.origin(), "discard")
	if reply := deliver(t, socket); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("final reply %q", reply)
	}
	if len(listener.accepted()) != 0 {
		t.Fatal("a discarded notification was re-injected")
	}
}
