package httpjson

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startVerificationOnlyBoundary composes the exact boundary a verification
// daemon assembles: the process capability, no signing application service,
// and no route matcher. The datasource behind such a daemon serves
// received-DSN locality only.
func startVerificationOnlyBoundary(t *testing.T, processSecret []byte) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	tracked, err := newTrackedListener(raw, nil)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("newTrackedListener() error = %v", err)
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("NewRequestValidator() error = %v", err)
	}
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       raw.Addr().String(),
		RequestDeadline: 5 * time.Second,
		MaxInFlight:     2,
		MaxWaiters:      4,
		AdmissionWait:   100 * time.Millisecond,
	}, &boundaryCapabilityMatcher{value: bytes.Clone(processSecret)}, readiness,
		&boundaryProcessor{}, &boundaryFatalNotifier{}, validator)
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("NewHTTPBoundary() error = %v", err)
	}
	server := &http.Server{
		Handler:                      handler,
		ConnContext:                  tracked.ConnContext,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
		MaxHeaderBytes:               transportServerMaxHeaderBytes,
	}
	done := make(chan struct{})
	go func() {
		_ = server.Serve(tracked)
		close(done)
	}()
	t.Cleanup(func() {
		handler.Close()
		_ = server.Close()
		_ = tracked.Close()
		<-done
	})
	return raw.Addr().String()
}

// TestVerificationOnlyBoundaryRefusesEverySigningRoute proves a daemon that
// holds only the process capability cannot be made to sign: every signing and
// propagation route answers 403 for every credential the daemon knows,
// including its own process capability, while the process route it does own
// stays reachable.
func TestVerificationOnlyBoundaryRefusesEverySigningRoute(t *testing.T) {
	processSecret := bytes.Repeat([]byte{0xa5}, 32)
	foreignSecret := bytes.Repeat([]byte{0xb6}, 32)
	address := startVerificationOnlyBoundary(t, processSecret)
	client := &http.Client{Timeout: 5 * time.Second}
	credentials := map[string][]byte{
		localCapabilityHeader:        processSecret,
		dsnSignCapabilityHeader:      processSecret,
		dsnPropagateCapabilityHeader: processSecret,
		"foreign":                    foreignSecret,
	}
	for _, path := range []string{
		signPath, revisePath, dsnSignPath, dsnPropagatePath, dsnPropagateCommitPath,
	} {
		for header, secret := range credentials {
			field := header
			if field == "foreign" {
				field = localCapabilityHeader
			}
			status := verificationOnlyStatus(t, client, address, path, field, secret)
			if status != http.StatusForbidden {
				t.Fatalf("%s with %s answered %d, want 403", path, header, status)
			}
		}
		if status := verificationOnlyStatus(t, client, address, path, "", nil); status != http.StatusForbidden {
			t.Fatalf("%s without a credential answered %d, want 403", path, status)
		}
	}
	if status := verificationOnlyStatus(
		t, client, address, processPath, localCapabilityHeader, processSecret,
	); status == http.StatusForbidden {
		t.Fatal("the process route the daemon owns answered 403")
	}
	if status := verificationOnlyStatus(
		t, client, address, processPath, localCapabilityHeader, foreignSecret,
	); status != http.StatusForbidden {
		t.Fatalf("the process route accepted a foreign credential with status %d", status)
	}
}

// verificationOnlyStatus performs one bounded request and returns its status.
func verificationOnlyStatus(
	t *testing.T,
	client *http.Client,
	address, path, header string,
	secret []byte,
) int {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost, "http://"+address+path, strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatalf("NewRequest(%s) error = %v", path, err)
	}
	request.Header.Set("Content-Type", "application/json")
	if header != "" {
		request.Header.Set(header, base64.RawURLEncoding.EncodeToString(secret))
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Do(%s) error = %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}
