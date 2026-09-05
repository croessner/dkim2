//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/testsupport"
)

// capabilityFixture creates one protected capability file with exact policy.
func capabilityFixture(t *testing.T, mode os.FileMode, size int) string {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)
	directory := filepath.Join(root, "protected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("capability directory failed")
	}
	path := filepath.Join(directory, "propagate.key")
	value := make([]byte, size)
	for index := range value {
		value[index] = byte(index + 1)
	}
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal("capability file failed")
	}
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal("capability directory mode failed")
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	return path
}

// TestLoadCapabilityPolicy proves the exact protected-file rules.
func TestLoadCapabilityPolicy(t *testing.T) {
	capability, err := LoadCapability(capabilityFixture(t, 0o600, 32))
	if err != nil || capability == nil {
		t.Fatalf("valid capability rejected: %v", err)
	}
	defer func() { _ = capability.Close() }()
	if _, err := LoadCapability(capabilityFixture(t, 0o666, 32)); err == nil {
		t.Fatal("a world-readable capability was loaded")
	}
	if _, err := LoadCapability(capabilityFixture(t, 0o600, 31)); err == nil {
		t.Fatal("a short capability was loaded")
	}
	if _, err := LoadCapability("relative.key"); err == nil {
		t.Fatal("a relative capability path was loaded")
	}
}

// TestCapabilityRouteConfinement proves the credential reaches only the two
// propagation operations of one literal loopback origin.
func TestCapabilityRouteConfinement(t *testing.T) {
	capability, err := LoadCapability(capabilityFixture(t, 0o600, 32))
	if err != nil {
		t.Fatal("capability load failed")
	}
	defer func() { _ = capability.Close() }()
	const origin = "http://127.0.0.1:8080"
	if err := capability.bindRequestTargets(origin); err != nil {
		t.Fatal("binding the propagation origin failed")
	}
	if err := capability.bindRequestTargets("http://127.0.0.1:9090"); err == nil {
		t.Fatal("a second origin was bound to the same capability")
	}
	for _, target := range []string{origin + routePropagate, origin + routeCommit} {
		request := generatedRequest(t, target)
		if err := capability.EditRequest(context.Background(), request); err != nil {
			t.Fatalf("the propagation request %q was not credentialed", target)
		}
		if request.Header.Get(propagateCapabilityHeader) == "" {
			t.Fatalf("no credential on %q", target)
		}
	}
	for _, target := range []string{
		origin + "/v1/process", origin + "/v1/sign", origin + "/v1/revise",
		origin + "/v1/dsn/sign", "http://127.0.0.1:9090" + routePropagate,
	} {
		request := generatedRequest(t, target)
		if err := capability.EditRequest(context.Background(), request); err == nil {
			t.Fatalf("the foreign route %q was credentialed", target)
		}
	}
}

// TestCapabilityRejectsPreCredentialedRequests proves header spoofing fails.
func TestCapabilityRejectsPreCredentialedRequests(t *testing.T) {
	capability, err := LoadCapability(capabilityFixture(t, 0o600, 32))
	if err != nil {
		t.Fatal("capability load failed")
	}
	defer func() { _ = capability.Close() }()
	const origin = "http://127.0.0.1:8080"
	if err := capability.bindRequestTargets(origin); err != nil {
		t.Fatal("binding failed")
	}
	for _, header := range []string{
		propagateCapabilityHeader, capabilityHeader, dsnSignCapabilityHeader,
	} {
		request := generatedRequest(t, origin+routePropagate)
		request.Header.Set(header, "spoofed")
		if err := capability.EditRequest(context.Background(), request); err == nil {
			t.Fatalf("a request already carrying %q was credentialed", header)
		}
	}
}

// TestCapabilityCloseErases proves the credential does not survive shutdown.
func TestCapabilityCloseErases(t *testing.T) {
	capability, err := LoadCapability(capabilityFixture(t, 0o600, 32))
	if err != nil {
		t.Fatal("capability load failed")
	}
	const origin = "http://127.0.0.1:8080"
	if err := capability.bindRequestTargets(origin); err != nil {
		t.Fatal("binding failed")
	}
	if err := capability.Close(); err != nil {
		t.Fatal("close failed")
	}
	if err := capability.Close(); err != nil {
		t.Fatal("second close was not idempotent")
	}
	request := generatedRequest(t, origin+routePropagate)
	if err := capability.EditRequest(context.Background(), request); err == nil {
		t.Fatal("a closed capability still credentialed a request")
	}
	rendered := capability.String() + capability.GoString()
	if strings.Contains(rendered, base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})) {
		t.Fatal("capability leaked material")
	}
	if _, err := capability.MarshalJSON(); err == nil {
		t.Fatal("capability serialization was permitted")
	}
}

// generatedRequest builds one request with the exact generated-client shape.
func generatedRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
	if err != nil {
		t.Fatal("request construction failed")
	}
	request.ContentLength = 2
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", fixedUserAgent)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", cacheControlNoStore)
	return request
}

// TestClientEndpointConfinement proves only literal loopback origins are used.
func TestClientEndpointConfinement(t *testing.T) {
	for _, origin := range []string{
		"http://daemon.example:8080", "https://127.0.0.1:8080",
		"http://127.0.0.1:8080/v1", "http://user@127.0.0.1:8080",
	} {
		capability, err := LoadCapability(capabilityFixture(t, 0o600, 32))
		if err != nil {
			t.Fatal("capability load failed")
		}
		client, err := NewClient(
			origin, capability, "tenant-a", "mta.example",
			time.Second, time.Second, 1<<20,
		)
		_ = capability.Close()
		if err == nil {
			_ = client.Close()
			t.Fatalf("origin %q was admitted", origin)
		}
	}
}

// TestPropagateRejectsUnboundedInput proves the request bounds fail closed.
func TestPropagateRejectsUnboundedInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		},
	))
	defer server.Close()
	capability, err := LoadCapability(capabilityFixture(t, 0o600, 32))
	if err != nil {
		t.Fatal("capability load failed")
	}
	defer func() { _ = capability.Close() }()
	client, err := NewClient(
		server.URL, capability, "tenant-a", "mta.example",
		time.Second, time.Second, 16,
	)
	if err != nil {
		t.Fatalf("client construction failed: %v", err)
	}
	defer func() { _ = client.Close() }()
	ctx := context.Background()
	if _, err := client.Propagate(ctx, nil, "<a@b.example>", false); err == nil {
		t.Fatal("an empty notification was submitted")
	}
	oversized := make([]byte, 64)
	if _, err := client.Propagate(ctx, oversized, "<a@b.example>", false); err == nil {
		t.Fatal("an oversized notification was submitted")
	}
	if _, err := client.Propagate(ctx, []byte("x"), "", false); err == nil {
		t.Fatal("a notification without a forward path was submitted")
	}
}

// TestCommitRefusesUnprovenResults proves commit needs an accepted coordinate.
func TestCommitRefusesUnprovenResults(t *testing.T) {
	capability, err := LoadCapability(capabilityFixture(t, 0o600, 32))
	if err != nil {
		t.Fatal("capability load failed")
	}
	defer func() { _ = capability.Close() }()
	client, err := NewClient(
		"http://127.0.0.1:8080", capability, "tenant-a", "mta.example",
		time.Second, time.Second, 1<<20,
	)
	if err != nil {
		t.Fatal("client construction failed")
	}
	defer func() { _ = client.Close() }()
	if err := client.Commit(context.Background(), Result{}); err == nil {
		t.Fatal("an empty result was committed")
	}
	discarded := Result{state: &resultState{disposition: DispositionDiscard}}
	if err := client.Commit(context.Background(), discarded); err == nil {
		t.Fatal("a discarded result was committed")
	}
}

// TestForwardPathAndTokenGrammar freezes the accepted response value shapes.
func TestForwardPathAndTokenGrammar(t *testing.T) {
	valid := []string{"<a@b.example>", "<x>"}
	invalid := []string{"", "<>", "a@b.example", "<a b@example>", "<a<b>@x>"}
	for _, value := range valid {
		if !validForwardPath(value) {
			t.Fatalf("forward path %q refused", value)
		}
	}
	for _, value := range invalid {
		if validForwardPath(value) {
			t.Fatalf("forward path %q admitted", value)
		}
	}
	if !validCommitToken("abcdefghijklmnop") || validCommitToken("short") ||
		validCommitToken(strings.Repeat("a", 513)) ||
		validCommitToken("abcdefghijklmno.") {
		t.Fatal("commit token grammar drifted")
	}
}

// TestResultRedaction proves a result never renders its protected payload.
func TestResultRedaction(t *testing.T) {
	result := Result{state: &resultState{
		disposition:      DispositionAccept,
		nextHopRecipient: "<victim@example.com>",
		message:          []byte("signed bytes"),
	}}
	rendered := result.String() + result.GoString()
	if strings.Contains(rendered, "victim") || strings.Contains(rendered, "signed") {
		t.Fatalf("result leaked payload: %q", rendered)
	}
	if _, err := result.MarshalJSON(); err == nil {
		t.Fatal("result serialization was permitted")
	}
	result.Clear()
	if result.NextHopRecipient() != "" || len(result.Message()) != 0 {
		t.Fatal("the protected payload survived clearing")
	}
}
