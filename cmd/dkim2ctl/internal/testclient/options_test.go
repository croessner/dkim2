package testclient

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestParseServerURLFreezesLoopbackAuthority validates the literal URL allowlist.
func TestParseServerURLFreezesLoopbackAuthority(t *testing.T) {
	t.Parallel()
	for _, accepted := range []string{"http://127.0.0.1:1", "http://127.0.0.1:65535", "http://[::1]:8080"} {
		if _, err := ParseServerURL(accepted); err != nil {
			t.Fatalf("rejected accepted URL")
		}
	}
	for _, rejected := range []string{
		"", "https://127.0.0.1:8080", "http://localhost:8080", "http://127.0.0.2:8080",
		"http://0.0.0.0:8080", "http://127.0.0.1:08080", "http://127.0.0.1",
		"http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:8080/",
		"http://user@127.0.0.1:8080", "http://127.0.0.1:8080?q", "http://127.0.0.1:8080#f",
		"http://[::ffff:127.0.0.1]:8080", "http://[::1%25lo0]:8080",
	} {
		if _, err := ParseServerURL(rejected); ExitClassOf(err) != ExitUsage {
			t.Fatalf("accepted hostile URL shape")
		}
	}
}

// TestOptionsValidationFreezesLiteralBounds checks independently spelled flag contracts.
func TestOptionsValidationFreezesLiteralBounds(t *testing.T) {
	t.Parallel()
	valid := Options{
		ServerURL: "http://127.0.0.1:8080", Timeout: 100 * time.Millisecond,
		Output: outputJSONL,
	}
	if err := valid.Validate(false); err != nil {
		t.Fatal("valid options rejected")
	}
	for _, invalid := range []Options{
		{ServerURL: valid.ServerURL, Timeout: 99 * time.Millisecond, Output: outputJSONL},
		{ServerURL: valid.ServerURL, Timeout: 60001 * time.Millisecond, Output: outputJSONL},
		{ServerURL: valid.ServerURL, Timeout: time.Second, Output: "json"},
		{ServerURL: valid.ServerURL, Timeout: time.Second, Output: outputJSONL, CapabilityFile: "relative"},
	} {
		if ExitClassOf(invalid.Validate(false)) != ExitUsage {
			t.Fatal("invalid option set accepted")
		}
	}
	if ExitClassOf(valid.Validate(true)) != ExitUsage {
		t.Fatal("missing required capability accepted")
	}
}

// TestCapabilityLifecycleAndPrivacy proves collision rejection, editing, and redaction.
func TestCapabilityLifecycleAndPrivacy(t *testing.T) {
	t.Parallel()
	var bytes [32]byte
	copy(bytes[:], strings.Repeat("S", 32))
	capability, err := newCapability(bytes)
	if err != nil {
		t.Fatal("capability construction failed")
	}
	for _, formatted := range []string{
		fmt.Sprint(capability), fmt.Sprintf("%#v", capability), fmt.Sprintf("%x", capability),
	} {
		if strings.Contains(formatted, "SSSS") {
			t.Fatal("capability marker leaked")
		}
	}
	request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/process", nil)
	request.Header.Set(headerContentType, mediaTypeJSON)
	if err := capability.EditRequest(t.Context(), request); err != nil {
		t.Fatal("request editing failed")
	}
	if len(request.Header.Values("X-DKIM2-Capability")) != 1 {
		t.Fatal("request editor did not add exactly one field")
	}
	if err := capability.EditRequest(t.Context(), request); ExitClassOf(err) != ExitCapability {
		t.Fatal("request editor accepted collision")
	}
	if err := capability.Close(); err != nil {
		t.Fatal("capability close failed")
	}
	fresh, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/process", nil)
	fresh.Header.Set(headerContentType, mediaTypeJSON)
	if err := capability.EditRequest(t.Context(), fresh); ExitClassOf(err) != ExitCapability {
		t.Fatal("closed capability remained usable")
	}
}

// TestCapabilityMismatchAlwaysDiffersFromOwnedValue proves the negative editor
// cannot accidentally authenticate when the owned bytes match a former test
// constant.
func TestCapabilityMismatchAlwaysDiffersFromOwnedValue(t *testing.T) {
	t.Parallel()
	var value [32]byte
	for index := range value {
		value[index] = 0xa5
	}
	capability, err := newCapability(value)
	if err != nil {
		t.Fatal("capability construction failed")
	}
	defer func() { _ = capability.Close() }()
	request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/process", nil)
	if err := capability.editNegativeRequest(request, mutationMismatchingCapability); err != nil {
		t.Fatal("mismatch editing failed")
	}
	encoded := request.Header.Get(capabilityHeader)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != len(value) {
		t.Fatal("mismatch header is not one exact capability")
	}
	if string(decoded) == string(value[:]) {
		t.Fatal("mismatch mutation emitted the owned capability")
	}
}

// TestCapabilityEditorRejectsNoncanonicalExistingHeader proves collision
// detection is case-insensitive even for a directly forged Header map.
func TestCapabilityEditorRejectsNoncanonicalExistingHeader(t *testing.T) {
	t.Parallel()
	var value [32]byte
	value[0] = 1
	capability, _ := newCapability(value)
	defer func() { _ = capability.Close() }()
	request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/process", nil)
	request.Header.Set(headerContentType, mediaTypeJSON)
	request.Header["x-dkim2-capability"] = []string{"forged"}
	if err := capability.EditRequest(t.Context(), request); ExitClassOf(err) != ExitCapability {
		t.Fatal("noncanonical capability collision accepted")
	}
}

// TestCapabilityEditorIsConfinedToGeneratedProcessShape proves the exported
// generated-client editor cannot credential health, remote, or malformed
// requests.
func TestCapabilityEditorIsConfinedToGeneratedProcessShape(t *testing.T) {
	t.Parallel()
	var value [32]byte
	value[0] = 1
	capability, _ := newCapability(value)
	defer func() { _ = capability.Close() }()
	for _, request := range []*http.Request{
		mustRequest(t, http.MethodGet, "http://127.0.0.1:8080/healthz"),
		mustRequest(t, http.MethodPost, "http://example.test/v1/process"),
		{Method: http.MethodPost},
	} {
		if err := capability.EditRequest(t.Context(), request); ExitClassOf(err) != ExitInternal {
			t.Fatal("capability editor escaped generated process confinement")
		}
	}
}

// TestCapabilityEditorsAreConfinedToDistinctGeneratedRoutes proves separation.
func TestCapabilityEditorsAreConfinedToDistinctGeneratedRoutes(t *testing.T) {
	t.Parallel()
	var value [32]byte
	value[0] = 1
	sign, _ := newCapability(value)
	sign.operation = OperationSign
	defer func() { _ = sign.Close() }()
	signRequest := mustRequest(t, http.MethodPost, "http://127.0.0.1:8080/v1/sign")
	if err := sign.EditRequest(t.Context(), signRequest); err != nil {
		t.Fatal("sign capability rejected generated sign route")
	}
	processRequest := mustRequest(t, http.MethodPost, "http://127.0.0.1:8080/v1/process")
	if err := sign.EditRequest(
		t.Context(), processRequest,
	); ExitClassOf(err) != ExitInternal {
		t.Fatal("sign capability escaped onto process route")
	}
}

// mustRequest constructs one test request and fails without exposing its URL.
func mustRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal("construct request")
	}
	request.Header.Set(headerContentType, mediaTypeJSON)
	return request
}

// TestLoadCapabilityValidatesProtectedFile proves exact file shape and content.
func TestLoadCapabilityValidatesProtectedFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "capability")
	if err := os.WriteFile(path, []byte(strings.Repeat("C", 32)), 0o600); err != nil {
		t.Fatal("write protected fixture")
	}
	capability, err := LoadCapability(path)
	if err != nil {
		t.Fatal("valid protected capability rejected")
	}
	_ = capability.Close()

	for name, fixture := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"short": {[]byte("short"), 0o600},
		"zero":  {make([]byte, 32), 0o600},
		"mode":  {[]byte(strings.Repeat("C", 32)), 0o644},
	} {
		testPath := filepath.Join(directory, name)
		if err := os.WriteFile(testPath, fixture.data, fixture.mode); err != nil {
			t.Fatal("write hostile protected fixture")
		}
		if _, err := LoadCapability(testPath); ExitClassOf(err) != ExitCapability {
			t.Fatal("hostile protected file accepted")
		}
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal("create symlink fixture")
	}
	if _, err := LoadCapability(link); ExitClassOf(err) != ExitCapability {
		t.Fatal("symlink accepted")
	}
	hardlink := filepath.Join(directory, "hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal("create hardlink fixture")
	}
	if _, err := LoadCapability(path); ExitClassOf(err) != ExitCapability {
		t.Fatal("multiply linked capability accepted")
	}
	if _, err := LoadCapability(hardlink); ExitClassOf(err) != ExitCapability {
		t.Fatal("hardlink capability alias accepted")
	}
}

// TestOptionsRejectCapabilityPathAliases proves lexical separation preflight.
func TestOptionsRejectCapabilityPathAliases(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "capability")
	options := DefaultOptions()
	options.CapabilityFile = path
	options.SignCapabilityFile = path
	if ExitClassOf(options.validateRequirements(
		capabilityRequirements{process: true, sign: true},
	)) != ExitUsage {
		t.Fatal("identical capability paths accepted")
	}
}
