//go:build linux || darwin

package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/testsupport"
)

const (
	capabilityPrivacyMarker     = "private-capability-marker"
	expectedCapabilityFileBytes = 32
)

// capabilityFixture owns one sealed direct-child test generation.
type capabilityFixture struct {
	directory string
	path      string
	value     []byte
}

// newCapabilityFixture creates one valid protected direct child.
func newCapabilityFixture(t *testing.T) capabilityFixture {
	t.Helper()
	base := testsupport.TrustedTempDirectory(t)
	directory := filepath.Join(base, "generation")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if capabilityBytes != expectedCapabilityFileBytes {
		t.Fatalf("capability byte bound = %d, want %d", capabilityBytes, expectedCapabilityFileBytes)
	}
	value := bytes.Repeat([]byte{0xa5}, expectedCapabilityFileBytes)
	path := filepath.Join(directory, "capability")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, protectedDirectoryMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	return capabilityFixture{directory: directory, path: path, value: value}
}

// mutateCapabilityFixture temporarily unseals one test generation.
func mutateCapabilityFixture(t *testing.T, fixture capabilityFixture, mutate func()) {
	t.Helper()
	if err := os.Chmod(fixture.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	mutate()
	if err := os.Chmod(fixture.directory, protectedDirectoryMode); err != nil {
		t.Fatal(err)
	}
}

// TestLoadCapabilityOwnsExactValueAndCloseZeroizes proves the successful lifecycle.
func TestLoadCapabilityOwnsExactValueAndCloseZeroizes(t *testing.T) {
	fixture := newCapabilityFixture(t)
	capability, err := LoadCapability(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := capability.bindRequestTarget("http://127.0.0.1:8080", "/v1/process"); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8080/v1/process",
		bytes.NewReader([]byte("{}")),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := editFixedRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := capability.EditRequest(t.Context(), request); err != nil {
		t.Fatal("valid generated request was rejected")
	}
	if len(request.Header.Values(capabilityHeader)) != 1 {
		t.Fatal("capability was not attached exactly once")
	}
	subjects := []any{
		capability,
		*capability,
		any(capability),
		capability.state,
		*capability.state,
		capability.state.guard,
		*capability.state.guard,
		struct{ Value any }{Value: capability},
		struct{ Value Capability }{Value: *capability},
	}
	for _, subject := range subjects {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			formatted := fmt.Sprintf(format, subject)
			if strings.Contains(formatted, capabilityPrivacyMarker) ||
				strings.Contains(formatted, string(fixture.value)) ||
				strings.Contains(formatted, "0xa5") ||
				strings.Contains(formatted, "127.0.0.1:8080") {
				t.Fatal("capability formatting exposed protected content")
			}
		}
		if output, marshalErr := json.Marshal(subject); marshalErr == nil ||
			strings.Contains(string(output), capabilityPrivacyMarker) ||
			strings.Contains(string(output), "165") ||
			strings.Contains(string(output), "127.0.0.1:8080") {
			t.Fatal("capability serialization did not fail closed")
		}
		if marshaler, ok := subject.(interface{ MarshalText() ([]byte, error) }); ok {
			if output, marshalErr := marshaler.MarshalText(); marshalErr == nil ||
				strings.Contains(string(output), capabilityPrivacyMarker) ||
				strings.Contains(string(output), "165") ||
				strings.Contains(string(output), "127.0.0.1:8080") {
				t.Fatal("capability text serialization did not fail closed")
			}
		}
	}
	if err := capability.Close(); err != nil {
		t.Fatal(err)
	}
	guard := capability.guard()
	guard.mu.Lock()
	closed := guard.closed
	cleared := bytes.Equal(guard.value[:], make([]byte, capabilityBytes))
	guard.mu.Unlock()
	if !closed || !cleared {
		t.Fatal("Close did not zeroize the retained capability")
	}
	if err := capability.EditRequest(t.Context(), request); !errors.Is(err, &Error{}) {
		t.Fatal("closed capability remained usable")
	}
	if err := capability.Close(); err != nil {
		t.Fatal("second Close was not idempotent")
	}
}

// TestCapabilityRejectsUnboundOrDriftingGeneratedRequests freezes credential scope.
func TestCapabilityRejectsUnboundOrDriftingGeneratedRequests(t *testing.T) {
	var value [expectedCapabilityFileBytes]byte
	value[0] = 1
	newRequest := func(t *testing.T, target string) *http.Request {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader([]byte("{}")))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		if err := editFixedRequest(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		return request
	}

	unbound, err := newCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := unbound.EditRequest(t.Context(), newRequest(t, "http://127.0.0.1:8080/v1/process")); !errors.Is(err, &Error{}) {
		t.Fatal("unbound capability credentialed a request")
	}
	if err := unbound.bindRequestTarget("http://127.0.0.1:8080", "/healthz"); !errors.Is(err, &Error{}) {
		t.Fatal("non-operation route was bound")
	}
	for _, endpoint := range []string{
		"http://example.test:8080",
		"http://127.0.0.1",
		"http://127.0.0.1:08080",
		"http://127.0.0.1:8080/",
		"http://127.0.0.1:8080?",
		"http://127.0.0.1:8080#",
		"http://127.0.0.1:8080/%23",
		"http://127.0.0.1:8080?query",
		"http://user@127.0.0.1:8080",
		"http://[::ffff:127.0.0.1]:8080",
	} {
		if err := unbound.bindRequestTarget(endpoint, "/v1/process"); !errors.Is(err, &Error{}) {
			t.Fatalf("noncanonical capability endpoint %q was bound", endpoint)
		}
	}
	if err := unbound.bindRequestTarget("http://127.0.0.1:8080", "/v1/process"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: testCaseWrongRoute, mutate: func(request *http.Request) { request.URL.Path = routeSign }},
		{name: "wrong authority", mutate: func(request *http.Request) { request.URL.Host = "127.0.0.1:8081" }},
		{name: "authority override", mutate: func(request *http.Request) { request.Host = "127.0.0.1:8081" }},
		{name: testCaseWrongMethod, mutate: func(request *http.Request) { request.Method = http.MethodGet }},
		{name: testCaseQuery, mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "empty body", mutate: func(request *http.Request) {
			request.Body = io.NopCloser(bytes.NewReader(nil))
			request.ContentLength = 0
		}},
		{name: "extra header", mutate: func(request *http.Request) { request.Header.Set("X-Extra", "x") }},
		{name: "case variant capability", mutate: func(request *http.Request) {
			request.Header["x-dkim2-capability"] = []string{"existing"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, "http://127.0.0.1:8080/v1/process")
			test.mutate(request)
			if err := unbound.EditRequest(t.Context(), request); !errors.Is(err, &Error{}) {
				t.Fatal("credential attached outside exact generated request shape")
			}
			for name := range request.Header {
				if strings.EqualFold(name, capabilityHeader) {
					if test.name != "case variant capability" {
						t.Fatal("failed request gained a capability header")
					}
				}
			}
		})
	}
}

// TestLoadCapabilityRejectsDescriptorAndContentViolations freezes file policy.
func TestLoadCapabilityRejectsDescriptorAndContentViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, capabilityFixture)
	}{
		{
			name: "short",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				if err := os.WriteFile(fixture.path, fixture.value[:capabilityBytes-1], 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "long",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				if err := os.WriteFile(fixture.path, append(fixture.value, 0), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "zero",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				if err := os.WriteFile(fixture.path, make([]byte, capabilityBytes), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe mode",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				if err := os.Chmod(fixture.path, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				if err := os.Link(fixture.path, filepath.Join(fixture.directory, "alias")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				target := fixture.path + ".target"
				if err := os.Rename(fixture.path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, fixture.path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				if err := os.Remove(fixture.path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(fixture.path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "fifo",
			mutate: func(t *testing.T, fixture capabilityFixture) {
				if err := os.Remove(fixture.path); err != nil {
					t.Fatal(err)
				}
				if err := mkfifoCapabilityFixture(fixture.path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCapabilityFixture(t)
			mutateCapabilityFixture(t, fixture, func() { test.mutate(t, fixture) })
			capability, err := LoadCapability(fixture.path)
			if capability != nil || !errors.Is(err, &Error{}) {
				if capability != nil {
					_ = capability.Close()
				}
				t.Fatalf("LoadCapability() accepted %s fixture", test.name)
			}
		})
	}
}

// TestLoadCapabilityRejectsUntrustedAncestryAndParentAliases freezes traversal.
func TestLoadCapabilityRejectsUntrustedAncestryAndParentAliases(t *testing.T) {
	t.Run("unsealed direct parent", func(t *testing.T) {
		fixture := newCapabilityFixture(t)
		if err := os.Chmod(fixture.directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if capability, err := LoadCapability(fixture.path); capability != nil || !errors.Is(err, &Error{}) {
			t.Fatal("unsealed direct parent was accepted")
		}
	})
	t.Run("writable ancestor", func(t *testing.T) {
		fixture := newCapabilityFixture(t)
		ancestor := filepath.Dir(fixture.directory)
		original, err := os.Stat(ancestor)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0o770); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ancestor, original.Mode().Perm()) })
		if capability, err := LoadCapability(fixture.path); capability != nil || !errors.Is(err, &Error{}) {
			t.Fatal("writable ancestor was accepted")
		}
	})
	t.Run("symlink parent", func(t *testing.T) {
		fixture := newCapabilityFixture(t)
		alias := fixture.directory + ".alias"
		if err := os.Symlink(fixture.directory, alias); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(alias) })
		if capability, err := LoadCapability(
			filepath.Join(alias, filepath.Base(fixture.path)),
		); capability != nil || !errors.Is(err, &Error{}) {
			t.Fatal("symlinked parent was accepted")
		}
	})
	t.Run("wrong owner authority", func(t *testing.T) {
		fixture := newCapabilityFixture(t)
		capability, err := loadCapabilityObservedWithUID(
			fixture.path, nil, uint32(os.Geteuid()+1),
		)
		if capability != nil || !errors.Is(err, &Error{}) {
			t.Fatal("wrong effective UID authority was accepted")
		}
	})
}

// TestLoadCapabilityRejectsPreopenAndPostreadRaces proves retained snapshots.
func TestLoadCapabilityRejectsPreopenAndPostreadRaces(t *testing.T) {
	t.Run("final child replacement", func(t *testing.T) {
		fixture := newCapabilityFixture(t)
		observed := false
		capability, err := loadCapabilityObserved(fixture.path, func(event capabilityLoadEvent) {
			if event != capabilityBeforeFinalOpen || observed {
				return
			}
			observed = true
			mutateCapabilityFixture(t, fixture, func() {
				if renameErr := os.Rename(fixture.path, fixture.path+".old"); renameErr != nil {
					t.Fatal(renameErr)
				}
				if writeErr := os.WriteFile(
					fixture.path, bytes.Repeat([]byte{0x5a}, capabilityBytes), 0o600,
				); writeErr != nil {
					t.Fatal(writeErr)
				}
			})
		})
		if !observed || capability != nil || !errors.Is(err, &Error{}) {
			t.Fatal("pre-open child replacement was accepted")
		}
	})
	t.Run("in-place child mutation", func(t *testing.T) {
		fixture := newCapabilityFixture(t)
		observed := false
		capability, err := loadCapabilityObserved(fixture.path, func(event capabilityLoadEvent) {
			if event != capabilityAfterRead || observed {
				return
			}
			observed = true
			if writeErr := os.WriteFile(
				fixture.path, bytes.Repeat([]byte{0x5a}, capabilityBytes), 0o600,
			); writeErr != nil {
				t.Fatal(writeErr)
			}
		})
		if !observed || capability != nil || !errors.Is(err, &Error{}) {
			t.Fatal("post-read child mutation was accepted")
		}
	})
	t.Run("parent generation mutation", func(t *testing.T) {
		fixture := newCapabilityFixture(t)
		observed := false
		capability, err := loadCapabilityObserved(fixture.path, func(event capabilityLoadEvent) {
			if event != capabilityAfterRead || observed {
				return
			}
			observed = true
			mutateCapabilityFixture(t, fixture, func() {
				if writeErr := os.WriteFile(
					filepath.Join(fixture.directory, "other"), []byte("x"), 0o600,
				); writeErr != nil {
					t.Fatal(writeErr)
				}
			})
		})
		if !observed || capability != nil || !errors.Is(err, &Error{}) {
			t.Fatal("post-read parent mutation was accepted")
		}
	})
}

// TestLoadCapabilityErrorsRemainContentFree proves hostile paths never echo.
func TestLoadCapabilityErrorsRemainContentFree(t *testing.T) {
	for _, path := range []string{
		capabilityPrivacyMarker,
		"/tmp/" + capabilityPrivacyMarker + "/missing",
		"/tmp/../tmp/" + capabilityPrivacyMarker,
	} {
		capability, err := LoadCapability(path)
		if capability != nil || !errors.Is(err, &Error{}) ||
			strings.Contains(err.Error(), capabilityPrivacyMarker) {
			t.Fatal("capability failure exposed input-derived content")
		}
	}
}
