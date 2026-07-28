package testclient

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

const capabilityHeader = "X-DKIM2-Capability"
const capabilityRedacted = "dkim2ctl_protected_capability"

// Capability owns one exact local process capability until Close.
type Capability struct {
	mu        sync.Mutex
	value     [32]byte
	operation Operation
	closed    bool
}

// newCapability validates and takes ownership of one exact opaque value.
func newCapability(value [32]byte) (*Capability, error) {
	var nonzero byte
	for _, current := range value {
		nonzero |= current
	}
	if nonzero == 0 {
		return nil, NewExitError(ExitCapability)
	}
	return &Capability{value: value, operation: OperationProcess}, nil
}

// EditRequest attaches the capability to exactly one otherwise-uncredentialed request.
func (c *Capability) EditRequest(_ context.Context, request *http.Request) error {
	if c == nil || !validGeneratedOperationRequest(request, c.operation) {
		return NewExitError(ExitInternal)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return NewExitError(ExitCapability)
	}
	if hasCapabilityHeader(request.Header) {
		return NewExitError(ExitCapability)
	}
	encoded := base64.RawURLEncoding.EncodeToString(c.value[:])
	request.Header.Add(capabilityHeader, encoded)
	return nil
}

// LoadCapabilityForOperation binds protected bytes to exactly one generated route.
func LoadCapabilityForOperation(path string, operation Operation) (*Capability, error) {
	if operation != OperationProcess && operation != OperationSign &&
		operation != OperationRevise {
		return nil, NewExitError(ExitCapability)
	}
	capability, err := LoadCapability(path)
	if err != nil {
		return nil, err
	}
	capability.mu.Lock()
	capability.operation = operation
	capability.mu.Unlock()
	return capability, nil
}

// capabilitiesAreDistinct compares protected values without exposing diagnostics.
func capabilitiesAreDistinct(capabilities ...*Capability) bool {
	values := make([][32]byte, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability == nil {
			continue
		}
		capability.mu.Lock()
		if capability.closed {
			capability.mu.Unlock()
			return false
		}
		values = append(values, capability.value)
		capability.mu.Unlock()
	}
	defer func() {
		for index := range values {
			values[index] = [32]byte{}
		}
	}()
	for left := range values {
		for right := left + 1; right < len(values); right++ {
			if subtle.ConstantTimeCompare(values[left][:], values[right][:]) == 1 {
				return false
			}
		}
	}
	return true
}

// editNegativeRequest applies one closed capability mutation without exposing bytes.
func (c *Capability) editNegativeRequest(request *http.Request, mutation string) error {
	if c == nil || request == nil || request.Header == nil {
		return NewExitError(ExitInternal)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || hasCapabilityHeader(request.Header) {
		return NewExitError(ExitCapability)
	}
	switch mutation {
	case mutationMissingCapability:
		return nil
	case mutationEmptyCapability:
		request.Header.Add(capabilityHeader, "")
	case mutationMismatchingCapability:
		mismatch := c.value
		mismatch[0] ^= 1
		request.Header.Add(capabilityHeader, base64.RawURLEncoding.EncodeToString(mismatch[:]))
		for index := range mismatch {
			mismatch[index] = 0
		}
	case mutationDuplicateCapability:
		encoded := base64.RawURLEncoding.EncodeToString(c.value[:])
		request.Header.Add(capabilityHeader, encoded)
		request.Header.Add(capabilityHeader, encoded)
	default:
		request.Header.Add(capabilityHeader, base64.RawURLEncoding.EncodeToString(c.value[:]))
	}
	return nil
}

// validGeneratedOperationRequest confines editing to one generated operation route.
func validGeneratedOperationRequest(request *http.Request, operation Operation) bool {
	if request == nil || request.URL == nil || request.Header == nil ||
		request.Method != http.MethodPost ||
		request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.RawPath != "" ||
		request.URL.Opaque != "" || request.URL.ForceQuery || request.URL.User != nil ||
		request.Host != request.URL.Host ||
		!exactHeader(request.Header, "Content-Type", mediaTypeJSON) {
		return false
	}
	expectedPath := ""
	switch operation {
	case OperationProcess:
		expectedPath = processPath
	case OperationSign:
		expectedPath = signPath
	case OperationRevise:
		expectedPath = revisePath
	default:
		return false
	}
	if request.URL.EscapedPath() != expectedPath {
		return false
	}
	_, err := ParseServerURL(schemeHTTP + "://" + request.URL.Host)
	return err == nil && request.URL.Scheme == schemeHTTP
}

// hasCapabilityHeader detects an existing capability field independent of
// canonical map spelling.
func hasCapabilityHeader(header http.Header) bool {
	for name := range header {
		if strings.EqualFold(name, capabilityHeader) {
			return true
		}
	}
	return false
}

// Close zeroes the owned array and rejects later request editing.
func (c *Capability) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	for index := range c.value {
		c.value[index] = 0
	}
	c.closed = true
	return nil
}

// String returns a content-free diagnostic representation.
func (c *Capability) String() string {
	return capabilityRedacted
}

// GoString returns a content-free Go-syntax diagnostic representation.
func (c *Capability) GoString() string {
	return capabilityRedacted
}

// Format makes every fmt verb content-free.
func (c *Capability) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(capabilityRedacted))
}
