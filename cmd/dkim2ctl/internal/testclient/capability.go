package testclient

import (
	"context"
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
	mu     sync.Mutex
	value  [32]byte
	closed bool
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
	return &Capability{value: value}, nil
}

// EditRequest attaches the capability to exactly one otherwise-uncredentialed request.
func (c *Capability) EditRequest(_ context.Context, request *http.Request) error {
	if c == nil || !validGeneratedProcessRequest(request) {
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

// validGeneratedProcessRequest confines capability editing to the generated
// typed process request shape over a canonical loopback authority.
func validGeneratedProcessRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.Header == nil ||
		request.Method != http.MethodPost || request.URL.EscapedPath() != processPath ||
		request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.RawPath != "" ||
		request.URL.Opaque != "" || request.URL.ForceQuery || request.URL.User != nil ||
		request.Host != request.URL.Host ||
		!exactHeader(request.Header, "Content-Type", mediaTypeJSON) {
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
