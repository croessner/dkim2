package testclient

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
)

const (
	capabilityHeader        = "X-DKIM2-Capability"
	dsnSignCapabilityHeader = "X-DKIM2-DSN-Sign-Capability"
	// dsnPropagateCapabilityHeader is the sole credential field of the
	// propagation and propagation-commit routes.
	dsnPropagateCapabilityHeader = "X-DKIM2-DSN-Propagate-Capability"
)
const capabilityRedacted = "dkim2ctl_protected_capability"

// Capability owns one exact local process capability until Close.
type Capability struct {
	mu        sync.Mutex
	value     [32]byte
	operation Operation
	header    string
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
	return &Capability{value: value, operation: OperationProcess, header: capabilityHeader}, nil
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
	if hasAnyCapabilityHeader(request.Header) {
		return NewExitError(ExitCapability)
	}
	encoded := base64.RawURLEncoding.EncodeToString(c.value[:])
	request.Header.Add(c.header, encoded)
	return nil
}

// LoadCapabilityForOperation binds protected bytes to exactly one generated route.
func LoadCapabilityForOperation(path string, operation Operation) (*Capability, error) {
	if operation != OperationProcess && operation != OperationSign &&
		operation != OperationRevise && operation != OperationDSNSign &&
		operation != OperationDSNPropagate {
		return nil, NewExitError(ExitCapability)
	}
	capability, err := LoadCapability(path)
	if err != nil {
		return nil, err
	}
	capability.mu.Lock()
	capability.operation = operation
	capability.header = capabilityHeaderForOperation(operation)
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
	if c.closed || hasAnyCapabilityHeader(request.Header) {
		return NewExitError(ExitCapability)
	}
	switch mutation {
	case mutationMissingCapability:
		return nil
	case mutationEmptyCapability:
		request.Header.Add(c.header, "")
	case mutationMismatchingCapability:
		mismatch := c.value
		mismatch[0] ^= 1
		request.Header.Add(c.header, base64.RawURLEncoding.EncodeToString(mismatch[:]))
		for index := range mismatch {
			mismatch[index] = 0
		}
	case mutationDuplicateCapability:
		encoded := base64.RawURLEncoding.EncodeToString(c.value[:])
		request.Header.Add(c.header, encoded)
		request.Header.Add(c.header, encoded)
	default:
		request.Header.Add(c.header, base64.RawURLEncoding.EncodeToString(c.value[:]))
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
		!exactHeader(request.Header, headerContentType, mediaTypeJSON) {
		return false
	}
	if !slices.Contains(operationRoutePaths(operation), request.URL.EscapedPath()) {
		return false
	}
	_, err := ParseServerURL(schemeHTTP + "://" + request.URL.Host)
	return err == nil && request.URL.Scheme == schemeHTTP
}

// operationRoutePaths returns every route one loaded credential may address.
// The propagation credential covers both propagation routes because the
// contract binds them to the same security scheme; every other credential
// covers exactly one route.
func operationRoutePaths(operation Operation) []string {
	switch operation {
	case OperationProcess:
		return []string{processPath}
	case OperationSign:
		return []string{signPath}
	case OperationRevise:
		return []string{revisePath}
	case OperationDSNSign:
		return []string{dsnSignPath}
	case OperationDSNPropagate, OperationDSNPropagateCommit:
		return []string{dsnPropagatePath, dsnCommitPath}
	default:
		return nil
	}
}

// capabilityHeaderForOperation returns the exact isolated credential header.
func capabilityHeaderForOperation(operation Operation) string {
	switch operation {
	case OperationDSNSign:
		return dsnSignCapabilityHeader
	case OperationDSNPropagate, OperationDSNPropagateCommit:
		return dsnPropagateCapabilityHeader
	default:
		return capabilityHeader
	}
}

// hasAnyCapabilityHeader detects every operation capability field.
func hasAnyCapabilityHeader(header http.Header) bool {
	return hasHeader(header, capabilityHeader) || hasHeader(header, dsnSignCapabilityHeader) ||
		hasHeader(header, dsnPropagateCapabilityHeader)
}

// hasHeader detects an existing field independent of canonical map spelling.
func hasHeader(header http.Header, name string) bool {
	for headerName := range header {
		if strings.EqualFold(headerName, name) {
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
