package dkim2

import (
	"bytes"
	"fmt"
	"io"
)

const verifyRequestRedactedText = "dkim2.VerifyRequest{redacted}"

// VerifyRequest contains immutable raw RFC 5322 bytes and independent current SMTP envelope evidence.
type VerifyRequest struct {
	state *verifyRequestState
}

type verifyRequestState struct {
	rawMessage   []byte
	reversePath  []byte
	forwardPaths [][]byte
}

// NewVerifyRequest constructs a request by cloning every caller-owned byte slice.
func NewVerifyRequest(rawMessage, reversePath []byte, forwardPaths [][]byte) VerifyRequest {
	return VerifyRequest{
		state: &verifyRequestState{
			rawMessage:   bytes.Clone(rawMessage),
			reversePath:  bytes.Clone(reversePath),
			forwardPaths: cloneByteSlices(forwardPaths),
		},
	}
}

// RawMessage returns an independent copy of the authoritative RFC 5322 bytes.
func (r VerifyRequest) RawMessage() []byte {
	if r.state == nil {
		return nil
	}
	return bytes.Clone(r.state.rawMessage)
}

// ReversePath returns an independent copy of the current bracketed SMTP reverse-path.
func (r VerifyRequest) ReversePath() []byte {
	if r.state == nil {
		return nil
	}
	return bytes.Clone(r.state.reversePath)
}

// ForwardPaths returns independent copies of the current bracketed SMTP forward-paths.
func (r VerifyRequest) ForwardPaths() [][]byte {
	if r.state == nil {
		return nil
	}
	return cloneByteSlices(r.state.forwardPaths)
}

// values returns immutable request-owned slices to the package verifier.
func (r VerifyRequest) values() ([]byte, []byte, [][]byte) {
	if r.state == nil {
		return nil, nil, nil
	}
	return r.state.rawMessage, r.state.reversePath, r.state.forwardPaths
}

// String returns a constant representation without message or envelope bytes.
func (VerifyRequest) String() string { return verifyRequestRedactedText }

// GoString returns a constant representation without message or envelope bytes.
func (VerifyRequest) GoString() string { return verifyRequestRedactedText }

// Format prevents formatting from traversing message or envelope bytes.
func (VerifyRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, verifyRequestRedactedText)
}

// MarshalJSON rejects serialization outside the explicitly generated REST request.
func (VerifyRequest) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of message or envelope bytes.
func (VerifyRequest) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// cloneByteSlices deep-clones nested byte slices while preserving nil elements and order.
func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}

	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = bytes.Clone(value)
	}
	return cloned
}
