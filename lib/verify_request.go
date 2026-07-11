package dkim2

import "bytes"

// VerifyRequest contains immutable raw RFC 5322 bytes and independent current SMTP envelope evidence.
type VerifyRequest struct {
	rawMessage   []byte
	reversePath  []byte
	forwardPaths [][]byte
}

// NewVerifyRequest constructs a request by cloning every caller-owned byte slice.
func NewVerifyRequest(rawMessage, reversePath []byte, forwardPaths [][]byte) VerifyRequest {
	return VerifyRequest{
		rawMessage:   bytes.Clone(rawMessage),
		reversePath:  bytes.Clone(reversePath),
		forwardPaths: cloneByteSlices(forwardPaths),
	}
}

// RawMessage returns an independent copy of the authoritative RFC 5322 bytes.
func (r VerifyRequest) RawMessage() []byte {
	return bytes.Clone(r.rawMessage)
}

// ReversePath returns an independent copy of the current bracketed SMTP reverse-path.
func (r VerifyRequest) ReversePath() []byte {
	return bytes.Clone(r.reversePath)
}

// ForwardPaths returns independent copies of the current bracketed SMTP forward-paths.
func (r VerifyRequest) ForwardPaths() [][]byte {
	return cloneByteSlices(r.forwardPaths)
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
