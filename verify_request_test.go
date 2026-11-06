package dkim2

import (
	"bytes"
	"testing"
)

// TestVerifyRequestClonesStorage proves request construction and accessors do not share mutable storage.
func TestVerifyRequestClonesStorage(t *testing.T) {
	raw := []byte("Subject: synthetic\r\n\r\nbody\r\n")
	reverse := []byte("<sender@example.test>")
	forward := [][]byte{[]byte("<one@example.test>"), []byte("<two@example.test>")}
	wantRaw := bytes.Clone(raw)
	wantReverse := bytes.Clone(reverse)
	wantForward := [][]byte{bytes.Clone(forward[0]), bytes.Clone(forward[1])}

	request := NewVerifyRequest(raw, reverse, forward)
	raw[0] = 'X'
	reverse[1] = 'X'
	forward[0][1] = 'X'
	forward[1] = []byte("changed")

	if got := request.RawMessage(); !bytes.Equal(got, wantRaw) {
		t.Fatal("RawMessage did not preserve immutable caller input")
	}
	if got := request.ReversePath(); !bytes.Equal(got, wantReverse) {
		t.Fatal("ReversePath did not preserve immutable caller input")
	}
	if got := request.ForwardPaths(); !equalByteSlices(got, wantForward) {
		t.Fatal("ForwardPaths did not preserve immutable caller input")
	}

	gotRaw := request.RawMessage()
	gotReverse := request.ReversePath()
	gotForward := request.ForwardPaths()
	gotRaw[0] = 'Y'
	gotReverse[1] = 'Y'
	gotForward[0][1] = 'Y'
	gotForward[1] = nil

	if got := request.RawMessage(); !bytes.Equal(got, wantRaw) {
		t.Fatal("RawMessage accessor exposed request-owned storage")
	}
	if got := request.ReversePath(); !bytes.Equal(got, wantReverse) {
		t.Fatal("ReversePath accessor exposed request-owned storage")
	}
	if got := request.ForwardPaths(); !equalByteSlices(got, wantForward) {
		t.Fatal("ForwardPaths accessor exposed request-owned storage")
	}
}

// TestVerifyRequestZeroValueIsSafe proves the zero request exposes no mutable phantom input.
func TestVerifyRequestZeroValueIsSafe(t *testing.T) {
	var request VerifyRequest
	if request.RawMessage() != nil {
		t.Fatal("zero request unexpectedly contains raw message bytes")
	}
	if request.ReversePath() != nil {
		t.Fatal("zero request unexpectedly contains reverse-path bytes")
	}
	if request.ForwardPaths() != nil {
		t.Fatal("zero request unexpectedly contains forward-path bytes")
	}
}

// equalByteSlices compares nested byte slices without normalizing their contents.
func equalByteSlices(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}
