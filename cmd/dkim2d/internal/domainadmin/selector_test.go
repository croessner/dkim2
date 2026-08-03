package domainadmin

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type boundedShortEntropy struct{ maximum int }

// Read returns bounded successful short reads.
func (r boundedShortEntropy) Read(value []byte) (int, error) {
	count := min(len(value), r.maximum)
	for index := range value[:count] {
		value[index] = 1
	}
	return count, nil
}

type errorAfterBytesEntropy struct{}

// Read returns all requested bytes together with a source failure.
func (errorAfterBytesEntropy) Read(value []byte) (int, error) {
	copy(value, bytes.Repeat([]byte{1}, len(value)))
	return len(value), errors.New("entropy failure")
}

type noProgressEntropy struct{}

// Read returns no bytes and no error.
func (noProgressEntropy) Read([]byte) (int, error) { return 0, nil }

type failingEntropy struct{}

// Read returns one immediate entropy failure.
func (failingEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy failure") }

type invalidCountEntropy int

// Read reports one impossible Reader count without touching memory.
func (r invalidCountEntropy) Read(value []byte) (int, error) {
	if r < 0 {
		return int(r), nil
	}
	return len(value) + int(r), nil
}

// TestRandomTokenHandlesShortReadsAndRejectsAmbiguousEntropy freezes entropy semantics.
func TestRandomTokenHandlesShortReadsAndRejectsAmbiguousEntropy(t *testing.T) {
	if token, err := randomToken(t.Context(), boundedShortEntropy{maximum: 3}); err != nil || len(token) != 26 {
		t.Fatal("bounded successful short reads rejected")
	}
	for _, source := range []entropyReader{errorAfterBytesEntropy{}, failingEntropy{}, invalidCountEntropy(-1), invalidCountEntropy(1)} {
		if token, err := randomToken(t.Context(), source); err == nil || token != "" {
			t.Fatal("ambiguous entropy source produced a token")
		}
	}
	done := make(chan bool, 1)
	go func() {
		token, err := randomToken(context.Background(), noProgressEntropy{})
		done <- err != nil && token == ""
	}()
	select {
	case rejected := <-done:
		if !rejected {
			t.Fatal("no-progress entropy source produced a token")
		}
	case <-time.After(time.Second):
		t.Fatal("no-progress entropy source did not terminate")
	}
}

// TestContextEntropyReaderPermitsZeroLengthReads preserves the io.Reader contract.
func TestContextEntropyReaderPermitsZeroLengthReads(t *testing.T) {
	reader := contextEntropyReader{ctx: t.Context(), source: noProgressEntropy{}}
	if count, err := reader.Read(nil); count != 0 || err != nil {
		t.Fatal("zero-length entropy read violated the reader contract")
	}
}

// TestRandomTokenRejectsCancellationWithoutEntropyFallback freezes cancellation.
func TestRandomTokenRejectsCancellationWithoutEntropyFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if token, err := randomToken(ctx, boundedShortEntropy{maximum: 16}); err == nil || token != "" {
		t.Fatal("cancelled entropy generation succeeded")
	}
}
