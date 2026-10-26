package domainadmin

import (
	"context"
	"encoding/base32"
	"io"
	"strings"

	"github.com/croessner/dkim2/provider"
)

const entropyBytes128 = 16

// entropyReader is the minimum injectable cryptographic entropy seam.
type entropyReader interface {
	Read([]byte) (int, error)
}

// contextEntropyReader fails reads after cancellation without fallback entropy.
type contextEntropyReader struct {
	ctx    context.Context
	source entropyReader
}

// Read obtains entropy only while the owning operation remains live.
func (r contextEntropyReader) Read(value []byte) (int, error) {
	if r.ctx == nil || r.source == nil || r.ctx.Err() != nil {
		return 0, context.Canceled
	}
	if len(value) == 0 {
		return 0, nil
	}
	count, err := r.source.Read(value)
	if cancellation := r.ctx.Err(); cancellation != nil {
		return 0, cancellation
	}
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, io.ErrNoProgress
	}
	if count < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if count > len(value) {
		return 0, io.ErrShortBuffer
	}
	return count, nil
}

// randomToken reads and encodes one canonical lower-case 128-bit token.
func randomToken(ctx context.Context, entropy entropyReader) (string, error) {
	bytes := make([]byte, entropyBytes128)
	reader := contextEntropyReader{ctx: ctx, source: entropy}
	for offset := 0; offset < len(bytes); {
		count, err := reader.Read(bytes[offset:])
		if count < 0 || count > len(bytes)-offset || err != nil || count == 0 {
			clear(bytes)
			return "", newError(CodeUnavailable)
		}
		offset += count
	}
	if ctx.Err() != nil {
		clear(bytes)
		return "", newError(CodeUnavailable)
	}
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes))
	clear(bytes)
	if len(encoded) != 26 {
		return "", newError(CodeUnavailable)
	}
	return encoded, nil
}

// selectorPrefix returns one algorithm-separated DNS-label-safe namespace.
func selectorPrefix(algorithm provider.Algorithm) (string, error) {
	switch algorithm {
	case provider.AlgorithmEd25519SHA256:
		return "d2e-", nil
	case provider.AlgorithmRSASHA256:
		return "d2r-", nil
	default:
		return "", newError(CodeInvalidIntent)
	}
}
