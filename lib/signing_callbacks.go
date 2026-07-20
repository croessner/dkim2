package dkim2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/signing"
)

// PrivateKeySignRequest carries only one closed algorithm and native SHA-256 digest.
type PrivateKeySignRequest struct {
	algorithm Algorithm
	digest    [sha256.Size]byte
	valid     bool
}

// Algorithm returns the requested baseline signing algorithm.
func (r PrivateKeySignRequest) Algorithm() Algorithm {
	if !r.valid {
		return AlgorithmUnknown
	}
	return r.algorithm
}

// Digest returns the native SHA-256 digest by value.
func (r PrivateKeySignRequest) Digest() [sha256.Size]byte { return r.digest }

// Valid reports whether the request was created by the signing facade.
func (r PrivateKeySignRequest) Valid() bool {
	return r.valid && (r.algorithm == AlgorithmRSASHA256 || r.algorithm == AlgorithmEd25519SHA256)
}

// String returns a constant secret-safe request summary.
func (r PrivateKeySignRequest) String() string { return "dkim2.PrivateKeySignRequest{redacted}" }

// GoString returns the constant secret-safe request Go representation.
func (r PrivateKeySignRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r PrivateKeySignRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// PrivateKeySignResult is the closed immutable result of one digest-signing callback.
type PrivateKeySignResult struct {
	signature []byte
	signed    bool
}

// NewPrivateKeySignResult constructs a detached successful callback result.
func NewPrivateKeySignResult(signature []byte) PrivateKeySignResult {
	return PrivateKeySignResult{signature: bytes.Clone(signature), signed: true}
}

// IsZero reports whether no declared callback result is present.
func (r PrivateKeySignResult) IsZero() bool { return !r.signed && r.signature == nil }

// String returns a constant secret-safe result summary.
func (r PrivateKeySignResult) String() string { return "dkim2.PrivateKeySignResult{redacted}" }

// GoString returns the constant secret-safe result Go representation.
func (r PrivateKeySignResult) GoString() string { return r.String() }

// Format routes every result formatting form through the redacted summary.
func (r PrivateKeySignResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// PrivateKeySigner signs one native SHA-256 digest through an opaque handle.
type PrivateKeySigner interface {
	SignDigest(context.Context, PrivateKeyHandle, PrivateKeySignRequest) (PrivateKeySignResult, error)
}

type privateKeySignerBridge struct{ signer PrivateKeySigner }

// SignDigest maps the internal minimal callback into the public closed bridge.
func (b privateKeySignerBridge) SignDigest(ctx context.Context, handle signing.PrivateKeyHandle, request signing.PrivateKeySignRequest) (signing.PrivateKeySignResult, error) {
	if !handle.Valid() || !request.Valid() || nilSigningCallback(b.signer) {
		return signing.PrivateKeySignResult{}, provider.NewFailure(provider.FailureContract)
	}
	var algorithm Algorithm
	switch request.Algorithm() {
	case signing.AlgorithmRSASHA256:
		algorithm = AlgorithmRSASHA256
	case signing.AlgorithmEd25519SHA256:
		algorithm = AlgorithmEd25519SHA256
	default:
		return signing.PrivateKeySignResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.signer.SignDigest(ctx, PrivateKeyHandle{value: handle}, PrivateKeySignRequest{
		algorithm: algorithm, digest: request.Digest(), valid: algorithm != AlgorithmUnknown,
	})
	if err != nil {
		if !result.IsZero() {
			return signing.PrivateKeySignResult{}, provider.NewFailure(provider.FailureContract)
		}
		return signing.PrivateKeySignResult{}, bridgeProviderError(ctx, err)
	}
	if !result.signed {
		return signing.PrivateKeySignResult{}, nil
	}
	return signing.NewPrivateKeySignResult(result.signature), nil
}

// bridgeProviderError maps public classified errors without retaining their causes.
func bridgeProviderError(ctx context.Context, err error) error {
	if nilSigningCallback(err) {
		return provider.NewFailure(provider.FailureContract)
	}
	if ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		return ctx.Err()
	}
	switch ProviderErrorClassOf(err) {
	case ProviderErrorClassTemporary:
		return provider.NewFailure(provider.FailureTemporary)
	case ProviderErrorClassPermanent:
		return provider.NewFailure(provider.FailurePermanent)
	default:
		return provider.NewFailure(provider.FailureContract)
	}
}

// nilSigningCallback reports nil and typed-nil injected callback services.
func nilSigningCallback(value any) bool {
	return niliface.IsNil(value)
}
