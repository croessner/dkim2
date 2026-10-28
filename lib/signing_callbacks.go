package dkim2

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/signing"
)

// PrivateKeySignRequest carries only one closed algorithm and the message
// representative of the Section 12.8 signature input that algorithm signs:
// the 32-byte SHA-256 digest for rsa-sha256 and ed25519-sha256, and the
// complete Section 12.8 input bytes for mldsa44, which is pure ML-DSA
// (Draft-08 Section 3.4: the field values are not hashed first).
type PrivateKeySignRequest struct {
	algorithm      Algorithm
	representative []byte
	valid          bool
}

// Algorithm returns the requested signing algorithm.
func (r PrivateKeySignRequest) Algorithm() Algorithm {
	if !r.valid {
		return AlgorithmUnknown
	}
	return r.algorithm
}

// MessageRepresentative returns a copy of the exact bytes the algorithm's
// signing primitive consumes. A signer passes it unchanged to
// rsa.SignPKCS1v15 with crypto.SHA256, to ed25519.Sign, or, for mldsa44, to
// the hedged crypto/mldsa PrivateKey.Sign with MLDSA44SignerOptions (context
// string "DKIM2").
func (r PrivateKeySignRequest) MessageRepresentative() []byte { return bytes.Clone(r.representative) }

// Digest returns a copy of the 32-byte SHA-256 signature-input digest for
// rsa-sha256 and ed25519-sha256. It returns nil for mldsa44, which signs the
// complete input; use MessageRepresentative for every algorithm.
//
// Deprecated: use MessageRepresentative, which covers every algorithm.
func (r PrivateKeySignRequest) Digest() []byte {
	if r.algorithm == AlgorithmMLDSA44 {
		return nil
	}
	return bytes.Clone(r.representative)
}

// MLDSA44SignerOptions returns the options every mldsa44 PrivateKeySigner
// passes to crypto/mldsa PrivateKey.Sign: pure ML-DSA.Sign over the message
// representative with the Draft-08 Section 3.4 context string "DKIM2".
// Signers use the default hedged (randomized) Sign, never SignDeterministic.
func MLDSA44SignerOptions() *mldsa.Options { return cryptodkim2.MLDSA44SignerOptions() }

// MLDSA44Available reports an error when the cryptographic runtime cannot
// provide ML-DSA-44, for example a binary built against the FIPS 140-3 Go
// Cryptographic Module v1.0.0. Verifier construction and mldsa44 signing
// credentials fail closed in that runtime; daemons call it at startup to
// report the reason.
func MLDSA44Available() error {
	if cryptodkim2.MLDSA44Available() != nil {
		return newSigningError(SigningErrorUnsupportedAlgorithm)
	}
	return nil
}

// Valid reports whether the request was created by the signing facade.
func (r PrivateKeySignRequest) Valid() bool {
	return r.valid && (r.algorithm == AlgorithmRSASHA256 || r.algorithm == AlgorithmEd25519SHA256 ||
		r.algorithm == AlgorithmMLDSA44)
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

// PrivateKeySigner signs one message representative through an opaque
// handle. The method keeps its historical name; for mldsa44 the
// representative is the complete Section 12.8 input, not a digest.
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
	case signing.AlgorithmMLDSA44:
		algorithm = AlgorithmMLDSA44
	default:
		return signing.PrivateKeySignResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.signer.SignDigest(ctx, PrivateKeyHandle{value: handle}, PrivateKeySignRequest{
		algorithm: algorithm, representative: request.MessageRepresentative(), valid: algorithm != AlgorithmUnknown,
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
