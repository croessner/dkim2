package dkim2

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/croessner/dkim2/internal/verify"
)

type publicKeyBridge struct {
	provider PublicKeyProvider
	sink     ObservationSink
}

// LookupKey adapts the closed public provider matrix into typed protocol-core key facts.
func (b publicKeyBridge) LookupKey(
	ctx context.Context,
	query verify.KeyQuery,
) (key verify.PublicKey, resultErr error) {
	started := time.Now()
	defer func() {
		b.observeLookup(ctx, query.Algorithm, key, resultErr, time.Since(started))
	}()
	algorithm, ok := publicAlgorithm(query.Algorithm)
	if !ok || nilPublicKeyProvider(b.provider) {
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
	}
	result, err := b.provider.LookupPublicKey(ctx, newPublicKeyQuery(query.Domain, query.Selector, algorithm))
	if err != nil {
		if !result.IsZero() {
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
		}
		if nilSigningCallback(err) {
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
		}
		if ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return verify.PublicKey{}, ctx.Err()
		}
		class := ProviderErrorClassOf(err)
		if errors.Is(err, context.DeadlineExceeded) && class != ProviderErrorClassTemporary {
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
		}
		switch class {
		case ProviderErrorClassTemporary:
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureTemporary)
		case ProviderErrorClassPermanent:
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailurePermanent)
		default:
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
		}
	}
	if result.IsZero() || !result.Status().Known() || result.Algorithm() != algorithm {
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
	}
	metadata := result.KeyPolicyMetadata()
	if (result.Status() == PublicKeyStatusMissing || result.Status() == PublicKeyStatusAmbiguous) &&
		(metadata.TestingDeclared() || metadata.StrictIdentityDeclared()) {
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
	}

	internalAlgorithm := verify.Algorithm(result.Algorithm())
	switch result.Status() {
	case PublicKeyStatusFound:
		return foundInternalPublicKey(result, internalAlgorithm)
	case PublicKeyStatusMissing, PublicKeyStatusInvalid, PublicKeyStatusAmbiguous, PublicKeyStatusRevoked, PublicKeyStatusUnsupportedKeyType, PublicKeyStatusAlgorithmMismatch:
		if publicResultHasMaterial(result) {
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
		}
		return verify.PublicKey{Algorithm: internalAlgorithm, Metadata: verify.KeyMetadata{Status: internalKeyStatus(result.Status()), Policy: internalKeyPolicyMetadata(result.KeyPolicyMetadata())}}, nil
	default:
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
	}
}

// observeLookup emits one closed DNS lookup event after bridge validation.
func (b publicKeyBridge) observeLookup(
	ctx context.Context,
	algorithm verify.Algorithm,
	key verify.PublicKey,
	err error,
	duration time.Duration,
) {
	result, reason, errorClass := dnsEventOutcome(ctx, key, err)
	event, ok := NewObservationEvent(
		ObservationDNSLookupCompleted,
		ObservationOperationDNSLookup,
		result,
		reason,
		errorClass,
		observationAlgorithm(algorithm),
		ObservationCacheNotUsed,
		observationDurationBucket(duration),
		ObservationBucketNone,
		ObservationBucketNone,
		ObservationBucketNone,
		ObservationBucketNone,
	)
	if ok {
		Observe(ctx, b.sink, event)
	}
}

// dnsEventOutcome maps provider bridge output into closed lookup classes.
func dnsEventOutcome(
	ctx context.Context,
	key verify.PublicKey,
	err error,
) (ObservationResult, ObservationReason, ObservationErrorClass) {
	if err != nil {
		switch {
		case ctx != nil && ctx.Err() == context.Canceled:
			return ObservationResultTemporary, ObservationReasonUnavailable, ObservationErrorCanceled
		case ctx != nil && ctx.Err() == context.DeadlineExceeded:
			return ObservationResultTemporary, ObservationReasonUnavailable, ObservationErrorDeadline
		default:
			return ObservationResultFailure, ObservationReasonProtocol, ObservationErrorPermanent
		}
	}
	if key.Metadata.Status == verify.KeyStatusFound {
		return ObservationResultSuccess, ObservationReasonNone, ObservationErrorNone
	}
	return ObservationResultFailure, ObservationReasonProtocol, ObservationErrorNone
}

// observationAlgorithm maps a verifier algorithm into the public telemetry family.
func observationAlgorithm(algorithm verify.Algorithm) ObservationAlgorithm {
	switch algorithm {
	case verify.AlgorithmRSASHA256:
		return ObservationAlgorithmRSA
	case verify.AlgorithmEd25519SHA256:
		return ObservationAlgorithmEd25519
	default:
		return ObservationAlgorithmUnknown
	}
}

// foundInternalPublicKey validates one mutually exclusive public material variant.
func foundInternalPublicKey(result PublicKeyResult, algorithm verify.Algorithm) (verify.PublicKey, error) {
	rsaKey, hasRSA := result.RSAPublicKey()
	edKey, hasEd := result.Ed25519PublicKey()
	if hasRSA == hasEd {
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
	}
	switch algorithm {
	case verify.AlgorithmRSASHA256:
		if !hasRSA || rsaKey == nil || rsaKey.N == nil {
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
		}
		return verify.PublicKey{Algorithm: algorithm, Material: cloneRSAPublicKey(rsaKey), Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound, Policy: internalKeyPolicyMetadata(result.KeyPolicyMetadata())}}, nil
	case verify.AlgorithmEd25519SHA256:
		if !hasEd {
			return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
		}
		return verify.PublicKey{Algorithm: algorithm, Material: ed25519.PublicKey(append([]byte(nil), edKey...)), Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound, Policy: internalKeyPolicyMetadata(result.KeyPolicyMetadata())}}, nil
	default:
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureContract)
	}
}

// publicResultHasMaterial reports whether any explicit public-key variant is present.
func publicResultHasMaterial(result PublicKeyResult) bool {
	_, hasRSA := result.RSAPublicKey()
	_, hasEd := result.Ed25519PublicKey()
	return hasRSA || hasEd
}

// publicAlgorithm maps an internal verification algorithm into the closed public provider vocabulary.
func publicAlgorithm(algorithm verify.Algorithm) (Algorithm, bool) {
	switch algorithm {
	case verify.AlgorithmRSASHA256:
		return AlgorithmRSASHA256, true
	case verify.AlgorithmEd25519SHA256:
		return AlgorithmEd25519SHA256, true
	default:
		return AlgorithmUnknown, false
	}
}

// internalKeyStatus maps a declared non-found public result into protocol-core key state.
func internalKeyStatus(status PublicKeyStatus) verify.KeyStatus {
	switch status {
	case PublicKeyStatusMissing:
		return verify.KeyStatusMissing
	case PublicKeyStatusInvalid:
		return verify.KeyStatusInvalid
	case PublicKeyStatusAmbiguous:
		return verify.KeyStatusAmbiguous
	case PublicKeyStatusRevoked:
		return verify.KeyStatusRevoked
	case PublicKeyStatusUnsupportedKeyType:
		return verify.KeyStatusUnsupportedKeyType
	case PublicKeyStatusAlgorithmMismatch:
		return verify.KeyStatusAlgorithmMismatch
	default:
		return verify.KeyStatusProviderContract
	}
}

// internalKeyPolicyMetadata maps bounded public DNS declarations into verifier facts.
func internalKeyPolicyMetadata(metadata KeyPolicyMetadata) verify.KeyPolicyMetadata {
	return verify.KeyPolicyMetadata{
		TestingDeclared:          metadata.TestingDeclared(),
		StrictIdentityDeclared:   metadata.StrictIdentityDeclared(),
		StrictIdentityApplicable: metadata.StrictIdentityApplicable(),
	}
}
