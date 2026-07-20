package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	defaultPublicationFreshness        = 5 * time.Minute
	maxConsumedPublicationCapabilities = 1024
)

// PublishedNextDomainCapability is single-use fresh evidence for one exact future credential.
type PublishedNextDomainCapability struct {
	domain, selector    string
	algorithm           Algorithm
	publicKey           any
	observation         [sha256.Size]byte
	nonce               [sha256.Size]byte
	issuedAt, expiresAt time.Time
	seal                [sha256.Size]byte
}

// Valid reports whether the capability has complete immutable publication evidence.
func (c PublishedNextDomainCapability) Valid() bool {
	return c.domain != "" && c.selector != "" && c.algorithm.Known() && c.publicKey != nil &&
		c.observation != [sha256.Size]byte{} && c.nonce != [sha256.Size]byte{} && !c.issuedAt.IsZero() && c.expiresAt.After(c.issuedAt) &&
		c.seal != [sha256.Size]byte{}
}

// String returns a constant secret-safe capability summary.
func (c PublishedNextDomainCapability) String() string {
	return "signing.PublishedNextDomainCapability{redacted}"
}

// GoString returns a constant secret-safe capability Go representation.
func (c PublishedNextDomainCapability) GoString() string { return c.String() }

// Format routes every capability formatting form through the redacted summary.
func (c PublishedNextDomainCapability) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// PublicationAuthority validates current profile publication and issues future-domain capabilities.
type PublicationAuthority struct {
	provider    verify.KeyProvider
	clock       func() time.Time
	entropy     io.Reader
	freshness   time.Duration
	sealKey     [sha256.Size]byte
	mu          sync.Mutex
	consumed    map[[sha256.Size]byte]time.Time
	maxConsumed int
}

// Valid reports whether the authority owns coherent immutable dependencies and bounded state.
func (a *PublicationAuthority) Valid() bool {
	return a != nil && !isNilSigningInterface(a.provider) && a.clock != nil && a.entropy != nil &&
		a.freshness > 0 && a.freshness <= defaultPublicationFreshness &&
		a.sealKey != [sha256.Size]byte{} && a.consumed != nil &&
		a.maxConsumed > 0 && a.maxConsumed <= maxConsumedPublicationCapabilities
}

// String returns a constant secret-safe publication authority summary.
func (a *PublicationAuthority) String() string { return "signing.PublicationAuthority{redacted}" }

// GoString returns a constant secret-safe authority Go representation.
func (a *PublicationAuthority) GoString() string { return a.String() }

// Format routes every authority formatting form through the redacted summary.
func (a *PublicationAuthority) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, a.String())
}

// NewPublicationAuthority constructs one publication issuer with private entropy.
func NewPublicationAuthority(keyProvider verify.KeyProvider, clock func() time.Time, freshness time.Duration) (*PublicationAuthority, error) {
	var sealKey [sha256.Size]byte
	if _, err := io.ReadFull(rand.Reader, sealKey[:]); err != nil || sealKey == [sha256.Size]byte{} {
		return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	return newPublicationAuthority(keyProvider, clock, freshness, sealKey, maxConsumedPublicationCapabilities)
}

// newPublicationAuthority constructs a deterministic bounded issuer for tests.
func newPublicationAuthority(keyProvider verify.KeyProvider, clock func() time.Time, freshness time.Duration, sealKey [sha256.Size]byte, maxConsumed int) (*PublicationAuthority, error) {
	return newPublicationAuthorityWithEntropy(keyProvider, clock, rand.Reader, freshness, sealKey, maxConsumed)
}

// newPublicationAuthorityWithEntropy constructs a deterministic issuer with injectable local entropy for tests.
func newPublicationAuthorityWithEntropy(keyProvider verify.KeyProvider, clock func() time.Time, entropy io.Reader, freshness time.Duration, sealKey [sha256.Size]byte, maxConsumed int) (*PublicationAuthority, error) {
	if isNilSigningInterface(keyProvider) || clock == nil || entropy == nil || sealKey == [sha256.Size]byte{} {
		return nil, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	if freshness == 0 {
		freshness = defaultPublicationFreshness
	}
	if freshness <= 0 || freshness > defaultPublicationFreshness || maxConsumed <= 0 || maxConsumed > maxConsumedPublicationCapabilities {
		return nil, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	return &PublicationAuthority{
		provider: keyProvider, clock: clock, entropy: entropy, freshness: freshness, sealKey: sealKey,
		consumed: make(map[[sha256.Size]byte]time.Time), maxConsumed: maxConsumed,
	}, nil
}

// ValidateProfilePublication proves every generated credential through the provider.
func (a *PublicationAuthority) ValidateProfilePublication(ctx context.Context, profile Profile) error {
	if a == nil || !profile.Valid() {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	for _, credential := range profile.credentials {
		if _, err := a.lookupPublishedCredential(ctx, profile.domain, credential); err != nil {
			return err
		}
	}
	return nil
}

// IssueNextDomain performs a fresh authoritative lookup and seals exact future evidence.
func (a *PublicationAuthority) IssueNextDomain(ctx context.Context, domain string, credential Credential) (PublishedNextDomainCapability, error) {
	if a == nil || !credential.Valid() {
		return PublishedNextDomainCapability{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	query, err := keyresolver.NewQuery(domain, credential.selector, credential.algorithm, keyresolver.DefaultLimits())
	if err != nil {
		return PublishedNextDomainCapability{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	now, err := a.operationTime()
	if err != nil {
		return PublishedNextDomainCapability{}, err
	}
	expiresAt := now.Add(a.freshness)
	if !expiresAt.After(now) || expiresAt.Year() > 9999 {
		return PublishedNextDomainCapability{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	var nonce [sha256.Size]byte
	if _, err := io.ReadFull(a.entropy, nonce[:]); err != nil || nonce == [sha256.Size]byte{} {
		return PublishedNextDomainCapability{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	observation, err := a.lookupPublishedCredential(ctx, query.SigningDomain(), credential)
	if err != nil {
		return PublishedNextDomainCapability{}, err
	}
	capability := PublishedNextDomainCapability{
		domain: query.SigningDomain(), selector: credential.selector, algorithm: credential.algorithm,
		publicKey: cloneSigningPublicKey(credential.publicKey), observation: observation,
		issuedAt: now, expiresAt: expiresAt, nonce: nonce,
	}
	capability.seal = a.capabilitySeal(capability)
	return capability, nil
}

// ConsumeAndRevalidate atomically consumes and freshly revalidates the exact supplied capability.
func (a *PublicationAuthority) ConsumeAndRevalidate(ctx context.Context, capability PublishedNextDomainCapability) error {
	if a == nil || ctx == nil {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !capability.Valid() {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	expectedSeal := a.capabilitySeal(capability)
	if subtle.ConstantTimeCompare(capability.seal[:], expectedSeal[:]) != 1 {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	now, err := a.operationTime()
	if err != nil {
		return err
	}
	return a.ConsumeAndRevalidateAt(ctx, capability, now)
}

// ValidateNextDomainCapabilityAt performs pure local seal, freshness, and reuse checks.
func (a *PublicationAuthority) ValidateNextDomainCapabilityAt(capability PublishedNextDomainCapability, now time.Time) error {
	if a == nil || !a.Valid() || !capability.Valid() || now.IsZero() {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	expectedSeal := a.capabilitySeal(capability)
	if subtle.ConstantTimeCompare(capability.seal[:], expectedSeal[:]) != 1 ||
		now.Before(capability.issuedAt) || !now.Before(capability.expiresAt) {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, reused := a.consumed[capability.seal]; reused {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return nil
}

// ConsumeAndRevalidateAt atomically consumes and revalidates at the plan-owned instant.
func (a *PublicationAuthority) ConsumeAndRevalidateAt(ctx context.Context, capability PublishedNextDomainCapability, now time.Time) error {
	if ctx == nil || a == nil {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.ValidateNextDomainCapabilityAt(capability, now); err != nil {
		return err
	}
	a.mu.Lock()
	for seal, expiry := range a.consumed {
		if !now.Before(expiry) {
			delete(a.consumed, seal)
		}
	}
	if _, reused := a.consumed[capability.seal]; reused {
		a.mu.Unlock()
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if len(a.consumed) >= a.maxConsumed {
		a.mu.Unlock()
		return newError(ErrorCodeLimitExceeded, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	a.consumed[capability.seal] = capability.expiresAt
	a.mu.Unlock()
	credential := Credential{
		selector: capability.selector, algorithm: capability.algorithm,
		publicKey: cloneSigningPublicKey(capability.publicKey), handle: PrivateKeyHandle{identity: capability.seal},
	}
	observation, err := a.lookupPublishedCredential(ctx, capability.domain, credential)
	if err != nil {
		return err
	}
	if observation != capability.observation {
		return newError(ErrorCodeKeyMismatch, ErrorLocation{Phase: PhaseCallback, Algorithm: capability.algorithm}, ErrorDetails{})
	}
	return nil
}

// lookupPublishedCredential owns the one strict provider matrix and exact-key match.
func (a *PublicationAuthority) lookupPublishedCredential(ctx context.Context, domain string, credential Credential) ([sha256.Size]byte, error) {
	if ctx == nil || a == nil || isNilSigningInterface(a.provider) || !credential.Valid() {
		return [sha256.Size]byte{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return [sha256.Size]byte{}, err
	}
	query := verify.KeyQuery{Domain: domain, Selector: credential.selector, Algorithm: credential.algorithm}
	result, callErr := a.provider.LookupKey(ctx, query)
	ctxErr := ctx.Err()
	if err := publicationCallbackError(result, callErr, ctxErr); err != nil {
		return [sha256.Size]byte{}, err
	}
	validated, err := validatePublishedResult(result, credential, ctxErr)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return publicationObservation(credential.algorithm, validated, result.Metadata), nil
}

// publicationCallbackError classifies the exact provider result/error pair before context reconciliation.
func publicationCallbackError(result verify.PublicKey, callErr, ctxErr error) error {
	if ctxErr != nil && callErr != nil && zeroPublicKey(result) && errors.Is(callErr, ctxErr) {
		return ctxErr
	}
	if isTypedNilSigningError(callErr) {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	if callErr == nil {
		return nil
	}
	if !zeroPublicKey(result) {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	class := provider.ClassOf(callErr)
	if ctxErr != nil && (class == provider.FailureTemporary || class == provider.FailurePermanent) {
		return ctxErr
	}
	switch class {
	case provider.FailureTemporary:
		return newError(ErrorCodeCallbackTemporary, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	case provider.FailurePermanent:
		return newError(ErrorCodeCallbackPermanent, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	default:
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
}

// validatePublishedResult validates one nil-error provider result and returns detached exact key material.
func validatePublishedResult(result verify.PublicKey, credential Credential, ctxErr error) (any, error) {
	if result.Algorithm != credential.algorithm || !result.Metadata.Status.Known() ||
		!result.Metadata.Policy.Valid() || !result.Metadata.Policy.AllowedForStatus(result.Metadata.Status, false) ||
		!verify.ValidProviderSource(result.Metadata.Source) {
		return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	switch result.Metadata.Status {
	case verify.KeyStatusFound:
		if result.Material == nil {
			return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
	case verify.KeyStatusMissing, verify.KeyStatusInvalid, verify.KeyStatusAmbiguous, verify.KeyStatusRevoked,
		verify.KeyStatusUnsupportedKeyType, verify.KeyStatusAlgorithmMismatch:
		if result.Material != nil {
			return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
		if ctxErr != nil {
			return nil, ctxErr
		}
		return nil, newError(ErrorCodeKeyMismatch, ErrorLocation{Phase: PhaseCallback, Algorithm: credential.algorithm}, ErrorDetails{})
	default:
		return nil, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	if ctxErr != nil {
		return nil, ctxErr
	}
	detached := detachProviderPublicKey(credential.algorithm, result.Material)
	if detached == nil {
		return nil, newError(ErrorCodeKeyMismatch, ErrorLocation{Phase: PhaseCallback, Algorithm: credential.algorithm}, ErrorDetails{})
	}
	validated, validationErr := cryptodkim2.ValidatePublicKey(credential.algorithm, detached, cryptodkim2.DefaultLimits())
	if validationErr != nil || !publicKeysEqual(validated, credential.publicKey) {
		return nil, newError(ErrorCodeKeyMismatch, ErrorLocation{Phase: PhaseCallback, Algorithm: credential.algorithm}, ErrorDetails{})
	}
	return validated, nil
}

// detachProviderPublicKey bounds and clones provider-owned material before validation.
func detachProviderPublicKey(algorithm Algorithm, material any) any {
	switch key := material.(type) {
	case ed25519.PublicKey:
		if algorithm != AlgorithmEd25519SHA256 || len(key) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(bytes.Clone(key))
	case *rsa.PublicKey:
		limits := DefaultLimits()
		if algorithm != AlgorithmRSASHA256 || key == nil || key.N == nil ||
			key.N.BitLen() < limits.MinRSABits || key.N.BitLen() > limits.MaxRSABits {
			return nil
		}
		return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
	default:
		return nil
	}
}

// publicationObservation binds exact material and bounded provider policy facts.
func publicationObservation(algorithm Algorithm, material any, metadata verify.KeyMetadata) [sha256.Size]byte {
	h := sha256.New()
	writeAuthorizationPart(h, []byte("dkim2/publication-observation/v1"))
	writeAuthorizationPart(h, []byte(algorithm))
	switch key := material.(type) {
	case interface{ Bytes() []byte }:
		writeAuthorizationPart(h, key.Bytes())
	default:
		writeAuthorizationPart(h, publicKeyTranscript(material))
	}
	writeAuthorizationPart(h, []byte(metadata.Status))
	writeAuthorizationPart(h, []byte(metadata.Source))
	writeAuthorizationPart(h, boolBytes(metadata.Policy.TestingDeclared))
	writeAuthorizationPart(h, boolBytes(metadata.Policy.StrictIdentityDeclared))
	writeAuthorizationPart(h, boolBytes(metadata.Policy.StrictIdentityApplicable))
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

// publicKeyTranscript serializes supported public material without exposing it.
func publicKeyTranscript(material any) []byte {
	switch key := material.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return nil
		}
		result := append([]byte(nil), key.N.Bytes()...)
		result = append(result, byte(key.E>>24), byte(key.E>>16), byte(key.E>>8), byte(key.E))
		return result
	case ed25519.PublicKey:
		return append([]byte(nil), key...)
	default:
		return nil
	}
}

// capabilitySeal seals exact credential, observation, and freshness.
func (a *PublicationAuthority) capabilitySeal(capability PublishedNextDomainCapability) [sha256.Size]byte {
	h := hmac.New(sha256.New, a.sealKey[:])
	writeAuthorizationPart(h, []byte("dkim2/published-next-domain/v1"))
	writeAuthorizationPart(h, []byte(capability.domain))
	writeAuthorizationPart(h, []byte(capability.selector))
	writeAuthorizationPart(h, []byte(capability.algorithm))
	writeAuthorizationPart(h, publicKeyTranscript(capability.publicKey))
	writeAuthorizationPart(h, capability.observation[:])
	writeAuthorizationPart(h, capability.nonce[:])
	writeAuthorizationPart(h, []byte(capability.issuedAt.UTC().Format(time.RFC3339Nano)))
	writeAuthorizationPart(h, []byte(capability.expiresAt.UTC().Format(time.RFC3339Nano)))
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

// zeroPublicKey reports the only legal result paired with provider errors.
func zeroPublicKey(result verify.PublicKey) bool {
	return result.Algorithm == "" && result.Material == nil && result.Metadata == (verify.KeyMetadata{})
}

// operationTime captures one nonnegative representable publication time.
func (a *PublicationAuthority) operationTime() (now time.Time, err error) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			err = newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
		}
	}()
	now = a.clock()
	if now.IsZero() || now.Unix() < 0 || now.Year() < 1 || now.Year() > 9999 {
		return time.Time{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseCallback}, ErrorDetails{})
	}
	return now, nil
}
