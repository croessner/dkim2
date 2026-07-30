package datasource

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/signature"
)

// Algorithm aliases the signature owner's closed signing algorithm vocabulary.
type Algorithm = signature.Algorithm

const (
	// AlgorithmRSASHA256 identifies one RSA-SHA256 signing credential.
	AlgorithmRSASHA256 = signature.AlgorithmRSASHA256
	// AlgorithmEd25519SHA256 identifies one Ed25519-SHA256 signing credential.
	AlgorithmEd25519SHA256 = signature.AlgorithmEd25519SHA256
)

// Credential contains one immutable public signing credential and opaque handle ID.
type Credential struct {
	selector      string
	algorithm     Algorithm
	publicKeySPKI []byte
	publicKey     any
	handleID      KeyHandleID
	complete      bool
}

// NewCredential validates and detaches one provider-neutral signing credential.
func NewCredential(selector string, algorithm Algorithm, publicKeySPKI []byte, handleID KeyHandleID, limits Limits) (Credential, error) {
	if limits.Validate() != nil || !algorithm.Known() || !handleID.Valid() ||
		len(publicKeySPKI) == 0 {
		return Credential{}, NewError(ErrorCodeInvalidRequest)
	}
	if handleID.ByteLen() > limits.MaxIdentifierBytes ||
		len(publicKeySPKI) > limits.MaxDecodedPublicKeyBytes {
		return Credential{}, NewError(ErrorCodeLimitExceeded)
	}
	canonicalSelector, err := canonicalDatasourceSelector(
		selector, limits.MaxSelectorBytes, limits.MaxSelectorLabels,
	)
	if err != nil {
		return Credential{}, err
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKeySPKI)
	if err != nil {
		return Credential{}, NewError(ErrorCodeInvalidRequest)
	}
	canonicalSPKI, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil || !bytes.Equal(canonicalSPKI, publicKeySPKI) {
		return Credential{}, NewError(ErrorCodeInvalidRequest)
	}
	validated, err := cryptodkim2.ValidatePublicKey(algorithm, parsed, cryptodkim2.DefaultLimits())
	if err != nil {
		return Credential{}, NewError(ErrorCodeInvalidRequest)
	}
	return Credential{
		selector: canonicalSelector, algorithm: algorithm,
		publicKeySPKI: bytes.Clone(canonicalSPKI),
		publicKey:     validated, handleID: handleID, complete: true,
	}, nil
}

// Valid reports whether the credential remains complete under hard limits.
func (c Credential) Valid() bool { return c.validForLimits(HardLimits()) }

// ValidForLimits reports whether the credential satisfies one narrowed datasource contract.
func (c Credential) ValidForLimits(limits Limits) bool { return c.validForLimits(limits) }

// Selector returns the canonical selector.
func (c Credential) Selector() string { return c.selector }

// Algorithm returns the baseline signing algorithm.
func (c Credential) Algorithm() Algorithm { return c.algorithm }

// PublicKeySPKIDER returns detached canonical public SPKI DER.
func (c Credential) PublicKeySPKIDER() []byte { return bytes.Clone(c.publicKeySPKI) }

// PublicKey returns detached validated public-key material.
func (c Credential) PublicKey() any { return cryptodkim2.ClonePublicKey(c.publicKey) }

// PublicKeySPKISHA256 returns the digest of the exact canonical SPKI DER.
func (c Credential) PublicKeySPKISHA256() [sha256.Size]byte {
	return sha256.Sum256(c.publicKeySPKI)
}

// KeyHandleID returns the provider-neutral opaque handle identifier.
func (c Credential) KeyHandleID() KeyHandleID { return c.handleID }

// String returns a constant protected credential summary.
func (c Credential) String() string { return "datasource.Credential{redacted}" }

// GoString returns a constant protected credential representation.
func (c Credential) GoString() string { return c.String() }

// Format prevents formatting verbs from exposing credential facts.
func (c Credential) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, c.String()) }

// validForLimits verifies the credential under one narrowed datasource contract.
func (c Credential) validForLimits(limits Limits) bool {
	if !c.complete {
		return false
	}
	rebuilt, err := NewCredential(c.selector, c.algorithm, c.publicKeySPKI, c.handleID, limits)
	return err == nil && credentialFactsEqual(c, rebuilt)
}

// Profile contains one immutable complete datasource signing profile.
type Profile struct {
	id          ProfileID
	domain      string
	status      RecordStatus
	credentials []Credential
	notBefore   time.Time
	notAfter    time.Time
	complete    bool
}

// NewProfile validates and detaches one complete datasource signing profile.
func NewProfile(
	id ProfileID,
	domain string,
	status RecordStatus,
	credentials []Credential,
	notBefore time.Time,
	notAfter time.Time,
	limits Limits,
) (Profile, error) {
	if limits.Validate() != nil || !id.Valid() || !status.Known() ||
		len(credentials) == 0 {
		return Profile{}, NewError(ErrorCodeInvalidRequest)
	}
	if id.ByteLen() > limits.MaxIdentifierBytes ||
		len(credentials) > limits.MaxCredentialsPerProfile {
		return Profile{}, NewError(ErrorCodeLimitExceeded)
	}
	canonicalDomain, err := canonicalDatasourceDomain(
		domain, limits.MaxDomainBytes, limits.MaxDomainLabels,
	)
	if err != nil {
		return Profile{}, err
	}
	windowPresent := !notBefore.IsZero() || !notAfter.IsZero()
	if windowPresent {
		if notBefore.IsZero() || notAfter.IsZero() || !notBefore.Before(notAfter) {
			return Profile{}, NewError(ErrorCodeInvalidRequest)
		}
		notBefore = notBefore.UTC()
		notAfter = notAfter.UTC()
	}
	ordered := make([]Credential, 0, len(credentials))
	seenAlgorithms := make(map[Algorithm]struct{}, len(credentials))
	seenSelectors := make(map[string]struct{}, len(credentials))
	seenHandles := make(map[KeyHandleID]struct{}, len(credentials))
	resolverLimits := keyresolver.DefaultLimits()
	resolverLimits.MaxSigningDomainBytes = limits.MaxDomainBytes
	resolverLimits.MaxSigningDomainLabels = limits.MaxDomainLabels
	resolverLimits.MaxSelectorBytes = limits.MaxSelectorBytes
	resolverLimits.MaxSelectorLabels = limits.MaxSelectorLabels
	for _, credential := range credentials {
		if !credential.Valid() {
			return Profile{}, NewError(ErrorCodeInvalidRequest)
		}
		if !credential.validForLimits(limits) {
			return Profile{}, NewError(ErrorCodeLimitExceeded)
		}
		query, queryErr := keyresolver.NewQuery(
			canonicalDomain,
			credential.selector,
			credential.algorithm,
			resolverLimits,
		)
		if queryErr != nil || query.SigningDomain() != canonicalDomain ||
			query.Selector() != credential.selector {
			return Profile{}, NewError(ErrorCodeLimitExceeded)
		}
		if _, duplicate := seenAlgorithms[credential.algorithm]; duplicate {
			return Profile{}, NewError(ErrorCodeInvalidRequest)
		}
		if _, duplicate := seenSelectors[credential.selector]; duplicate {
			return Profile{}, NewError(ErrorCodeInvalidRequest)
		}
		if _, duplicate := seenHandles[credential.handleID]; duplicate {
			return Profile{}, NewError(ErrorCodeInvalidRequest)
		}
		seenAlgorithms[credential.algorithm] = struct{}{}
		seenSelectors[credential.selector] = struct{}{}
		seenHandles[credential.handleID] = struct{}{}
	}
	for _, algorithm := range []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256} {
		for _, credential := range credentials {
			if credential.algorithm == algorithm {
				ordered = append(ordered, cloneCredential(credential))
			}
		}
	}
	return Profile{
		id: id, domain: canonicalDomain, status: status, credentials: ordered,
		notBefore: notBefore, notAfter: notAfter, complete: true,
	}, nil
}

// Valid reports whether the profile remains complete under hard limits.
func (p Profile) Valid() bool { return p.validForLimits(HardLimits()) }

// ValidForLimits reports whether the profile satisfies one narrowed datasource contract.
func (p Profile) ValidForLimits(limits Limits) bool { return p.validForLimits(limits) }

// ID returns the exact profile identity.
func (p Profile) ID() ProfileID { return p.id }

// SigningDomain returns the canonical profile signing domain.
func (p Profile) SigningDomain() string { return p.domain }

// Status returns the closed administrative profile status.
func (p Profile) Status() RecordStatus { return p.status }

// CredentialCount returns the bounded number of complete profile credentials.
func (p Profile) CredentialCount() int { return len(p.credentials) }

// Credentials returns detached credentials in RSA then Ed25519 order.
func (p Profile) Credentials() []Credential {
	output := make([]Credential, len(p.credentials))
	for index := range p.credentials {
		output[index] = cloneCredential(p.credentials[index])
	}
	return output
}

// ValidityWindow returns the optional half-open UTC validity window.
func (p Profile) ValidityWindow() (time.Time, time.Time, bool) {
	if p.notBefore.IsZero() || p.notAfter.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return p.notBefore, p.notAfter, true
}

// ActiveAt verifies status and the optional half-open validity window at one captured instant.
func (p Profile) ActiveAt(at time.Time) error {
	if at.IsZero() {
		return NewError(ErrorCodeInvalidRequest)
	}
	if !p.Valid() {
		return NewError(ErrorCodeInternalInvariant)
	}
	if p.status != RecordStatusActive {
		return NewError(ErrorCodeInactive)
	}
	if !p.notBefore.IsZero() && (at.Before(p.notBefore) || !at.Before(p.notAfter)) {
		return NewError(ErrorCodeInactive)
	}
	return nil
}

// String returns a constant protected profile summary.
func (p Profile) String() string { return "datasource.Profile{redacted}" }

// GoString returns a constant protected profile representation.
func (p Profile) GoString() string { return p.String() }

// Format prevents formatting verbs from exposing profile facts.
func (p Profile) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// validForLimits verifies the profile under one narrowed datasource contract.
func (p Profile) validForLimits(limits Limits) bool {
	if !p.complete {
		return false
	}
	rebuilt, err := NewProfile(
		p.id, p.domain, p.status, p.credentials, p.notBefore, p.notAfter, limits,
	)
	return err == nil && profileFactsEqual(p, rebuilt)
}

// isZero reports whether no profile fact is populated.
func (p Profile) isZero() bool {
	return p.id.zero() && p.domain == "" && p.status == 0 &&
		p.credentials == nil && p.notBefore.IsZero() && p.notAfter.IsZero() &&
		!p.complete
}

// Policy contains one immutable exact administrative profile binding.
type Policy struct {
	tenant        TenantID
	domain        string
	use           ProfileUse
	profileID     ProfileID
	status        RecordStatus
	rollout       Rollout
	compatibility Compatibility
	feedback      FeedbackRouteID
	complete      bool
}

// NewPolicy validates one exact administrative domain and tenant binding.
func NewPolicy(
	tenant TenantID,
	domain string,
	use ProfileUse,
	profileID ProfileID,
	status RecordStatus,
	rollout Rollout,
	compatibility Compatibility,
	feedback FeedbackRouteID,
	limits Limits,
) (Policy, error) {
	if limits.Validate() != nil || !tenant.Valid() || !profileID.Valid() ||
		!use.Known() || !status.Known() || !rollout.Known() ||
		compatibility != CompatibilityStrict ||
		(!feedback.zero() && !feedback.Valid()) {
		return Policy{}, NewError(ErrorCodeInvalidRequest)
	}
	if tenant.ByteLen() > limits.MaxIdentifierBytes ||
		profileID.ByteLen() > limits.MaxIdentifierBytes ||
		(feedback.Valid() && feedback.ByteLen() > limits.MaxIdentifierBytes) {
		return Policy{}, NewError(ErrorCodeLimitExceeded)
	}
	canonicalDomain, err := canonicalDatasourceDomain(
		domain, limits.MaxDomainBytes, limits.MaxDomainLabels,
	)
	if err != nil {
		return Policy{}, err
	}
	return Policy{
		tenant: tenant, domain: canonicalDomain, use: use, profileID: profileID,
		status: status, rollout: rollout, compatibility: compatibility,
		feedback: feedback, complete: true,
	}, nil
}

// Valid reports whether the policy remains complete under hard limits.
func (p Policy) Valid() bool { return p.validForLimits(HardLimits()) }

// ValidForLimits reports whether the policy satisfies one narrowed datasource contract.
func (p Policy) ValidForLimits(limits Limits) bool { return p.validForLimits(limits) }

// TenantID returns the exact tenant identity.
func (p Policy) TenantID() TenantID { return p.tenant }

// SigningDomain returns the canonical administrative signing domain.
func (p Policy) SigningDomain() string { return p.domain }

// Use returns the exact administrative selection purpose.
func (p Policy) Use() ProfileUse { return p.use }

// ProfileID returns the exact bound profile identity.
func (p Policy) ProfileID() ProfileID { return p.profileID }

// Status returns the closed policy-record status.
func (p Policy) Status() RecordStatus { return p.status }

// Rollout returns the closed administrative rollout state.
func (p Policy) Rollout() Rollout { return p.rollout }

// Compatibility returns the strict compatibility policy.
func (p Policy) Compatibility() Compatibility { return p.compatibility }

// FeedbackRouteID returns the optional opaque feedback-route reference.
func (p Policy) FeedbackRouteID() (FeedbackRouteID, bool) {
	return p.feedback, p.feedback.Valid()
}

// Eligible verifies whether this administrative policy may select a signing profile.
func (p Policy) Eligible() error {
	if !p.Valid() {
		return NewError(ErrorCodeInternalInvariant)
	}
	if p.status != RecordStatusActive || p.rollout != RolloutEnforce ||
		p.compatibility != CompatibilityStrict {
		return NewError(ErrorCodeInactive)
	}
	return nil
}

// String returns a constant protected policy summary.
func (p Policy) String() string { return "datasource.Policy{redacted}" }

// GoString returns a constant protected policy representation.
func (p Policy) GoString() string { return p.String() }

// Format prevents formatting verbs from exposing policy facts.
func (p Policy) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// validForLimits verifies the policy under one narrowed datasource contract.
func (p Policy) validForLimits(limits Limits) bool {
	if !p.complete {
		return false
	}
	rebuilt, err := NewPolicy(
		p.tenant, p.domain, p.use, p.profileID, p.status, p.rollout,
		p.compatibility, p.feedback, limits,
	)
	return err == nil && rebuilt == p
}

// isZero reports whether no policy fact is populated.
func (p Policy) isZero() bool {
	return p.tenant.zero() && p.domain == "" && p.use == 0 &&
		p.profileID.zero() && p.status == 0 && p.rollout == 0 &&
		p.compatibility == 0 && p.feedback.zero() && !p.complete
}

// cloneCredential returns a detached credential.
func cloneCredential(input Credential) Credential {
	input.publicKeySPKI = bytes.Clone(input.publicKeySPKI)
	input.publicKey = cryptodkim2.ClonePublicKey(input.publicKey)
	return input
}

// credentialFactsEqual compares exact immutable credential facts.
func credentialFactsEqual(left, right Credential) bool {
	return left.selector == right.selector && left.algorithm == right.algorithm &&
		bytes.Equal(left.publicKeySPKI, right.publicKeySPKI) &&
		publicKeysEqual(left.publicKey, right.publicKey) &&
		left.handleID == right.handleID && left.complete == right.complete
}

// profileFactsEqual compares exact immutable profile facts.
func profileFactsEqual(left, right Profile) bool {
	if left.id != right.id || left.domain != right.domain || left.status != right.status ||
		!left.notBefore.Equal(right.notBefore) || !left.notAfter.Equal(right.notAfter) ||
		left.complete != right.complete || len(left.credentials) != len(right.credentials) {
		return false
	}
	for index := range left.credentials {
		if !credentialFactsEqual(left.credentials[index], right.credentials[index]) {
			return false
		}
	}
	return true
}

// ProfileFactsEqual reports exact equality for two immutable profile values.
func ProfileFactsEqual(left, right Profile) bool {
	return left.Valid() && right.Valid() && profileFactsEqual(left, right)
}

// cloneProfile returns a detached immutable profile.
func cloneProfile(input Profile) Profile {
	credentials := input.credentials
	input.credentials = make([]Credential, len(credentials))
	for index := range credentials {
		input.credentials[index] = cloneCredential(credentials[index])
	}
	return input
}

// canonicalDatasourceDNSName distinguishes invalid syntax from a named bound excess.
func canonicalDatasourceDNSName(
	value string,
	maxBytes int,
	maxLabels int,
	hardBytes int,
	hardLabels int,
	canonicalize func(string, int, int) (string, error),
) (string, error) {
	canonical, err := canonicalize(value, hardBytes, hardLabels)
	if err != nil {
		if len(value) > hardBytes ||
			value != "" && strings.Count(value, ".")+1 > hardLabels {
			return "", NewError(ErrorCodeLimitExceeded)
		}
		return "", NewError(ErrorCodeInvalidRequest)
	}
	if len(canonical) > maxBytes || strings.Count(canonical, ".")+1 > maxLabels {
		return "", NewError(ErrorCodeLimitExceeded)
	}
	return canonical, nil
}

// canonicalDatasourceDomain applies shared domain grammar and datasource bounds.
func canonicalDatasourceDomain(value string, maxBytes, maxLabels int) (string, error) {
	hard := HardLimits()
	return canonicalDatasourceDNSName(
		value, maxBytes, maxLabels, hard.MaxDomainBytes, hard.MaxDomainLabels,
		keyresolver.CanonicalSigningDomain,
	)
}

// canonicalDatasourceSelector applies shared selector grammar and datasource bounds.
func canonicalDatasourceSelector(value string, maxBytes, maxLabels int) (string, error) {
	hard := HardLimits()
	return canonicalDatasourceDNSName(
		value, maxBytes, maxLabels, hard.MaxSelectorBytes, hard.MaxSelectorLabels,
		keyresolver.CanonicalSelector,
	)
}

// publicKeysEqual compares exact supported public-key material without exposing it.
func publicKeysEqual(left, right any) bool {
	leftSPKI, leftErr := x509.MarshalPKIXPublicKey(left)
	rightSPKI, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftSPKI, rightSPKI)
}
