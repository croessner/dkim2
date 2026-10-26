package signing

import (
	"crypto/sha256"
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/signature"
)

const maxPrivateKeyHandleIdentityBytes = 256

// PrivateKeyHandle is an opaque immutable provider reference with no key accessor.
type PrivateKeyHandle struct{ identity [sha256.Size]byte }

// NewPrivateKeyHandle constructs one opaque handle from provider-owned identity bytes.
func NewPrivateKeyHandle(identity []byte) (PrivateKeyHandle, error) {
	if len(identity) == 0 || len(identity) > maxPrivateKeyHandleIdentityBytes {
		return PrivateKeyHandle{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	h := sha256.New()
	writeAuthorizationPart(h, []byte("dkim2/private-key-handle/v1"))
	writeAuthorizationPart(h, identity)
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	if digest == [sha256.Size]byte{} {
		return PrivateKeyHandle{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return PrivateKeyHandle{identity: digest}, nil
}

// Valid reports whether the handle was constructed from nonempty identity.
func (h PrivateKeyHandle) Valid() bool { return h.identity != [sha256.Size]byte{} }

// String returns a constant secret-safe handle summary.
func (h PrivateKeyHandle) String() string { return "signing.PrivateKeyHandle{redacted}" }

// GoString returns a constant secret-safe handle Go representation.
func (h PrivateKeyHandle) GoString() string { return h.String() }

// Format routes every handle formatting form through the redacted summary.
func (h PrivateKeyHandle) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, h.String()) }

// Credential binds one selector, baseline algorithm, public key, and opaque private handle.
type Credential struct {
	selector  string
	algorithm Algorithm
	publicKey any
	handle    PrivateKeyHandle
}

// SignableAlgorithm reports whether this implementation can create
// signatures with algorithm: rsa-sha256 and ed25519-sha256. The unsettled
// post-quantum composite is not implemented and fails closed.
func SignableAlgorithm(algorithm Algorithm) bool {
	return algorithm.Signable()
}

// NewCredential validates one provider-neutral signing credential.
func NewCredential(selector string, algorithm Algorithm, publicKey any, handle PrivateKeyHandle, limits Limits) (Credential, error) {
	resolved, err := limits.normalized()
	if err != nil || !handle.Valid() || !SignableAlgorithm(algorithm) {
		return Credential{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	query, queryErr := keyresolver.NewQuery("credential.invalid", selector, algorithm, keyresolver.DefaultLimits())
	if queryErr != nil {
		return Credential{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	validated, validationErr := cryptodkim2.ValidatePublicKey(algorithm, publicKey, cryptodkim2.Limits{
		MinRSABits: resolved.MinRSABits, MaxRSABits: resolved.MaxRSABits,
		RequiredRSAExponent: resolved.RequiredRSAExponent, MaxSignatureBytes: resolved.MaxPrivateSignatureBytes,
	})
	if validationErr != nil {
		return Credential{}, newError(ErrorCodeKeyMismatch, ErrorLocation{Phase: PhasePreflight, Algorithm: algorithm}, ErrorDetails{})
	}
	return Credential{selector: query.Selector(), algorithm: algorithm, publicKey: validated, handle: handle}, nil
}

// Selector returns the canonical selector for trusted internal lookup.
func (c Credential) Selector() string { return c.selector }

// Algorithm returns the baseline algorithm.
func (c Credential) Algorithm() Algorithm { return c.algorithm }

// PublicKey returns detached public verification material.
func (c Credential) PublicKey() any { return cloneSigningPublicKey(c.publicKey) }

// Valid reports whether the credential is internally coherent.
func (c Credential) Valid() bool {
	if c.selector == "" || !c.algorithm.Known() || !c.handle.Valid() {
		return false
	}
	_, err := cryptodkim2.ValidatePublicKey(c.algorithm, c.publicKey, cryptodkim2.DefaultLimits())
	return err == nil
}

// String returns a constant secret-safe credential summary.
func (c Credential) String() string { return "signing.Credential{redacted}" }

// GoString returns a constant secret-safe credential Go representation.
func (c Credential) GoString() string { return c.String() }

// Format routes every credential formatting form through the redacted summary.
func (c Credential) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, c.String()) }

// Profile contains one canonical domain and up to one credential per
// signable algorithm in canonical signing order.
type Profile struct {
	domain      string
	credentials []Credential
}

// NewProfile validates domain, unique algorithms/selectors, and canonical credential order.
func NewProfile(domain string, credentials []Credential) (Profile, error) {
	if len(credentials) == 0 || len(credentials) > len(signature.SigningAlgorithmOrder()) {
		return Profile{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	canonicalDomain := ""
	ordered := make([]Credential, 0, len(credentials))
	seenAlgorithms := make(map[Algorithm]struct{}, len(credentials))
	seenSelectors := make(map[string]struct{}, len(credentials))
	for _, credential := range credentials {
		if !credential.Valid() {
			return Profile{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		query, err := keyresolver.NewQuery(domain, credential.selector, credential.algorithm, keyresolver.DefaultLimits())
		if err != nil {
			return Profile{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		if canonicalDomain == "" {
			canonicalDomain = query.SigningDomain()
		}
		if _, duplicate := seenAlgorithms[credential.algorithm]; duplicate {
			return Profile{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		if _, duplicate := seenSelectors[credential.selector]; duplicate {
			return Profile{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		seenAlgorithms[credential.algorithm] = struct{}{}
		seenSelectors[credential.selector] = struct{}{}
	}
	for _, algorithm := range signature.SigningAlgorithmOrder() {
		for _, credential := range credentials {
			if credential.algorithm == algorithm {
				ordered = append(ordered, cloneCredential(credential))
			}
		}
	}
	return Profile{domain: canonicalDomain, credentials: ordered}, nil
}

// Domain returns the canonical signing domain.
func (p Profile) Domain() string { return p.domain }

// Credentials returns detached credentials in RSA then Ed25519 order.
func (p Profile) Credentials() []Credential {
	output := slices.Clone(p.credentials)
	for index := range output {
		output[index] = cloneCredential(output[index])
	}
	return output
}

// Valid reports whether the profile remains canonical and coherent.
func (p Profile) Valid() bool {
	rebuilt, err := NewProfile(p.domain, p.credentials)
	return err == nil && rebuilt.domain == p.domain && credentialsEqual(rebuilt.credentials, p.credentials)
}

// ValidForLimits reports whether every credential satisfies one narrowed operation contract.
func (p Profile) ValidForLimits(limits Limits) bool {
	if !p.Valid() {
		return false
	}
	credentials := make([]Credential, len(p.credentials))
	for index, credential := range p.credentials {
		rebuilt, err := NewCredential(
			credential.selector, credential.algorithm, credential.publicKey,
			credential.handle, limits,
		)
		if err != nil {
			return false
		}
		credentials[index] = rebuilt
	}
	rebuilt, err := NewProfile(p.domain, credentials)
	return err == nil && credentialsEqual(rebuilt.credentials, p.credentials)
}

// String returns a constant secret-safe profile summary.
func (p Profile) String() string { return "signing.Profile{redacted}" }

// GoString returns a constant secret-safe profile Go representation.
func (p Profile) GoString() string { return p.String() }

// Format routes every profile formatting form through the redacted summary.
func (p Profile) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// cloneCredential returns detached credential material.
func cloneCredential(input Credential) Credential {
	input.publicKey = cloneSigningPublicKey(input.publicKey)
	return input
}

// cloneSigningPublicKey returns detached supported public-key material
// through the cryptographic owner.
func cloneSigningPublicKey(material any) any { return cryptodkim2.ClonePublicKey(material) }

// publicKeysEqual compares exact algorithm-specific public material through
// the cryptographic owner.
func publicKeysEqual(left, right any) bool { return cryptodkim2.PublicKeysEqual(left, right) }

// credentialsEqual compares canonical credential facts including opaque handles.
func credentialsEqual(left, right []Credential) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].selector != right[index].selector || left[index].algorithm != right[index].algorithm ||
			left[index].handle != right[index].handle || !publicKeysEqual(left[index].publicKey, right[index].publicKey) {
			return false
		}
	}
	return true
}
