package dkim2

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/signing"
)

// PrivateKeyHandle is an opaque immutable reference understood only by a
// caller-provided PrivateKeySigner.
type PrivateKeyHandle struct{ value signing.PrivateKeyHandle }

// NewPrivateKeyHandle constructs an opaque handle from provider-owned identity
// bytes without retaining or exposing those bytes.
func NewPrivateKeyHandle(identity []byte) (PrivateKeyHandle, error) {
	value, err := signing.NewPrivateKeyHandle(identity)
	if err != nil {
		return PrivateKeyHandle{}, mapSigningError(err)
	}
	return PrivateKeyHandle{value: value}, nil
}

// Valid reports whether the handle was constructed from a nonempty identity.
func (h PrivateKeyHandle) Valid() bool { return h.value.Valid() }

// ProjectedPrivateKeyHandle returns the detached internal handle needed by
// repository-owned datasource bridges. The return type prevents use outside
// sibling modules that are permitted to import the internal signing package.
func ProjectedPrivateKeyHandle(handle PrivateKeyHandle) (signing.PrivateKeyHandle, error) {
	if !handle.Valid() {
		return signing.PrivateKeyHandle{}, newSigningError(SigningErrorInvalidRequest)
	}
	return handle.value, nil
}

// String returns a constant secret-safe handle summary.
func (h PrivateKeyHandle) String() string { return "dkim2.PrivateKeyHandle{redacted}" }

// GoString returns the constant secret-safe handle Go representation.
func (h PrivateKeyHandle) GoString() string { return h.String() }

// Format routes every handle formatting form through the redacted summary.
func (h PrivateKeyHandle) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, h.String()) }

// RSASigningCredential is one immutable RSA-SHA256 public credential paired
// with an opaque private-key handle.
type RSASigningCredential struct{ value signing.Credential }

// NewRSASigningCredential validates and snapshots one RSA-SHA256 credential.
func NewRSASigningCredential(selector string, publicKey *rsa.PublicKey, handle PrivateKeyHandle) (RSASigningCredential, error) {
	value, err := signing.NewCredential(selector, signing.AlgorithmRSASHA256, publicKey, handle.value, signing.DefaultLimits())
	if err != nil {
		return RSASigningCredential{}, mapSigningError(err)
	}
	return RSASigningCredential{value: value}, nil
}

// Valid reports whether the RSA credential remains coherent.
func (c RSASigningCredential) Valid() bool {
	return c.value.Valid() && c.value.Algorithm() == signing.AlgorithmRSASHA256
}

// String returns a constant secret-safe credential summary.
func (c RSASigningCredential) String() string { return "dkim2.RSASigningCredential{redacted}" }

// GoString returns the constant secret-safe credential Go representation.
func (c RSASigningCredential) GoString() string { return c.String() }

// Format routes every credential formatting form through the redacted summary.
func (c RSASigningCredential) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// Ed25519SigningCredential is one immutable Ed25519-SHA256 public credential
// paired with an opaque private-key handle.
type Ed25519SigningCredential struct{ value signing.Credential }

// NewEd25519SigningCredential validates and snapshots one Ed25519-SHA256 credential.
func NewEd25519SigningCredential(selector string, publicKey ed25519.PublicKey, handle PrivateKeyHandle) (Ed25519SigningCredential, error) {
	value, err := signing.NewCredential(selector, signing.AlgorithmEd25519SHA256, publicKey, handle.value, signing.DefaultLimits())
	if err != nil {
		return Ed25519SigningCredential{}, mapSigningError(err)
	}
	return Ed25519SigningCredential{value: value}, nil
}

// Valid reports whether the Ed25519 credential remains coherent.
func (c Ed25519SigningCredential) Valid() bool {
	return c.value.Valid() && c.value.Algorithm() == signing.AlgorithmEd25519SHA256
}

// String returns a constant secret-safe credential summary.
func (c Ed25519SigningCredential) String() string {
	return "dkim2.Ed25519SigningCredential{redacted}"
}

// GoString returns the constant secret-safe credential Go representation.
func (c Ed25519SigningCredential) GoString() string { return c.String() }

// Format routes every credential formatting form through the redacted summary.
func (c Ed25519SigningCredential) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// SigningProfile is an immutable canonical signing domain with one or both
// baseline algorithm credentials.
type SigningProfile struct{ value signing.Profile }

// NewProjectedSigningProfile seals one already validated internal datasource
// projection for sibling command modules without rebuilding its credentials.
//
// The parameter deliberately remains an internal type: only modules inside
// this repository may cross this narrow datasource-to-signing bridge.
func NewProjectedSigningProfile(projected signing.Profile) (SigningProfile, error) {
	if !projected.Valid() {
		return SigningProfile{}, newSigningError(SigningErrorInvalidRequest)
	}
	return newSigningProfile(projected.Domain(), projected.Credentials())
}

// NewRSASigningProfile constructs a single-algorithm RSA-SHA256 profile.
func NewRSASigningProfile(domain string, credential RSASigningCredential) (SigningProfile, error) {
	return newSigningProfile(domain, []signing.Credential{credential.value})
}

// NewEd25519SigningProfile constructs a single-algorithm Ed25519-SHA256 profile.
func NewEd25519SigningProfile(domain string, credential Ed25519SigningCredential) (SigningProfile, error) {
	return newSigningProfile(domain, []signing.Credential{credential.value})
}

// NewDualSigningProfile constructs a canonical RSA-then-Ed25519 profile.
func NewDualSigningProfile(domain string, rsaCredential RSASigningCredential, ed25519Credential Ed25519SigningCredential) (SigningProfile, error) {
	return newSigningProfile(domain, []signing.Credential{rsaCredential.value, ed25519Credential.value})
}

// newSigningProfile delegates all profile invariants to the internal signing owner.
func newSigningProfile(domain string, credentials []signing.Credential) (SigningProfile, error) {
	value, err := signing.NewProfile(domain, credentials)
	if err != nil {
		return SigningProfile{}, mapSigningError(err)
	}
	return SigningProfile{value: value}, nil
}

// Valid reports whether the profile remains canonical and coherent.
func (p SigningProfile) Valid() bool { return p.value.Valid() }

// String returns a constant secret-safe profile summary.
func (p SigningProfile) String() string { return "dkim2.SigningProfile{redacted}" }

// GoString returns the constant secret-safe profile Go representation.
func (p SigningProfile) GoString() string { return p.String() }

// Format routes every profile formatting form through the redacted summary.
func (p SigningProfile) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }
