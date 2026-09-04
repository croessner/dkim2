package verify

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// KeyProvider resolves public verification keys by canonical lookup tuple.
type KeyProvider interface {
	LookupKey(context.Context, KeyQuery) (PublicKey, error)
}

// KeyQuery identifies one canonical static-key lookup.
type KeyQuery struct {
	// Domain is the canonical d= signing domain.
	Domain string
	// Selector is the canonical s= selector.
	Selector string
	// Algorithm is the canonical signature algorithm name.
	Algorithm Algorithm
}

// String returns a constant secret-safe key query summary.
func (q KeyQuery) String() string { return "verify.KeyQuery{redacted}" }

// GoString returns a constant secret-safe key query Go representation.
func (q KeyQuery) GoString() string { return q.String() }

// Format routes every query formatting form through the redacted summary.
func (q KeyQuery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, q.String()) }

// PublicKey carries provider-owned public key material and bounded metadata.
type PublicKey struct {
	// Algorithm records the algorithm the key material is intended to verify.
	Algorithm Algorithm
	// Material carries algorithm-specific public key material for later crypto slices.
	Material any
	// Metadata carries secret-safe provider classification facts.
	Metadata KeyMetadata
}

// String returns a constant secret-safe public-key result summary.
func (k PublicKey) String() string { return "verify.PublicKey{redacted}" }

// GoString returns a constant secret-safe public-key Go representation.
func (k PublicKey) GoString() string { return k.String() }

// Format routes every key formatting form through the redacted summary.
func (k PublicKey) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, k.String()) }

// KeyMetadata carries bounded key-provider facts without key bytes.
type KeyMetadata struct {
	// Status records the provider result class.
	Status KeyStatus
	// Source records a low-cardinality provider source token.
	Source string
	// Policy carries bounded DNS key declarations without raw record data.
	Policy KeyPolicyMetadata
}

// KeyPolicyMetadata carries bounded key-policy declarations across verifier boundaries.
type KeyPolicyMetadata struct {
	// TestingDeclared reports whether a DNS key record declared testing mode.
	TestingDeclared bool
	// StrictIdentityDeclared reports whether a DNS key record declared strict identity.
	StrictIdentityDeclared bool
	// StrictIdentityApplicable remains false for the active numeric DKIM2 i= grammar.
	StrictIdentityApplicable bool
}

// Valid reports whether metadata is coherent with the active DKIM2 draft.
func (m KeyPolicyMetadata) Valid() bool { return !m.StrictIdentityApplicable }

// AllowedForStatus reports whether DNS declarations may accompany one provider key status.
func (m KeyPolicyMetadata) AllowedForStatus(status KeyStatus, providerFailed bool) bool {
	if m == (KeyPolicyMetadata{}) {
		return true
	}
	if providerFailed {
		return false
	}
	switch status {
	case KeyStatusFound, KeyStatusInvalid, KeyStatusRevoked, KeyStatusUnsupportedKeyType,
		KeyStatusAlgorithmMismatch, KeyStatusWrongType, KeyStatusPolicyRejected:
		return true
	default:
		return false
	}
}

// ValidProviderSource reports whether a source is an empty or bounded low-cardinality token.
func ValidProviderSource(value string) bool {
	return value == "" || safeDiagnosticToken(value) == value
}

// Request carries current-message verification input for later coordination.
type Request struct {
	// Message is the parser-owned RFC 5322 message.
	Message rawmsg.Message
	// Envelope carries current SMTP envelope evidence.
	Envelope Envelope
	// TargetSequence selects a DKIM2-Signature i= value when non-zero.
	TargetSequence uint64
	// RequireEnvelope records whether current-envelope matching is mandatory.
	RequireEnvelope bool
	// SkipEnvelopeForNonCurrentTarget explicitly disables envelope matching for diagnostic non-current targets.
	SkipEnvelopeForNonCurrentTarget bool
	// ReferenceTime replaces the verifier clock for the Section 8.4 timestamp
	// window of the selected signature when non-zero. Callers set it when the
	// signature is evaluated relative to another authenticated instant, such as
	// an embedded original's completion signature judged against the outer
	// DSN's t=; the zero value keeps the injected clock.
	ReferenceTime time.Time
}
