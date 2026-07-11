package verify

import (
	"context"

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

// PublicKey carries provider-owned public key material and bounded metadata.
type PublicKey struct {
	// Algorithm records the algorithm the key material is intended to verify.
	Algorithm Algorithm
	// Material carries algorithm-specific public key material for later crypto slices.
	Material any
	// Metadata carries secret-safe provider classification facts.
	Metadata KeyMetadata
}

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
}
