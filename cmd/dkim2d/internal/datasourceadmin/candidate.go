package datasourceadmin

import (
	"context"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
	"sync"
)

// OperationBinding is one protected canonical 128-bit operation identity.
type OperationBinding struct{ value string }

// NewOperationBinding validates and owns one canonical operation identity.
func NewOperationBinding(value string) (OperationBinding, error) {
	if !validOperationID(value) {
		return OperationBinding{}, newError(CodeInvalid)
	}
	return OperationBinding{value: value}, nil
}

// Equal reports whether two initialized operation bindings are identical.
func (b OperationBinding) Equal(other OperationBinding) bool {
	return validOperationID(b.value) && validOperationID(other.value) &&
		subtle.ConstantTimeCompare([]byte(b.value), []byte(other.value)) == 1
}

// Initialized reports whether the binding contains one canonical operation identity.
func (b OperationBinding) Initialized() bool { return validOperationID(b.value) }

// WithValue supplies the canonical operation value only to a bounded provider callback.
func (b OperationBinding) WithValue(ctx context.Context, use func(string) error) error {
	if ctx == nil || use == nil || ctx.Err() != nil || !validOperationID(b.value) {
		return newError(CodeInvalid)
	}
	if err := use(b.value); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// String returns a constant protected operation-binding representation.
func (OperationBinding) String() string { return redacted }

// GoString returns a constant protected operation-binding representation.
func (OperationBinding) GoString() string { return redacted }

// Format prevents operation identity from reaching formatting sinks.
func (OperationBinding) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected operation-binding serialization.
func (OperationBinding) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// CandidateContent owns one immutable version-neutral generation.
type CandidateContent struct {
	mu       sync.Mutex
	snapshot *Snapshot
	closed   bool
}

// NewCandidateContent takes ownership of one complete v2 or v3 snapshot.
func NewCandidateContent(snapshot *Snapshot) (*CandidateContent, error) {
	if snapshot == nil ||
		(snapshot.SchemaVersion() != SchemaVersionV2 && snapshot.SchemaVersion() != SchemaVersionV3) {
		return nil, newError(CodeInvalid)
	}
	return &CandidateContent{snapshot: snapshot}, nil
}

// validOperationID accepts exactly one nonzero lower-case base32 128-bit value.
func validOperationID(value string) bool {
	if len(value) != 26 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(value))
	if err != nil || len(decoded) != 16 {
		clear(decoded)
		return false
	}
	var combined byte
	for _, octet := range decoded {
		combined |= octet
	}
	canonical := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded))
	clear(decoded)
	return combined != 0 && canonical == value
}

// Generation returns the candidate generation or zero after close.
func (c *CandidateContent) Generation() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0
	}
	return c.snapshot.Generation()
}

// schemaVersion returns the owned schema only inside the administration package.
func (c *CandidateContent) schemaVersion() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.snapshot == nil {
		return ""
	}
	return c.snapshot.SchemaVersion()
}

// WithRows supplies a detached projection outside the candidate owner lock.
func (c *CandidateContent) WithRows(ctx context.Context, use func(Rows) error) error {
	if c == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeInvalid)
	}
	c.mu.Lock()
	if c.closed || c.snapshot == nil {
		c.mu.Unlock()
		return newError(CodeInvalid)
	}
	snapshot := c.snapshot
	c.mu.Unlock()
	return snapshot.WithRows(ctx, use)
}

// Close erases and releases all candidate state.
func (c *CandidateContent) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	snapshot := c.snapshot
	c.snapshot = nil
	c.closed = true
	c.mu.Unlock()
	if snapshot != nil {
		_ = snapshot.Close()
	}
	return nil
}

// String returns a constant protected candidate representation.
func (*CandidateContent) String() string { return redacted }

// GoString returns a constant protected candidate representation.
func (*CandidateContent) GoString() string { return redacted }

// Format prevents formatting verbs from exposing candidate content.
func (*CandidateContent) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected candidate serialization.
func (*CandidateContent) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// PublicationEnvelope owns one operation-bound v3 candidate and its immutable digest.
type PublicationEnvelope struct {
	mu               sync.Mutex
	operation        OperationBinding
	sourceGeneration uint64
	content          *CandidateContent
	digest           CandidateContentDigest
	closed           bool
}

// NewPublicationEnvelope takes content ownership on success and leaves rejected content caller-owned.
func NewPublicationEnvelope(operation string, content *CandidateContent) (*PublicationEnvelope, error) {
	return newPublicationEnvelope(operation, 0, content)
}

// NewCampaignPublicationEnvelope binds a new campaign candidate to its exact
// frozen source generation. The source is immutable and part of the digest.
func NewCampaignPublicationEnvelope(operation string, sourceGeneration uint64, content *CandidateContent) (*PublicationEnvelope, error) {
	if sourceGeneration == 0 || content == nil || content.Generation() <= sourceGeneration {
		return nil, newError(CodeInvalid)
	}
	return newPublicationEnvelope(operation, sourceGeneration, content)
}

func newPublicationEnvelope(operation string, sourceGeneration uint64, content *CandidateContent) (*PublicationEnvelope, error) {
	binding, bindingErr := NewOperationBinding(operation)
	if bindingErr != nil || content == nil || content.schemaVersion() != SchemaVersionV3 {
		return nil, newError(CodeInvalid)
	}
	generation := content.Generation()
	var digest CandidateContentDigest
	err := content.WithRows(context.Background(), func(rows Rows) error {
		if sourceGeneration == 0 {
			digest = digestCandidate(SchemaVersionV3, generation, binding.value, rows)
		} else {
			digest = digestCampaignCandidate(SchemaVersionV3, sourceGeneration, generation, binding.value, rows)
		}
		return nil
	})
	if err != nil || !digest.Valid() {
		return nil, newError(CodeInvalid)
	}
	return &PublicationEnvelope{operation: binding, sourceGeneration: sourceGeneration, content: content, digest: digest}, nil
}

// SourceGeneration returns the immutable frozen source generation, or zero
// for legacy v3 envelopes that must remain unknown/retained.
func (e *PublicationEnvelope) SourceGeneration() uint64 {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.content == nil {
		return 0
	}
	return e.sourceGeneration
}

// Generation returns the candidate generation or zero after close.
func (e *PublicationEnvelope) Generation() uint64 {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.content == nil {
		return 0
	}
	return e.content.Generation()
}

// Digest returns the protected operation-bound content identity.
func (e *PublicationEnvelope) Digest() CandidateContentDigest {
	if e == nil {
		return CandidateContentDigest{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.content == nil {
		return CandidateContentDigest{}
	}
	return e.digest
}

// Binding returns the immutable operation binding or its zero value after close.
func (e *PublicationEnvelope) Binding() OperationBinding {
	if e == nil {
		return OperationBinding{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.content == nil {
		return OperationBinding{}
	}
	return e.operation
}

// WithMetadata supplies protected operation and digest metadata to a bounded provider callback.
func (e *PublicationEnvelope) WithMetadata(
	ctx context.Context,
	use func(OperationBinding, uint64, CandidateContentDigest) error,
) error {
	if e == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeInvalid)
	}
	e.mu.Lock()
	if e.closed || e.content == nil {
		e.mu.Unlock()
		return newError(CodeInvalid)
	}
	operation, source, digest := e.operation, e.sourceGeneration, e.digest
	e.mu.Unlock()
	if err := use(operation, source, digest); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// PreparedEvidence returns the phase-specific pre-stage digest evidence.
func (e *PublicationEnvelope) PreparedEvidence() PreparedEvidence {
	return PreparedEvidence{digest: e.Digest()}
}

// WithRows supplies a detached candidate projection outside the envelope lock.
func (e *PublicationEnvelope) WithRows(ctx context.Context, use func(Rows) error) error {
	if e == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeInvalid)
	}
	e.mu.Lock()
	if e.closed || e.content == nil {
		e.mu.Unlock()
		return newError(CodeInvalid)
	}
	content := e.content
	e.mu.Unlock()
	return content.WithRows(ctx, use)
}

// Close erases and releases the operation envelope and neutral content.
func (e *PublicationEnvelope) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	content := e.content
	e.content = nil
	e.operation = OperationBinding{}
	e.sourceGeneration = 0
	e.digest = CandidateContentDigest{}
	e.closed = true
	e.mu.Unlock()
	if content != nil {
		return content.Close()
	}
	return nil
}

// String returns a constant protected publication-envelope representation.
func (*PublicationEnvelope) String() string { return redacted }

// GoString returns a constant protected publication-envelope representation.
func (*PublicationEnvelope) GoString() string { return redacted }

// Format prevents formatting verbs from exposing publication metadata or content.
func (*PublicationEnvelope) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected publication-envelope serialization.
func (*PublicationEnvelope) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// PreparedEvidence is the pre-stage candidate-content phase.
type PreparedEvidence struct{ digest CandidateContentDigest }

// StagedEvidence is the canonical backend-readback phase.
type StagedEvidence struct{ digest CandidateContentDigest }

// ParsePreparedEvidence validates one exact stored prepared candidate digest.
func ParsePreparedEvidence(value []byte) (PreparedEvidence, error) {
	digest, err := ParseCandidateContentDigest(value)
	if err != nil {
		return PreparedEvidence{}, err
	}
	return PreparedEvidence{digest: digest}, nil
}

// NewStagedEvidence constructs exact canonical backend-readback evidence.
func NewStagedEvidence(digest CandidateContentDigest) StagedEvidence {
	return StagedEvidence{digest: digest}
}

// Matches proves prepared and staged phases carry equal content bytes.
func (p PreparedEvidence) Matches(staged StagedEvidence) bool {
	return p.digest.Valid() && staged.digest.Valid() && p.digest.Equal(staged.digest)
}

// Digest returns the protected prepared candidate-content identity.
func (p PreparedEvidence) Digest() CandidateContentDigest { return p.digest }

// Digest returns the protected staged readback candidate-content identity.
func (s StagedEvidence) Digest() CandidateContentDigest { return s.digest }

// ParseStagedEvidence validates one exact stored canonical readback digest.
func ParseStagedEvidence(value []byte) (StagedEvidence, error) {
	digest, err := ParseCandidateContentDigest(value)
	if err != nil {
		return StagedEvidence{}, err
	}
	return NewStagedEvidence(digest), nil
}

// String returns a constant protected prepared-evidence representation.
func (PreparedEvidence) String() string { return redacted }

// GoString returns a constant protected prepared-evidence representation.
func (PreparedEvidence) GoString() string { return redacted }

// Format prevents prepared evidence from reaching formatting sinks.
func (PreparedEvidence) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected prepared-evidence serialization.
func (PreparedEvidence) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected staged-evidence representation.
func (StagedEvidence) String() string { return redacted }

// GoString returns a constant protected staged-evidence representation.
func (StagedEvidence) GoString() string { return redacted }

// Format prevents staged evidence from reaching formatting sinks.
func (StagedEvidence) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected staged-evidence serialization.
func (StagedEvidence) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }
