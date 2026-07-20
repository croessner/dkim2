package signing

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

const revisionTranscriptDomain = "dkim2/revision-capability/v1"

// RevisionVerificationStatus identifies the closed dedicated revision outcome.
type RevisionVerificationStatus string

const (
	// RevisionVerificationVerified reports complete ordinary all-hop proof.
	RevisionVerificationVerified RevisionVerificationStatus = "verified"
	// RevisionVerificationTerminalNextDomainAuthorizationRequired reports clean proof ending in terminal nd=.
	RevisionVerificationTerminalNextDomainAuthorizationRequired RevisionVerificationStatus = "terminal_next_domain_authorization_required"
	// RevisionVerificationProtocolRejected reports rejected inherited protocol evidence.
	RevisionVerificationProtocolRejected RevisionVerificationStatus = "protocol_rejected"
	// RevisionVerificationUnsupported reports unsupported-only inherited evidence.
	RevisionVerificationUnsupported RevisionVerificationStatus = "unsupported"
	// RevisionVerificationProviderTemporary reports retryable key-provider failure.
	RevisionVerificationProviderTemporary RevisionVerificationStatus = "provider_temporary"
	// RevisionVerificationProviderRejected reports permanent key-provider rejection.
	RevisionVerificationProviderRejected RevisionVerificationStatus = "provider_rejected"
	// RevisionVerificationProviderContract reports an inconsistent provider contract.
	RevisionVerificationProviderContract RevisionVerificationStatus = "provider_contract"
	// RevisionVerificationLimitExceeded reports bounded verification work exhaustion.
	RevisionVerificationLimitExceeded RevisionVerificationStatus = "limit_exceeded"
)

// Known reports whether status belongs to the closed dedicated revision vocabulary.
func (s RevisionVerificationStatus) Known() bool {
	switch s {
	case RevisionVerificationVerified, RevisionVerificationTerminalNextDomainAuthorizationRequired,
		RevisionVerificationProtocolRejected, RevisionVerificationUnsupported,
		RevisionVerificationProviderTemporary, RevisionVerificationProviderRejected,
		RevisionVerificationProviderContract, RevisionVerificationLimitExceeded:
		return true
	default:
		return false
	}
}

// RevisionVerification stores one initialized closed outcome without message content.
type RevisionVerification struct {
	status      RevisionVerificationStatus
	initialized bool
}

// Valid reports whether the outcome was constructed by VerifyForRevision.
func (r RevisionVerification) Valid() bool { return r.initialized && r.status.Known() }

// Status returns the closed status or zero for an invalid outcome.
func (r RevisionVerification) Status() RevisionVerificationStatus {
	if !r.Valid() {
		return ""
	}
	return r.status
}

// String returns a constant secret-safe outcome summary.
func (r RevisionVerification) String() string { return "signing.RevisionVerification{redacted}" }

// GoString returns a constant secret-safe outcome Go representation.
func (r RevisionVerification) GoString() string { return r.String() }

// Format routes every outcome formatting form through the redacted summary.
func (r RevisionVerification) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// RevisionRequest carries exact immutable inbound evidence for dedicated revision verification.
type RevisionRequest struct {
	Message  rawmsg.Message
	Envelope verify.Envelope
}

// String returns a constant secret-safe request summary.
func (r RevisionRequest) String() string { return "signing.RevisionRequest{redacted}" }

// GoString returns a constant secret-safe request Go representation.
func (r RevisionRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r RevisionRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// VerifiedRevisionInput is an opaque sealed exact-input capability with no content accessor.
type VerifiedRevisionInput struct {
	raw            []byte
	reversePath    []byte
	forwardPaths   [][]byte
	protocolFields [][]byte
	proof          verify.RevisionProof
	seal           [sha256.Size]byte
	initialized    bool
}

// IsZero reports whether no capability state was supplied.
func (c VerifiedRevisionInput) IsZero() bool {
	return c.raw == nil && c.reversePath == nil && c.forwardPaths == nil && c.protocolFields == nil &&
		c.proof.IsZero() && c.seal == [sha256.Size]byte{} && !c.initialized
}

// Valid reports only whether the value has the structural shape of an issued capability.
func (c VerifiedRevisionInput) Valid() bool {
	return c.initialized && len(c.raw) > 0 && c.proof.Valid() && len(c.protocolFields) > 0 && c.seal != [sha256.Size]byte{}
}

// String returns a constant secret-safe capability summary.
func (c VerifiedRevisionInput) String() string { return "signing.VerifiedRevisionInput{redacted}" }

// GoString returns a constant secret-safe capability Go representation.
func (c VerifiedRevisionInput) GoString() string { return c.String() }

// Format routes every capability formatting form through the redacted summary.
func (c VerifiedRevisionInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// RevisionVerifier owns dedicated proof orchestration and one immutable sealing key.
type RevisionVerifier struct {
	verifier    verify.Verifier
	limits      Limits
	sealKey     [sha256.Size]byte
	initialized bool
}

// PreparedRevisionRevalidation is one opaque provider-free capability revalidation plan.
type PreparedRevisionRevalidation struct {
	prepared    verify.PreparedRevisionProof
	capability  VerifiedRevisionInput
	expected    [sha256.Size]byte
	initialized bool
}

// Valid reports whether the prepared capability plan is initialized.
func (p PreparedRevisionRevalidation) Valid() bool {
	return p.initialized && p.prepared.Valid() && p.capability.Valid() && p.expected != [sha256.Size]byte{}
}

// Usage returns exact repeated inherited proof work and fixed callback counts.
func (p PreparedRevisionRevalidation) Usage() verify.RevisionUsage {
	if !p.Valid() {
		return verify.RevisionUsage{}
	}
	return p.prepared.Usage()
}

// String returns a constant secret-safe prepared revalidation summary.
func (p PreparedRevisionRevalidation) String() string {
	return "signing.PreparedRevisionRevalidation{redacted}"
}

// GoString returns the constant secret-safe prepared revalidation Go representation.
func (p PreparedRevisionRevalidation) GoString() string { return p.String() }

// Format routes every prepared revalidation formatting form through the redacted summary.
func (p PreparedRevisionRevalidation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

// String returns a constant secret-safe verifier summary.
func (v RevisionVerifier) String() string { return "signing.RevisionVerifier{redacted}" }

// GoString returns a constant secret-safe verifier Go representation.
func (v RevisionVerifier) GoString() string { return v.String() }

// Format routes every verifier formatting form through the redacted summary.
func (v RevisionVerifier) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, v.String())
}

// NewRevisionVerifier constructs a dedicated revision verifier with a fresh per-instance seal key.
func NewRevisionVerifier(verifier verify.Verifier, limits Limits) (RevisionVerifier, error) {
	return newRevisionVerifier(verifier, limits, rand.Reader)
}

// newRevisionVerifier constructs a verifier from an injected entropy source for deterministic tests.
func newRevisionVerifier(verifier verify.Verifier, limits Limits, entropy io.Reader) (RevisionVerifier, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return RevisionVerifier{}, err
	}
	if !verifier.Valid() || entropy == nil || !revisionLimitsCoherent(verifier, resolved) {
		return RevisionVerifier{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	var key [sha256.Size]byte
	if _, err := io.ReadFull(entropy, key[:]); err != nil || key == [sha256.Size]byte{} {
		return RevisionVerifier{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	return RevisionVerifier{verifier: verifier, limits: resolved, sealKey: key, initialized: true}, nil
}

// revisionLimitsCoherent prevents a signing coordinator from claiming ceilings narrower than its proof engine.
func revisionLimitsCoherent(verifier verify.Verifier, limits Limits) bool {
	options := verifier.Options()
	return limits.MaxHashSetsPerInstance >= options.Limits.MaxInstanceHashSets &&
		limits.MaxSignatureSetsPerField >= options.Limits.MaxSignatureSets &&
		limits.MaxTotalSignatureSets >= options.RevisionLimits.MaxTotalSignatureSets &&
		limits.MaxPublicKeyLookups >= options.RevisionLimits.MaxPublicKeyLookups &&
		limits.MaxCanonicalWorkBytes >= options.RevisionLimits.MaxCanonicalWorkBytes &&
		limits.MaxSignatureInputBytes >= options.RevisionLimits.MaxSignatureInputBytes
}

// VerifyForRevision verifies all inherited proof and seals exact cloned input only for clean states.
func (v RevisionVerifier) VerifyForRevision(ctx context.Context, request RevisionRequest) (RevisionVerification, VerifiedRevisionInput, error) {
	if ctx == nil || !v.valid() || !request.Message.Initialized() {
		return RevisionVerification{}, VerifiedRevisionInput{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return RevisionVerification{}, VerifiedRevisionInput{}, err
	}
	if status := v.preflight(request); status != "" {
		return newRevisionVerification(status), VerifiedRevisionInput{}, nil
	}
	proofOutcome, proof, err := v.verifier.VerifyRevisionProof(ctx, verify.Request{Message: request.Message, Envelope: request.Envelope})
	if err != nil {
		return RevisionVerification{}, VerifiedRevisionInput{}, err
	}
	status, ok := mapRevisionProofOutcome(proofOutcome)
	if !ok {
		return RevisionVerification{}, VerifiedRevisionInput{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	result := newRevisionVerification(status)
	if status != RevisionVerificationVerified && status != RevisionVerificationTerminalNextDomainAuthorizationRequired {
		if proof.Valid() {
			return RevisionVerification{}, VerifiedRevisionInput{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
		}
		return result, VerifiedRevisionInput{}, nil
	}
	if !proof.Valid() || string(proof.State()) != string(proofOutcome) {
		return RevisionVerification{}, VerifiedRevisionInput{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	capability := VerifiedRevisionInput{
		raw: request.Message.RawBytes(), reversePath: request.Envelope.ReversePath(),
		forwardPaths: request.Envelope.ForwardPaths(), protocolFields: revisionProtocolFields(request.Message),
		proof: proof, initialized: true,
	}
	capability.seal = v.seal(capability)
	if !v.capabilityWithinLimits(capability) {
		return RevisionVerification{}, VerifiedRevisionInput{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	return result, capability, nil
}

// CaptureOperationInstant captures the sole verifier-owned time for one signing operation.
func (v RevisionVerifier) CaptureOperationInstant() (verify.RevisionInstant, error) {
	if !v.valid() {
		return verify.RevisionInstant{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return v.verifier.CaptureRevisionInstant()
}

// ConsumeVerifiedRevisionInput validates the capability at one newly captured instant.
func (v RevisionVerifier) ConsumeVerifiedRevisionInput(ctx context.Context, capability VerifiedRevisionInput, revised rawmsg.Message) error {
	instant, err := v.CaptureOperationInstant()
	if err != nil {
		return err
	}
	return v.ConsumeVerifiedRevisionInputAt(ctx, capability, revised, instant)
}

// ConsumeVerifiedRevisionInputAt validates exact capability state at one operation instant.
func (v RevisionVerifier) ConsumeVerifiedRevisionInputAt(ctx context.Context, capability VerifiedRevisionInput, revised rawmsg.Message, instant verify.RevisionInstant) error {
	if ctx == nil || !v.valid() || !revised.Initialized() {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.preflightRevised(revised) != "" {
		return newError(ErrorCodeLimitExceeded, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if !v.capabilityWithinLimits(capability) {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	expectedSeal := v.seal(capability)
	if subtle.ConstantTimeCompare(capability.seal[:], expectedSeal[:]) != 1 {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if !equalProtocolFields(capability.protocolFields, revisionProtocolFields(revised)) {
		return newError(ErrorCodeProtocolTampering, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	revalidated, err := v.verifier.RevalidateRevisionProofAt(ctx, capability.proof, instant)
	if err != nil {
		return err
	}
	if revalidated != verify.RevisionProofRevalidated {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return nil
}

// RevalidateForSigningAt repeats full inherited proof and exact capability binding at one instant.
func (v RevisionVerifier) RevalidateForSigningAt(ctx context.Context, capability VerifiedRevisionInput, instant verify.RevisionInstant) error {
	prepared, err := v.PrepareRevalidationForSigningAt(ctx, capability, instant)
	if err != nil {
		return err
	}
	return v.ExecuteRevalidationForSigning(ctx, prepared)
}

// PrepareRevalidationForSigningAt completes all local inherited-proof work before authority reservation.
func (v RevisionVerifier) PrepareRevalidationForSigningAt(ctx context.Context, capability VerifiedRevisionInput, instant verify.RevisionInstant) (PreparedRevisionRevalidation, error) {
	if ctx == nil || !v.valid() || !v.capabilityWithinLimits(capability) || !instant.Valid() {
		return PreparedRevisionRevalidation{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return PreparedRevisionRevalidation{}, err
	}
	expectedSeal := v.seal(capability)
	if subtle.ConstantTimeCompare(capability.seal[:], expectedSeal[:]) != 1 {
		return PreparedRevisionRevalidation{}, newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	message, err := rawmsg.Parse(capability.raw)
	if err != nil {
		return PreparedRevisionRevalidation{}, newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	envelope := verify.NewEnvelope(capability.reversePath, capability.forwardPaths)
	outcome, prepared, err := v.verifier.PrepareRevisionProofAt(ctx, verify.Request{Message: message, Envelope: envelope}, instant)
	if err != nil {
		return PreparedRevisionRevalidation{}, err
	}
	if outcome != "" || !prepared.Valid() {
		return PreparedRevisionRevalidation{}, newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	expectedUsage := capability.proof.Facts().Usage()
	actualUsage := prepared.Usage()
	if expectedUsage.ProtocolFields() != actualUsage.ProtocolFields() ||
		expectedUsage.SignatureSets() != actualUsage.SignatureSets() ||
		expectedUsage.KeyLookups() != actualUsage.KeyLookups() ||
		expectedUsage.CanonicalBytes() != actualUsage.CanonicalBytes() ||
		expectedUsage.CurrentCanonicalBytes() != actualUsage.CurrentCanonicalBytes() ||
		expectedUsage.SignatureCanonicalBytes() != actualUsage.SignatureCanonicalBytes() {
		return PreparedRevisionRevalidation{}, newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return PreparedRevisionRevalidation{
		prepared: prepared, capability: capability, expected: capability.seal, initialized: true,
	}, nil
}

// ExecuteRevalidationForSigning performs only inherited provider lookup and crypto work.
func (v RevisionVerifier) ExecuteRevalidationForSigning(ctx context.Context, prepared PreparedRevisionRevalidation) error {
	if ctx == nil || !v.valid() || !prepared.Valid() {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	outcome, proof, err := v.verifier.ExecutePreparedRevisionProof(ctx, prepared.prepared)
	if err != nil {
		return err
	}
	if outcome == "" || !proof.Valid() {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	candidate := prepared.capability
	candidate.proof = proof
	candidate.seal = [sha256.Size]byte{}
	candidate.seal = v.seal(candidate)
	if outcome != prepared.capability.proof.State() ||
		subtle.ConstantTimeCompare(prepared.expected[:], candidate.seal[:]) != 1 {
		return newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return nil
}

// preflightRevised bounds revised raw and inherited protocol shape before capability processing.
func (v RevisionVerifier) preflightRevised(message rawmsg.Message) RevisionVerificationStatus {
	metadata := message.Metadata()
	headers := message.Headers()
	protocol := revisionProtocolFields(message)
	if metadata.StoredBytes > v.limits.MaxMessageBytes || metadata.HeaderBytes > v.limits.MaxHeaderBytes ||
		metadata.HeaderFields >= v.limits.MaxHeaderFields ||
		len(protocol) >= v.limits.MaxProtocolFields ||
		len(headers.FieldsByName(signature.HeaderName)) >= v.limits.MaxSignatures {
		return RevisionVerificationLimitExceeded
	}
	for _, field := range protocol {
		if len(field) > v.limits.MaxFieldBytes || physicalLineOver(field, v.limits.MaxLineBytes) {
			return RevisionVerificationLimitExceeded
		}
	}
	return ""
}

// capabilityWithinLimits rejects malformed or oversized capability shape before transcript hashing.
func (v RevisionVerifier) capabilityWithinLimits(capability VerifiedRevisionInput) bool {
	inboundRecipients := v.verifier.Options().Limits.MaxEnvelopeRecipients
	if !capability.Valid() || len(capability.raw) > v.limits.MaxMessageBytes || len(capability.protocolFields) > v.limits.MaxProtocolFields || len(capability.forwardPaths) > inboundRecipients {
		return false
	}
	if capability.reversePath == nil && len(capability.forwardPaths) == 0 {
		if capability.proof.State() != verify.RevisionProofTerminalNextDomainAuthorizationRequired {
			return false
		}
	} else {
		if !signature.ValidEnvelopePath(capability.reversePath, true) {
			return false
		}
		if len(capability.forwardPaths) == 0 {
			return false
		}
		for _, path := range capability.forwardPaths {
			if !signature.ValidEnvelopePath(path, false) {
				return false
			}
		}
	}
	for _, field := range capability.protocolFields {
		if len(field) == 0 || len(field) > v.limits.MaxFieldBytes || physicalLineOver(field, v.limits.MaxLineBytes) {
			return false
		}
	}
	facts := capability.proof.Facts()
	usage := facts.Usage()
	return facts.Valid() && len(capability.protocolFields) == usage.ProtocolFields() && facts.InstanceCount() <= v.limits.MaxInstances && facts.SignatureCount() <= v.limits.MaxSignatures &&
		usage.SignatureSets() <= v.limits.MaxTotalSignatureSets && usage.KeyLookups() <= v.limits.MaxPublicKeyLookups && usage.CanonicalBytes() <= v.limits.MaxCanonicalWorkBytes
}

// physicalLineOver reports whether exact field bytes exceed the signing line ceiling.
func physicalLineOver(field []byte, limit int) bool {
	start := 0
	for index := 0; index+1 < len(field); index++ {
		if field[index] == '\r' && field[index+1] == '\n' {
			if index-start > limit {
				return true
			}
			start = index + 2
			index++
		}
	}
	return len(field)-start > limit
}

// valid reports whether the coordinator owns coherent immutable dependencies.
func (v RevisionVerifier) valid() bool {
	return v.initialized && v.verifier.Valid() && v.limits.Validate() == nil && v.sealKey != [sha256.Size]byte{}
}

// preflight bounds exact input before any key-provider callback.
func (v RevisionVerifier) preflight(request RevisionRequest) RevisionVerificationStatus {
	metadata := request.Message.Metadata()
	if metadata.StoredBytes > v.limits.MaxMessageBytes || metadata.HeaderBytes > v.limits.MaxHeaderBytes ||
		metadata.HeaderFields > v.limits.MaxHeaderFields {
		return RevisionVerificationLimitExceeded
	}
	headers := request.Message.Headers()
	protocol := revisionProtocolFields(request.Message)
	if len(protocol) >= v.limits.MaxProtocolFields || len(headers.FieldsByName(instance.HeaderName)) > v.limits.MaxInstances ||
		len(headers.FieldsByName(signature.HeaderName)) >= v.limits.MaxSignatures ||
		request.Envelope.RecipientCount() > v.verifier.Options().Limits.MaxEnvelopeRecipients {
		return RevisionVerificationLimitExceeded
	}
	for _, field := range protocol {
		if len(field) > v.limits.MaxFieldBytes || physicalLineOver(field, v.limits.MaxLineBytes) {
			return RevisionVerificationLimitExceeded
		}
	}
	return ""
}

// newRevisionVerification constructs one closed initialized result.
func newRevisionVerification(status RevisionVerificationStatus) RevisionVerification {
	if !status.Known() {
		return RevisionVerification{}
	}
	return RevisionVerification{status: status, initialized: true}
}

// mapRevisionProofOutcome maps the one narrow verify-owned seam exhaustively.
func mapRevisionProofOutcome(outcome verify.RevisionProofOutcome) (RevisionVerificationStatus, bool) {
	switch outcome {
	case verify.RevisionProofVerified:
		return RevisionVerificationVerified, true
	case verify.RevisionProofTerminalNextDomainAuthorizationRequired:
		return RevisionVerificationTerminalNextDomainAuthorizationRequired, true
	case verify.RevisionProofProtocolRejected:
		return RevisionVerificationProtocolRejected, true
	case verify.RevisionProofUnsupported:
		return RevisionVerificationUnsupported, true
	case verify.RevisionProofProviderTemporary:
		return RevisionVerificationProviderTemporary, true
	case verify.RevisionProofProviderRejected:
		return RevisionVerificationProviderRejected, true
	case verify.RevisionProofProviderContract:
		return RevisionVerificationProviderContract, true
	case verify.RevisionProofLimitExceeded:
		return RevisionVerificationLimitExceeded, true
	default:
		return "", false
	}
}

// revisionProtocolFields returns inherited protocol fields in exact occurrence order and encoding.
func revisionProtocolFields(message rawmsg.Message) [][]byte {
	fields := message.Headers().Fields()
	protocol := make([][]byte, 0)
	for _, field := range fields {
		if field.NameLower() == strings.ToLower(instance.HeaderName) || field.NameLower() == strings.ToLower(signature.HeaderName) {
			protocol = append(protocol, field.OriginalBytes())
		}
	}
	return protocol
}

// equalProtocolFields compares exact inherited bytes, order, occurrence, case, and folding.
func equalProtocolFields(expected, actual [][]byte) bool {
	if len(expected) != len(actual) {
		return false
	}
	for index := range expected {
		if len(expected[index]) != len(actual[index]) || subtle.ConstantTimeCompare(expected[index], actual[index]) != 1 {
			return false
		}
	}
	return true
}

// seal authenticates one exact versioned domain-separated transcript.
func (v RevisionVerifier) seal(capability VerifiedRevisionInput) [sha256.Size]byte {
	mac := hmac.New(sha256.New, v.sealKey[:])
	transcript := newRevisionTranscript(mac)
	transcript.addBytes("raw", capability.raw != nil, capability.raw)
	transcript.addBytes("reverse_path", capability.reversePath != nil, capability.reversePath)
	transcript.addCount("forward_path_count", len(capability.forwardPaths))
	for _, path := range capability.forwardPaths {
		transcript.addBytes("forward_path", path != nil, path)
	}
	transcript.addCount("protocol_field_count", len(capability.protocolFields))
	for _, field := range capability.protocolFields {
		transcript.addBytes("protocol_field", true, field)
	}
	transcript.addBytes("draft", true, []byte(capability.proof.Draft()))
	transcript.addBytes("capability_state", true, []byte(capability.proof.State()))
	facts := capability.proof.Facts()
	transcript.addUint64("highest_sequence", facts.HighestSequence())
	transcript.addUint64("highest_instance", facts.HighestInstance())
	transcript.addCount("instance_count", facts.InstanceCount())
	transcript.addCount("signature_count", facts.SignatureCount())
	signatures := facts.Signatures()
	transcript.addCount("signature_fact_count", len(signatures))
	for _, fact := range signatures {
		transcript.addUint64("signature_sequence", fact.Sequence())
		transcript.addUint64("signature_instance", fact.Instance())
		transcript.addUint64("signature_timestamp", fact.Timestamp())
		transcript.addBool("donotmodify", fact.Flags().DoNotModify())
		transcript.addBool("donotexplode", fact.Flags().DoNotExplode())
		transcript.addBool("feedback", fact.Flags().Feedback())
		transcript.addBool("feedhere", fact.Flags().FeedHere())
		transcript.addBool("exploded", fact.Flags().Exploded())
		sets := fact.Sets()
		transcript.addCount("signature_set_count", len(sets))
		for _, set := range sets {
			transcript.addCount("signature_set_index", set.Index())
			transcript.addBytes("signature_set_algorithm", true, []byte(set.Algorithm()))
			transcript.addBytes("signature_set_state", true, []byte(set.State()))
		}
	}
	hashes := facts.Hashes()
	transcript.addUint64("hash_instance", hashes.Instance())
	headerDigest, bodyDigest := hashes.HeaderDigest(), hashes.BodyDigest()
	transcript.addBytes("header_sha256_pass", true, headerDigest[:])
	transcript.addBytes("body_sha256_pass", true, bodyDigest[:])
	transcript.addBytes("current_envelope", true, []byte(facts.Envelope()))
	custody := facts.Custody()
	transcript.addBytes("custody_status", true, []byte(custody.Status()))
	transcript.addBool("custody_had_nd", custody.HadNextDomain())
	hops := custody.Hops()
	transcript.addCount("custody_hop_count", len(hops))
	for _, hop := range hops {
		transcript.addUint64("custody_sequence", hop.Sequence())
		transcript.addBytes("custody_direct", true, []byte(hop.Direct()))
		transcript.addBytes("custody_link", true, []byte(hop.Link()))
	}
	history := facts.History()
	transcript.addBytes("history_coverage", true, []byte(history.Coverage()))
	transcript.addBytes("history_stop", true, []byte(history.Stop()))
	transcript.addUint64("history_target", history.Target())
	transcript.addUint64("history_reached", history.Reached())
	transcript.addBool("history_body_unavailable", history.HasUnavailableBody())
	transitions := history.Transitions()
	transcript.addCount("history_transition_count", len(transitions))
	for _, transition := range transitions {
		transcript.addUint64("history_from", transition.From())
		transcript.addUint64("history_to", transition.To())
		transcript.addBytes("history_mode", true, []byte(transition.Mode()))
		transcript.addBytes("history_header", true, []byte(transition.Header()))
		transcript.addBytes("history_body", true, []byte(transition.Body()))
	}
	addHistoryUsage(&transcript, "history", history.Usage())
	usage := facts.Usage()
	transcript.addCount("usage_protocol_fields", usage.ProtocolFields())
	transcript.addCount("usage_signature_sets", usage.SignatureSets())
	transcript.addCount("usage_key_lookups", usage.KeyLookups())
	transcript.addCount("usage_provider_calls", usage.ProviderCalls())
	transcript.addCount("usage_canonical_bytes", usage.CanonicalBytes())
	transcript.addCount("usage_current_canonical_bytes", usage.CurrentCanonicalBytes())
	transcript.addCount("usage_signature_canonical_bytes", usage.SignatureCanonicalBytes())
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// addHistoryUsage binds bounded recipe/history usage under one label prefix.
func addHistoryUsage(transcript *revisionTranscript, prefix string, usage verify.HistoryUsage) {
	transcript.addCount(prefix+"_decoded_bytes", usage.DecodedBytes())
	transcript.addCount(prefix+"_emitted_bytes", usage.EmittedBytes())
	transcript.addCount(prefix+"_items", usage.Items())
	transcript.addCount(prefix+"_work_units", usage.WorkUnits())
	transcript.addCount(prefix+"_canonical_bytes", usage.CanonicalBytes())
}

type revisionTranscript struct{ writer hash.Hash }

// newRevisionTranscript starts one explicit versioned domain-separated transcript.
func newRevisionTranscript(writer hash.Hash) revisionTranscript {
	transcript := revisionTranscript{writer: writer}
	transcript.addBytes("domain", true, []byte(revisionTranscriptDomain))
	return transcript
}

// addBytes adds label, presence, and byte length before value bytes.
func (t *revisionTranscript) addBytes(label string, present bool, value []byte) {
	t.addLengthPrefixed([]byte(label))
	presence := []byte{0}
	if present {
		presence[0] = 1
	}
	_, _ = t.writer.Write(presence)
	t.addLengthPrefixed(value)
}

// addCount adds a nonnegative collection count under an explicit label.
func (t *revisionTranscript) addCount(label string, count int) {
	if count < 0 {
		count = 0
	}
	t.addUint64(label, uint64(count))
}

// addUint64 adds one fixed-width unsigned fact under an explicit label.
func (t *revisionTranscript) addUint64(label string, value uint64) {
	t.addLengthPrefixed([]byte(label))
	_, _ = t.writer.Write([]byte{1})
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	t.addLengthPrefixed(encoded[:])
}

// addBool adds one explicit boolean fact under an explicit label.
func (t *revisionTranscript) addBool(label string, value bool) {
	encoded := byte(0)
	if value {
		encoded = 1
	}
	t.addBytes(label, true, []byte{encoded})
}

// addLengthPrefixed appends one uint64 length followed by exact bytes.
func (t *revisionTranscript) addLengthPrefixed(value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = t.writer.Write(size[:])
	_, _ = t.writer.Write(value)
}
