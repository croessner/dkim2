package dkim2

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/service"
)

// DraftIdentifier identifies the exact DKIM2 behavior baseline implemented by this verification facade.
const DraftIdentifier = "draft-ietf-dkim-dkim2-spec-05"

// ResultState identifies one of the four public DKIM2 verification outcomes.
type ResultState string

const (
	// ResultStatePASS reports complete success for the declared authenticated scope.
	ResultStatePASS ResultState = "PASS"
	// ResultStateFAIL reports a supported integrity mismatch.
	ResultStateFAIL ResultState = "FAIL"
	// ResultStatePERMERROR reports unrecoverable malformed, missing, unsupported, or ambiguous state.
	ResultStatePERMERROR ResultState = "PERMERROR"
	// ResultStateTEMPERROR reports a typed temporary public-key-provider failure.
	ResultStateTEMPERROR ResultState = "TEMPERROR"
)

// Known reports whether the result state belongs to the closed four-state vocabulary.
func (s ResultState) Known() bool {
	switch s {
	case ResultStatePASS, ResultStateFAIL, ResultStatePERMERROR, ResultStateTEMPERROR:
		return true
	default:
		return false
	}
}

// VerificationScope identifies which message state was verified.
type VerificationScope string

const (
	// VerificationScopeCurrent limits the result to the highest current signature and instance.
	VerificationScopeCurrent VerificationScope = "current"
	// VerificationScopeChain reports authenticated verification through every inherited revision.
	VerificationScopeChain VerificationScope = "chain"
)

// Known reports whether the scope belongs to the closed public vocabulary.
func (s VerificationScope) Known() bool {
	return s == VerificationScopeCurrent || s == VerificationScopeChain
}

// HistoricalState identifies whether one historical verification dimension was evaluated.
type HistoricalState string

const (
	// HistoricalStateNotEvaluated reports that the historical dimension was not evaluated.
	HistoricalStateNotEvaluated HistoricalState = "not_evaluated"
	// HistoricalStateComplete reports authenticated coverage through the origin.
	HistoricalStateComplete HistoricalState = "complete"
	// HistoricalStatePartial reports authenticated coverage with an explicit unavailable body.
	HistoricalStatePartial HistoricalState = "partial"
)

// Known reports whether the historical state belongs to the closed public vocabulary.
func (s HistoricalState) Known() bool {
	return s == HistoricalStateNotEvaluated || s == HistoricalStateComplete || s == HistoricalStatePartial
}

// CustodyStructure identifies the separately evaluated structural next-domain coverage.
type CustodyStructure string

const (
	// CustodyStructureNotEvaluated reports that earlier failure prevented reliable next-domain presence detection.
	CustodyStructureNotEvaluated CustodyStructure = "not_evaluated"
	// CustodyStructureNotPresent reports that no next-domain link was present.
	CustodyStructureNotPresent CustodyStructure = "not_present"
	// CustodyStructureNDLinksEvaluated reports that one or more intermediate next-domain links were evaluated.
	CustodyStructureNDLinksEvaluated CustodyStructure = "nd_links_evaluated"
	// CustodyStructureTerminalNDRequiresOOB reports that the current terminal next-domain needs unmodeled OOB trust.
	CustodyStructureTerminalNDRequiresOOB CustodyStructure = "terminal_nd_requires_oob"
)

// Known reports whether the custody structure belongs to the closed public vocabulary.
func (s CustodyStructure) Known() bool {
	switch s {
	case CustodyStructureNotEvaluated, CustodyStructureNotPresent, CustodyStructureNDLinksEvaluated, CustodyStructureTerminalNDRequiresOOB:
		return true
	default:
		return false
	}
}

// CheckClass identifies a bounded verification concern without exposing message-derived values.
type CheckClass string

const (
	// CheckClassMessage identifies raw message handling.
	CheckClassMessage CheckClass = "message"
	// CheckClassProtocol identifies DKIM2 field and sequence handling.
	CheckClassProtocol CheckClass = "protocol"
	// CheckClassBodyHash identifies current body-hash verification.
	CheckClassBodyHash CheckClass = "body_hash"
	// CheckClassHeaderHash identifies current header-hash verification.
	CheckClassHeaderHash CheckClass = "header_hash"
	// CheckClassSignature identifies cryptographic signature verification.
	CheckClassSignature CheckClass = "signature"
	// CheckClassKey identifies public-key validity or availability.
	CheckClassKey CheckClass = "key"
	// CheckClassTimestamp identifies timestamp policy evaluation.
	CheckClassTimestamp CheckClass = "timestamp"
	// CheckClassEnvelope identifies current SMTP envelope comparison.
	CheckClassEnvelope CheckClass = "envelope"
	// CheckClassDomainAlignment identifies signing-domain alignment.
	CheckClassDomainAlignment CheckClass = "domain_alignment"
	// CheckClassNextDomain identifies structural next-domain evaluation.
	CheckClassNextDomain CheckClass = "next_domain"
	// CheckClassProvider identifies public-key-provider behavior.
	CheckClassProvider CheckClass = "provider"
	// CheckClassInternalContract identifies an unknown or inconsistent internal fact.
	CheckClassInternalContract CheckClass = "internal_contract"
)

// Known reports whether the check class belongs to the closed public vocabulary.
func (c CheckClass) Known() bool {
	switch c {
	case CheckClassMessage, CheckClassProtocol, CheckClassBodyHash, CheckClassHeaderHash,
		CheckClassSignature, CheckClassKey, CheckClassTimestamp, CheckClassEnvelope,
		CheckClassDomainAlignment, CheckClassNextDomain, CheckClassProvider, CheckClassInternalContract:
		return true
	default:
		return false
	}
}

// ReasonCode identifies a bounded verification reason without retaining raw causes or input.
type ReasonCode string

const (
	// ReasonNone reports no failure reason for a successful fact.
	ReasonNone ReasonCode = "none"
	// ReasonInvalidRequest reports invalid public request state.
	ReasonInvalidRequest ReasonCode = "invalid_request"
	// ReasonLimitExceeded reports a configured resource limit violation.
	ReasonLimitExceeded ReasonCode = "limit_exceeded"
	// ReasonMalformedMessage reports malformed RFC 5322 input.
	ReasonMalformedMessage ReasonCode = "malformed_message"
	// ReasonMalformedProtocol reports malformed DKIM2 protocol input.
	ReasonMalformedProtocol ReasonCode = "malformed_protocol"
	// ReasonDuplicateHashAlgorithm reports any repeated h= algorithm name.
	ReasonDuplicateHashAlgorithm ReasonCode = "duplicate_hash_algorithm"
	// ReasonInvalidRecipeJSON reports malformed authenticated recipe JSON.
	ReasonInvalidRecipeJSON ReasonCode = "invalid_recipe_json"
	// ReasonDuplicateSelector reports a repeated selector in one signature field.
	ReasonDuplicateSelector ReasonCode = "duplicate_selector"
	// ReasonTooManySignatures reports a third signature occurrence for one algorithm.
	ReasonTooManySignatures ReasonCode = "too_many_signatures"
	// ReasonMissingProtocol reports required DKIM2 protocol state is absent.
	ReasonMissingProtocol ReasonCode = "missing_protocol"
	// ReasonSequenceInvalid reports invalid instance or signature numbering.
	ReasonSequenceInvalid ReasonCode = "sequence_invalid"
	// ReasonUnsupportedAlgorithm reports that no required supported algorithm was checkable.
	ReasonUnsupportedAlgorithm ReasonCode = "unsupported_algorithm"
	// ReasonHashMismatch reports a supported current-message hash mismatch.
	ReasonHashMismatch ReasonCode = "hash_mismatch"
	// ReasonSignatureMismatch reports a supported cryptographic signature mismatch.
	ReasonSignatureMismatch ReasonCode = "signature_mismatch"
	// ReasonMissingKey reports that required public-key material is absent.
	ReasonMissingKey ReasonCode = "missing_key"
	// ReasonInvalidKey reports invalid public-key material.
	ReasonInvalidKey ReasonCode = "invalid_key"
	// ReasonAmbiguousKey reports ambiguous public-key material.
	ReasonAmbiguousKey ReasonCode = "ambiguous_key"
	// ReasonRevokedKey reports an explicitly revoked DNS public key.
	ReasonRevokedKey ReasonCode = "revoked_key"
	// ReasonUnsupportedKeyType reports an unsupported DNS key type.
	ReasonUnsupportedKeyType ReasonCode = "unsupported_key_type"
	// ReasonKeyAlgorithmMismatch reports disagreement between requested algorithm and DNS key type.
	ReasonKeyAlgorithmMismatch ReasonCode = "key_algorithm_mismatch"
	// ReasonProviderTemporary reports a typed temporary provider failure.
	ReasonProviderTemporary ReasonCode = "provider_temporary"
	// ReasonProviderPermanent reports a typed permanent provider failure.
	ReasonProviderPermanent ReasonCode = "provider_permanent"
	// ReasonProviderContract reports an inconsistent or unclassified provider outcome.
	ReasonProviderContract ReasonCode = "provider_contract"
	// ReasonTimestampInvalid reports an expired, future, or unrepresentable timestamp.
	ReasonTimestampInvalid ReasonCode = "timestamp_invalid"
	// ReasonEnvelopeMismatch reports current SMTP envelope disagreement.
	ReasonEnvelopeMismatch ReasonCode = "envelope_mismatch"
	// ReasonDomainAlignmentMismatch reports signing-domain alignment failure.
	ReasonDomainAlignmentMismatch ReasonCode = "domain_alignment_mismatch"
	// ReasonNextDomainMismatch reports structural next-domain disagreement.
	ReasonNextDomainMismatch ReasonCode = "next_domain_mismatch"
	// ReasonOutOfBandRequired reports a terminal next-domain requiring unmodeled OOB trust.
	ReasonOutOfBandRequired ReasonCode = "out_of_band_required"
	// ReasonInternalContract reports an unknown or inconsistent internal fact.
	ReasonInternalContract ReasonCode = "internal_contract"
)

// Known reports whether the reason belongs to the closed public vocabulary.
func (r ReasonCode) Known() bool {
	switch r {
	case ReasonNone, ReasonInvalidRequest, ReasonLimitExceeded, ReasonMalformedMessage,
		ReasonMalformedProtocol, ReasonDuplicateHashAlgorithm, ReasonInvalidRecipeJSON,
		ReasonDuplicateSelector, ReasonTooManySignatures, ReasonMissingProtocol, ReasonSequenceInvalid,
		ReasonUnsupportedAlgorithm, ReasonHashMismatch, ReasonSignatureMismatch,
		ReasonMissingKey, ReasonInvalidKey, ReasonAmbiguousKey, ReasonRevokedKey, ReasonUnsupportedKeyType, ReasonKeyAlgorithmMismatch, ReasonProviderTemporary,
		ReasonProviderPermanent, ReasonProviderContract, ReasonTimestampInvalid,
		ReasonEnvelopeMismatch, ReasonDomainAlignmentMismatch, ReasonNextDomainMismatch,
		ReasonOutOfBandRequired, ReasonInternalContract:
		return true
	default:
		return false
	}
}

// SignatureStatus identifies a bounded per-signature-set outcome.
type SignatureStatus string

const (
	// SignatureStatusPASS reports a supported passing signature set.
	SignatureStatusPASS SignatureStatus = "pass"
	// SignatureStatusFAIL reports a supported failing signature set.
	SignatureStatusFAIL SignatureStatus = "fail"
	// SignatureStatusPERMERROR reports permanent key or protocol state for the set.
	SignatureStatusPERMERROR SignatureStatus = "permerror"
	// SignatureStatusTEMPERROR reports typed temporary provider state for the set.
	SignatureStatusTEMPERROR SignatureStatus = "temperror"
	// SignatureStatusIgnored reports an unknown algorithm ignored during aggregation.
	SignatureStatusIgnored SignatureStatus = "ignored"
)

// Known reports whether the signature status belongs to the closed public vocabulary.
func (s SignatureStatus) Known() bool {
	switch s {
	case SignatureStatusPASS, SignatureStatusFAIL, SignatureStatusPERMERROR, SignatureStatusTEMPERROR, SignatureStatusIgnored:
		return true
	default:
		return false
	}
}

// VerificationTarget identifies the current signature sequence and Message-Instance number.
type VerificationTarget struct {
	state *verificationTargetState
}

type verificationTargetState struct {
	sequence uint64
	instance uint64
}

const verificationTargetRedactedText = "dkim2.VerificationTarget{redacted}"

// newVerificationTarget constructs immutable bounded target metadata.
func newVerificationTarget(sequence, instance uint64) VerificationTarget {
	if sequence == 0 && instance == 0 {
		return VerificationTarget{}
	}
	return VerificationTarget{state: &verificationTargetState{sequence: sequence, instance: instance}}
}

// Sequence returns the target DKIM2-Signature sequence number.
func (t VerificationTarget) Sequence() uint64 {
	if t.state == nil {
		return 0
	}
	return t.state.sequence
}

// Instance returns the target Message-Instance number.
func (t VerificationTarget) Instance() uint64 {
	if t.state == nil {
		return 0
	}
	return t.state.instance
}

// isZero reports whether no target state is present.
func (t VerificationTarget) isZero() bool {
	return t.state == nil || t.state.sequence == 0 && t.state.instance == 0
}

// String returns a constant representation without sequence identifiers.
func (VerificationTarget) String() string { return verificationTargetRedactedText }

// GoString returns a constant representation without sequence identifiers.
func (VerificationTarget) GoString() string { return verificationTargetRedactedText }

// Format prevents formatting from traversing sequence identifiers.
func (VerificationTarget) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, verificationTargetRedactedText)
}

// MarshalJSON rejects serialization outside explicit mapped response boundaries.
func (VerificationTarget) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of sequence identifiers.
func (VerificationTarget) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// CheckFact records one bounded verification check and reason.
type CheckFact struct {
	class  CheckClass
	reason ReasonCode
}

// newCheckFact constructs immutable bounded check metadata.
func newCheckFact(class CheckClass, reason ReasonCode) CheckFact {
	return CheckFact{class: class, reason: reason}
}

// Class returns the bounded verification concern.
func (f CheckFact) Class() CheckClass {
	return f.class
}

// Reason returns the bounded verification reason.
func (f CheckFact) Reason() ReasonCode {
	return f.reason
}

// SignatureSetFact records one bounded algorithm-family and signature-set outcome.
type SignatureSetFact struct {
	algorithm Algorithm
	status    SignatureStatus
	reason    ReasonCode
	metadata  KeyPolicyMetadata
}

// newSignatureSetFact constructs immutable bounded signature-set metadata.
func newSignatureSetFact(algorithm Algorithm, status SignatureStatus, reason ReasonCode, metadata ...KeyPolicyMetadata) SignatureSetFact {
	fact := SignatureSetFact{algorithm: algorithm, status: status, reason: reason}
	if len(metadata) == 1 {
		fact.metadata = metadata[0]
	}
	return fact
}

// Algorithm returns the bounded signature algorithm family.
func (f SignatureSetFact) Algorithm() Algorithm {
	return f.algorithm
}

// Status returns the bounded signature-set status.
func (f SignatureSetFact) Status() SignatureStatus {
	return f.status
}

// Reason returns the bounded signature-set reason.
func (f SignatureSetFact) Reason() ReasonCode {
	return f.reason
}

// KeyPolicyMetadata returns bounded DNS key declarations for this signature set.
func (f SignatureSetFact) KeyPolicyMetadata() KeyPolicyMetadata { return f.metadata }

// VerifyResult is an immutable structured current-verification outcome.
type VerifyResult struct {
	state *verifyResultState
}

type verifyResultState struct {
	draft                string
	resultState          ResultState
	scope                VerificationScope
	historicalContent    HistoricalState
	historicalSignatures HistoricalState
	custodyStructure     CustodyStructure
	target               VerificationTarget
	primaryReason        ReasonCode
	checks               []CheckFact
	signatures           []SignatureSetFact
	policyProjection     policy.Projection
	replayProjection     service.ReplayProjection
	hasReplayProjection  bool
}

const verifyResultRedactedText = "dkim2.VerifyResult{redacted}"

type verifyResultData struct {
	state                ResultState
	scope                VerificationScope
	historicalContent    HistoricalState
	historicalSignatures HistoricalState
	custodyStructure     CustodyStructure
	target               VerificationTarget
	primaryReason        ReasonCode
	checks               []CheckFact
	signatures           []SignatureSetFact
	policyProjection     policy.Projection
}

// newVerifyResult constructs a result while cloning every collection owned by its caller.
func newVerifyResult(data verifyResultData) VerifyResult {
	if !verifyResultDataValid(data) {
		return internalContractResult(data.target)
	}

	return VerifyResult{state: &verifyResultState{
		draft:                DraftIdentifier,
		resultState:          data.state,
		scope:                data.scope,
		historicalContent:    data.historicalContent,
		historicalSignatures: data.historicalSignatures,
		custodyStructure:     data.custodyStructure,
		target:               data.target,
		primaryReason:        data.primaryReason,
		checks:               slices.Clone(data.checks),
		signatures:           slices.Clone(data.signatures),
		policyProjection:     data.policyProjection.Clone(),
	}}
}

// withReplayProjection attaches one service-owned sealed projection to a coherent PASS result.
func (r VerifyResult) withReplayProjection(projection service.ReplayProjection, present bool) VerifyResult {
	if !present || !projection.Valid() || !r.replayEligible() {
		return r
	}
	state := r.cloneState()
	state.replayProjection = projection
	state.hasReplayProjection = true
	return VerifyResult{state: state}
}

// replayEligible validates the complete public aggregate-current-PASS envelope.
func (r VerifyResult) replayEligible() bool {
	return r.state != nil &&
		r.state.draft == DraftIdentifier &&
		r.state.resultState == ResultStatePASS &&
		((r.state.scope == VerificationScopeCurrent && r.state.historicalContent == HistoricalStateNotEvaluated && r.state.historicalSignatures == HistoricalStateNotEvaluated) ||
			r.state.scope == VerificationScopeChain && (r.state.historicalContent == HistoricalStateComplete || r.state.historicalContent == HistoricalStatePartial) && r.state.historicalSignatures == HistoricalStateComplete) &&
		(r.state.custodyStructure == CustodyStructureNotPresent ||
			r.state.custodyStructure == CustodyStructureNDLinksEvaluated) &&
		r.state.target.Sequence() > 0 && r.state.target.Instance() > 0 &&
		r.state.primaryReason == ReasonNone
}

// cloneState returns an independently owned aggregate state.
func (r VerifyResult) cloneState() *verifyResultState {
	if r.state == nil {
		return &verifyResultState{}
	}
	state := *r.state
	state.checks = slices.Clone(r.state.checks)
	state.signatures = slices.Clone(r.state.signatures)
	state.policyProjection = r.state.policyProjection.Clone()
	return &state
}

// verifyResultDataValid rejects unknown facts and impossible public result combinations.
func verifyResultDataValid(data verifyResultData) bool {
	if !data.state.Known() || !data.scope.Known() ||
		!data.historicalContent.Known() || !data.historicalSignatures.Known() ||
		!data.custodyStructure.Known() || !data.primaryReason.Known() {
		return false
	}
	if data.state == ResultStatePASS &&
		data.custodyStructure != CustodyStructureNotPresent &&
		data.custodyStructure != CustodyStructureNDLinksEvaluated {
		return false
	}
	for _, fact := range data.checks {
		if !fact.class.Known() || !fact.reason.Known() {
			return false
		}
	}
	for _, fact := range data.signatures {
		if !fact.algorithm.Known() || !fact.status.Known() || !fact.reason.Known() || fact.metadata.StrictIdentityApplicable() || !publicResultKeyPolicyCoherent(fact) {
			return false
		}
	}

	return true
}

// publicResultKeyPolicyCoherent restricts DNS metadata to unique-record result reasons.
func publicResultKeyPolicyCoherent(fact SignatureSetFact) bool {
	if !fact.metadata.TestingDeclared() && !fact.metadata.StrictIdentityDeclared() {
		return true
	}
	switch fact.reason {
	case ReasonNone, ReasonSignatureMismatch, ReasonInvalidKey, ReasonRevokedKey, ReasonUnsupportedKeyType, ReasonKeyAlgorithmMismatch:
		return true
	default:
		return false
	}
}

// internalContractResult returns a bounded fail-closed result for invalid adapter input.
func internalContractResult(target VerificationTarget) VerifyResult {
	result := VerifyResult{state: &verifyResultState{
		draft:                DraftIdentifier,
		resultState:          ResultStatePERMERROR,
		scope:                VerificationScopeCurrent,
		historicalContent:    HistoricalStateNotEvaluated,
		historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure:     CustodyStructureNotEvaluated,
		target:               target,
		primaryReason:        ReasonInternalContract,
		checks: []CheckFact{
			newCheckFact(CheckClassInternalContract, ReasonInternalContract),
		},
	}}
	if target.isZero() {
		projection, _ := policy.NewUnavailableProjection(policy.PreTargetInternalContract)
		result.state.policyProjection = projection
	}
	return result
}

// PrimaryReason returns the deterministic highest-precedence bounded reason.
func (r VerifyResult) PrimaryReason() ReasonCode {
	if r.state == nil {
		return ""
	}
	return r.state.primaryReason
}

// Draft returns the exact DKIM2 draft identifier governing this result.
func (r VerifyResult) Draft() string {
	if r.state == nil {
		return ""
	}
	return r.state.draft
}

// State returns one of the four public verification states.
func (r VerifyResult) State() ResultState {
	if r.state == nil {
		return ""
	}
	return r.state.resultState
}

// Scope returns the authenticated verification scope.
func (r VerifyResult) Scope() VerificationScope {
	if r.state == nil {
		return ""
	}
	return r.state.scope
}

// HistoricalContent returns the historical content and recipe coverage state.
func (r VerifyResult) HistoricalContent() HistoricalState {
	if r.state == nil {
		return ""
	}
	return r.state.historicalContent
}

// HistoricalSignatures returns the historical cryptographic-signature coverage state.
func (r VerifyResult) HistoricalSignatures() HistoricalState {
	if r.state == nil {
		return ""
	}
	return r.state.historicalSignatures
}

// CustodyStructure returns separately evaluated structural next-domain coverage.
func (r VerifyResult) CustodyStructure() CustodyStructure {
	if r.state == nil {
		return ""
	}
	return r.state.custodyStructure
}

// Target returns the current verification target metadata.
func (r VerifyResult) Target() VerificationTarget {
	if r.state == nil {
		return VerificationTarget{}
	}
	return r.state.target
}

// Checks returns an independent copy of the bounded check facts.
func (r VerifyResult) Checks() []CheckFact {
	if r.state == nil {
		return nil
	}
	return slices.Clone(r.state.checks)
}

// CheckCount returns the bounded number of retained check facts.
func (r VerifyResult) CheckCount() int {
	if r.state == nil {
		return 0
	}
	return len(r.state.checks)
}

// SignatureSets returns an independent copy of the bounded signature-set facts.
func (r VerifyResult) SignatureSets() []SignatureSetFact {
	if r.state == nil {
		return nil
	}
	return slices.Clone(r.state.signatures)
}

// SignatureSetCount returns the bounded number of retained signature-set facts.
func (r VerifyResult) SignatureSetCount() int {
	if r.state == nil {
		return 0
	}
	return len(r.state.signatures)
}

// sealedPolicyProjection returns an independent policy projection for package-internal checks.
func (r VerifyResult) sealedPolicyProjection() policy.Projection {
	if r.state == nil {
		return policy.Projection{}
	}
	return r.state.policyProjection.Clone()
}

// Valid reports whether the result is a complete library-owned current-verification aggregate.
func (r VerifyResult) Valid() bool {
	if r.state == nil {
		return false
	}
	if !verifyResultPolicyProvenanceValid(r) ||
		len(r.state.checks) == 0 || len(r.state.checks) > HardMaxCheckFacts ||
		len(r.state.signatures) > HardMaxSignatureFacts ||
		r.state.primaryReason == ReasonInvalidRequest {
		return false
	}
	for _, fact := range r.state.checks {
		if fact.reason == ReasonInvalidRequest {
			return false
		}
	}
	for _, fact := range r.state.signatures {
		if fact.reason == ReasonInvalidRequest {
			return false
		}
	}
	target := r.state.target
	if target.isZero() {
		return r.state.resultState == ResultStatePERMERROR &&
			unavailableReasonMatches(r.state.policyProjection.PreTargetReason(), r.state.primaryReason)
	}
	if target.Sequence() == 0 || target.Instance() == 0 {
		return false
	}
	switch r.state.resultState {
	case ResultStatePASS:
		return r.state.primaryReason == ReasonNone &&
			(r.state.custodyStructure == CustodyStructureNotPresent ||
				r.state.custodyStructure == CustodyStructureNDLinksEvaluated)
	case ResultStateFAIL:
		return r.state.primaryReason == ReasonHashMismatch || r.state.primaryReason == ReasonSignatureMismatch
	case ResultStateTEMPERROR:
		return r.state.primaryReason == ReasonProviderTemporary
	case ResultStatePERMERROR:
		return r.state.primaryReason != ReasonNone &&
			r.state.primaryReason != ReasonHashMismatch &&
			r.state.primaryReason != ReasonSignatureMismatch &&
			r.state.primaryReason != ReasonProviderTemporary
	default:
		return false
	}
}

// String returns a constant representation without sealed or message-derived facts.
func (VerifyResult) String() string { return verifyResultRedactedText }

// GoString returns a constant representation without sealed or message-derived facts.
func (VerifyResult) GoString() string { return verifyResultRedactedText }

// Format prevents formatting from traversing sealed or message-derived facts.
func (VerifyResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, verifyResultRedactedText)
}

// MarshalJSON rejects serialization outside explicit mapped response boundaries.
func (VerifyResult) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of sealed verification facts.
func (VerifyResult) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}
