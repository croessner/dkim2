package service

import (
	"bytes"

	"github.com/croessner/dkim2/internal/verify"
)

// DraftIdentifier is the exact behavior baseline carried by service results.
const DraftIdentifier = "draft-ietf-dkim-dkim2-spec-06"

const hardMaxSignatureFacts = 16

// State identifies one of the four current-verification outcomes.
type State string

const (
	// StatePASS reports complete success for the declared authenticated scope.
	StatePASS State = "PASS"
	// StateFAIL reports a supported integrity mismatch.
	StateFAIL State = "FAIL"
	// StatePERMERROR reports permanent malformed, missing, or ambiguous state.
	StatePERMERROR State = "PERMERROR"
	// StateTEMPERROR reports a typed temporary provider failure.
	StateTEMPERROR State = "TEMPERROR"
)

// Known reports whether state belongs to the closed four-state vocabulary.
func (s State) Known() bool {
	return s == StatePASS || s == StateFAIL || s == StatePERMERROR || s == StateTEMPERROR
}

// Scope identifies the verified message-state boundary.
type Scope string

const (
	// ScopeCurrent limits verification to the highest current target.
	ScopeCurrent Scope = "current"
	// ScopeChain reports authenticated verification through every inherited revision.
	ScopeChain Scope = "chain"
)

// Known reports whether scope belongs to the closed service vocabulary.
func (s Scope) Known() bool { return s == ScopeCurrent || s == ScopeChain }

// HistoricalState identifies one deliberately unevaluated historical dimension.
type HistoricalState string

const (
	// HistoricalNotEvaluated reports that historical reconstruction or crypto did not run.
	HistoricalNotEvaluated HistoricalState = "not_evaluated"
	// HistoricalComplete reports authenticated coverage through the origin.
	HistoricalComplete HistoricalState = "complete"
	// HistoricalPartial reports authenticated coverage with an explicit unavailable body.
	HistoricalPartial HistoricalState = "partial"
)

// Known reports whether historical state belongs to the closed service vocabulary.
func (s HistoricalState) Known() bool {
	return s == HistoricalNotEvaluated || s == HistoricalComplete || s == HistoricalPartial
}

// Custody identifies bounded structural next-domain coverage.
type Custody string

const (
	// CustodyNotEvaluated reports that earlier failure prevented reliable nd= detection.
	CustodyNotEvaluated Custody = "not_evaluated"
	// CustodyNotPresent reports successful extraction found no nd= link.
	CustodyNotPresent Custody = "not_present"
	// CustodyNDLinksEvaluated reports one or more intermediate links were evaluated.
	CustodyNDLinksEvaluated Custody = "nd_links_evaluated"
	// CustodyTerminalNDRequiresOOB reports terminal nd= requires unavailable OOB trust.
	CustodyTerminalNDRequiresOOB Custody = "terminal_nd_requires_oob"
)

// Known reports whether custody belongs to the closed service vocabulary.
func (c Custody) Known() bool {
	return c == CustodyNotEvaluated || c == CustodyNotPresent || c == CustodyNDLinksEvaluated || c == CustodyTerminalNDRequiresOOB
}

// CheckClass identifies a bounded verification concern.
type CheckClass string

const (
	// CheckMessage identifies raw RFC 5322 parsing.
	CheckMessage CheckClass = "message"
	// CheckProtocol identifies DKIM2 structural processing.
	CheckProtocol CheckClass = "protocol"
	// CheckBodyHash identifies current body hash verification.
	CheckBodyHash CheckClass = "body_hash"
	// CheckHeaderHash identifies current header hash verification.
	CheckHeaderHash CheckClass = "header_hash"
	// CheckSignature identifies cryptographic signature verification.
	CheckSignature CheckClass = "signature"
	// CheckKey identifies public-key validity and availability.
	CheckKey CheckClass = "key"
	// CheckTimestamp identifies timestamp policy evaluation.
	CheckTimestamp CheckClass = "timestamp"
	// CheckEnvelope identifies current SMTP envelope matching.
	CheckEnvelope CheckClass = "envelope"
	// CheckDomainAlignment identifies signing-domain alignment.
	CheckDomainAlignment CheckClass = "domain_alignment"
	// CheckNextDomain identifies structural next-domain processing.
	CheckNextDomain CheckClass = "next_domain"
	// CheckProvider identifies injected key-provider behavior.
	CheckProvider CheckClass = "provider"
	// CheckInternalContract identifies inconsistent internal facts.
	CheckInternalContract CheckClass = "internal_contract"
)

// Known reports whether the check class belongs to the closed service vocabulary.
func (c CheckClass) Known() bool {
	switch c {
	case CheckMessage, CheckProtocol, CheckBodyHash, CheckHeaderHash, CheckSignature, CheckKey, CheckTimestamp, CheckEnvelope, CheckDomainAlignment, CheckNextDomain, CheckProvider, CheckInternalContract:
		return true
	default:
		return false
	}
}

// Reason identifies a bounded verification outcome reason.
type Reason string

const (
	// ReasonNone reports no failure.
	ReasonNone Reason = "none"
	// ReasonInvalidRequest reports request API misuse.
	ReasonInvalidRequest Reason = "invalid_request"
	// ReasonLimitExceeded reports a configured resource limit.
	ReasonLimitExceeded Reason = "limit_exceeded"
	// ReasonMalformedMessage reports malformed RFC 5322 bytes.
	ReasonMalformedMessage Reason = "malformed_message"
	// ReasonMalformedProtocol reports malformed DKIM2 state.
	ReasonMalformedProtocol Reason = "malformed_protocol"
	// ReasonDuplicateHashAlgorithm reports any repeated h= algorithm name.
	ReasonDuplicateHashAlgorithm Reason = "duplicate_hash_algorithm"
	// ReasonInvalidRecipeJSON reports malformed authenticated recipe JSON.
	ReasonInvalidRecipeJSON Reason = "invalid_recipe_json"
	// ReasonDuplicateSelector reports a repeated selector in one signature field.
	ReasonDuplicateSelector Reason = "duplicate_selector"
	// ReasonTooManySignatures reports a third signature occurrence for one algorithm.
	ReasonTooManySignatures Reason = "too_many_signatures"
	// ReasonMissingProtocol reports absent required DKIM2 state.
	ReasonMissingProtocol Reason = "missing_protocol"
	// ReasonSequenceInvalid reports invalid signature or instance numbering.
	ReasonSequenceInvalid Reason = "sequence_invalid"
	// ReasonUnsupportedAlgorithm reports no checkable required algorithm.
	ReasonUnsupportedAlgorithm Reason = "unsupported_algorithm"
	// ReasonHashMismatch reports a supported digest mismatch.
	ReasonHashMismatch Reason = "hash_mismatch"
	// ReasonSignatureMismatch reports a supported signature mismatch.
	ReasonSignatureMismatch Reason = "signature_mismatch"
	// ReasonMissingKey reports absent public-key material.
	ReasonMissingKey Reason = "missing_key"
	// ReasonInvalidKey reports invalid public-key material.
	ReasonInvalidKey Reason = "invalid_key"
	// ReasonAmbiguousKey reports ambiguous public-key material.
	ReasonAmbiguousKey Reason = "ambiguous_key"
	// ReasonRevokedKey reports an explicitly revoked DNS public key.
	ReasonRevokedKey Reason = "revoked_key"
	// ReasonUnsupportedKeyType reports an unsupported DNS key type.
	ReasonUnsupportedKeyType Reason = "unsupported_key_type"
	// ReasonKeyAlgorithmMismatch reports disagreement between requested algorithm and DNS key type.
	ReasonKeyAlgorithmMismatch Reason = "key_algorithm_mismatch"
	// ReasonProviderTemporary reports typed retryable provider failure.
	ReasonProviderTemporary Reason = "provider_temporary"
	// ReasonProviderPermanent reports typed unrecoverable provider failure.
	ReasonProviderPermanent Reason = "provider_permanent"
	// ReasonProviderContract reports inconsistent provider behavior.
	ReasonProviderContract Reason = "provider_contract"
	// ReasonTimestampInvalid reports rejected timestamp state.
	ReasonTimestampInvalid Reason = "timestamp_invalid"
	// ReasonEnvelopeMismatch reports current SMTP envelope disagreement.
	ReasonEnvelopeMismatch Reason = "envelope_mismatch"
	// ReasonDomainAlignmentMismatch reports signing-domain misalignment.
	ReasonDomainAlignmentMismatch Reason = "domain_alignment_mismatch"
	// ReasonNextDomainMismatch reports structural next-domain disagreement.
	ReasonNextDomainMismatch Reason = "next_domain_mismatch"
	// ReasonOutOfBandRequired reports terminal nd= requiring OOB trust.
	ReasonOutOfBandRequired Reason = "out_of_band_required"
	// ReasonInternalContract reports inconsistent internal facts.
	ReasonInternalContract Reason = "internal_contract"
)

// Known reports whether the reason belongs to the closed service vocabulary.
func (r Reason) Known() bool {
	switch r {
	case ReasonNone, ReasonInvalidRequest, ReasonLimitExceeded, ReasonMalformedMessage, ReasonMalformedProtocol, ReasonDuplicateHashAlgorithm, ReasonInvalidRecipeJSON, ReasonDuplicateSelector, ReasonTooManySignatures, ReasonMissingProtocol, ReasonSequenceInvalid, ReasonUnsupportedAlgorithm, ReasonHashMismatch, ReasonSignatureMismatch, ReasonMissingKey, ReasonInvalidKey, ReasonAmbiguousKey, ReasonRevokedKey, ReasonUnsupportedKeyType, ReasonKeyAlgorithmMismatch, ReasonProviderTemporary, ReasonProviderPermanent, ReasonProviderContract, ReasonTimestampInvalid, ReasonEnvelopeMismatch, ReasonDomainAlignmentMismatch, ReasonNextDomainMismatch, ReasonOutOfBandRequired, ReasonInternalContract:
		return true
	default:
		return false
	}
}

// KeyPolicyMetadata carries bounded DNS key declarations through service mapping.
type KeyPolicyMetadata struct {
	TestingDeclared          bool
	StrictIdentityDeclared   bool
	StrictIdentityApplicable bool
}

// Valid reports whether policy metadata is coherent with the active DKIM2 draft.
func (m KeyPolicyMetadata) Valid() bool { return !m.StrictIdentityApplicable }

// Algorithm identifies a bounded signature algorithm family.
type Algorithm string

const (
	// AlgorithmRSASHA256 identifies RSA-SHA256.
	AlgorithmRSASHA256 Algorithm = "rsa-sha256"
	// AlgorithmEd25519SHA256 identifies Ed25519-SHA256.
	AlgorithmEd25519SHA256 Algorithm = "ed25519-sha256"
	// AlgorithmUnknown bounds unrecognized algorithm spellings.
	AlgorithmUnknown Algorithm = "unknown"
)

// Known reports whether the algorithm belongs to the bounded service vocabulary.
func (a Algorithm) Known() bool {
	return a == AlgorithmRSASHA256 || a == AlgorithmEd25519SHA256 || a == AlgorithmUnknown
}

// SignatureStatus identifies one bounded signature-set outcome.
type SignatureStatus string

const (
	// SignaturePASS reports one supported signature pass.
	SignaturePASS SignatureStatus = "pass"
	// SignatureFAIL reports one supported signature mismatch.
	SignatureFAIL SignatureStatus = "fail"
	// SignaturePERMERROR reports permanent set-level failure.
	SignaturePERMERROR SignatureStatus = "permerror"
	// SignatureTEMPERROR reports typed temporary provider failure.
	SignatureTEMPERROR SignatureStatus = "temperror"
	// SignatureIgnored reports an unknown algorithm ignored by aggregation.
	SignatureIgnored SignatureStatus = "ignored"
)

// Known reports whether signature status belongs to the closed service vocabulary.
func (s SignatureStatus) Known() bool {
	return s == SignaturePASS || s == SignatureFAIL || s == SignaturePERMERROR || s == SignatureTEMPERROR || s == SignatureIgnored
}

// Limits bounds service input, extraction, and retained facts.
type Limits struct {
	MaxRawMessageBytes  int
	MaxRecipients       int
	MaxInstanceHashSets int
	MaxSignatureSets    int
	MaxCheckFacts       int
	MaxSignatureFacts   int
}

// DefaultLimits returns the closed service maxima.
func DefaultLimits() Limits {
	return Limits{32 << 20, 2000, 16, 16, 128, hardMaxSignatureFacts}
}

// Validate rejects zero, negative, or widening service limits.
func (l Limits) Validate() error {
	maximum := DefaultLimits()
	if l.MaxRawMessageBytes <= 0 || l.MaxRawMessageBytes > maximum.MaxRawMessageBytes ||
		l.MaxRecipients <= 0 || l.MaxRecipients > maximum.MaxRecipients ||
		l.MaxInstanceHashSets <= 0 || l.MaxInstanceHashSets > maximum.MaxInstanceHashSets ||
		l.MaxSignatureSets <= 0 || l.MaxSignatureSets > maximum.MaxSignatureSets ||
		l.MaxCheckFacts <= 0 || l.MaxCheckFacts > maximum.MaxCheckFacts ||
		l.MaxSignatureFacts <= 0 || l.MaxSignatureFacts > maximum.MaxSignatureFacts {
		return newError(ErrorInvalidConfig)
	}

	return nil
}

// Config contains immutable verifier policies and limits.
type Config struct {
	Limits          Limits
	AlgorithmPolicy verify.AlgorithmPolicy
	TimestampPolicy verify.TimestampPolicy
	Clock           verify.Clock
}

// DefaultConfig returns restrictive current-verification defaults.
func DefaultConfig() Config {
	options := verify.DefaultOptions()
	return Config{Limits: DefaultLimits(), AlgorithmPolicy: options.AlgorithmPolicy, TimestampPolicy: options.TimestampPolicy, Clock: options.Clock}
}

// Request owns raw RFC 5322 and current SMTP envelope bytes.
type Request struct {
	rawMessage   []byte
	reversePath  []byte
	forwardPaths [][]byte
}

// NewRequest constructs an immutable internal service request.
func NewRequest(rawMessage, reversePath []byte, forwardPaths [][]byte) Request {
	return Request{rawMessage: bytes.Clone(rawMessage), reversePath: bytes.Clone(reversePath), forwardPaths: cloneByteSlices(forwardPaths)}
}

// RawMessage returns an independent raw-message copy.
func (r Request) RawMessage() []byte { return bytes.Clone(r.rawMessage) }

// ReversePath returns an independent reverse-path copy.
func (r Request) ReversePath() []byte { return bytes.Clone(r.reversePath) }

// ForwardPaths returns independent forward-path copies.
func (r Request) ForwardPaths() [][]byte { return cloneByteSlices(r.forwardPaths) }

// cloneByteSlices deep-clones byte-slice collections.
func cloneByteSlices(input [][]byte) [][]byte {
	if len(input) == 0 {
		return nil
	}
	result := make([][]byte, len(input))
	for index := range input {
		result[index] = bytes.Clone(input[index])
	}
	return result
}
