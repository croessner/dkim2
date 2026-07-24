package verify

import (
	"fmt"
	"io"
	"slices"
)

// CheckKind identifies one verification check dimension.
type CheckKind string

const (
	// CheckKindBodyHash identifies current body hash validation.
	CheckKindBodyHash CheckKind = "body_hash"
	// CheckKindHeaderHash identifies current header hash validation.
	CheckKindHeaderHash CheckKind = "header_hash"
	// CheckKindSignature identifies cryptographic signature validation.
	CheckKindSignature CheckKind = "signature"
	// CheckKindKey identifies static public-key lookup and validation.
	CheckKindKey CheckKind = "key"
	// CheckKindTimestamp identifies local timestamp policy validation.
	CheckKindTimestamp CheckKind = "timestamp"
	// CheckKindEnvelope identifies current SMTP envelope validation.
	CheckKindEnvelope CheckKind = "envelope"
	// CheckKindDomainAlignment identifies d= alignment with the signed MAIL FROM domain.
	CheckKindDomainAlignment CheckKind = "domain_alignment"
	// CheckKindNextDomain identifies nd= chain-of-custody validation.
	CheckKindNextDomain CheckKind = "next_domain"
)

// CheckStatus records a stable per-check outcome.
type CheckStatus string

const (
	// CheckStatusNotEvaluated records a check that has not run.
	CheckStatusNotEvaluated CheckStatus = "not_evaluated"
	// CheckStatusPass records a successful check.
	CheckStatusPass CheckStatus = "pass"
	// CheckStatusFail records a failed check.
	CheckStatusFail CheckStatus = "fail"
	// CheckStatusUnsupported records a non-success unsupported state.
	CheckStatusUnsupported CheckStatus = "unsupported"
	// CheckStatusSkipped records an explicit skipped check.
	CheckStatusSkipped CheckStatus = "skipped"
	// CheckStatusNotApplicable records a check outside the selected target.
	CheckStatusNotApplicable CheckStatus = "not_applicable"
	// CheckStatusIndeterminate records a bounded non-success unknown state.
	CheckStatusIndeterminate CheckStatus = "indeterminate"
)

// SignatureSetStatus records one s= selector:algorithm:signature outcome.
type SignatureSetStatus string

const (
	// SignatureSetStatusNotChecked records a signature set not yet evaluated.
	SignatureSetStatusNotChecked SignatureSetStatus = "not_checked"
	// SignatureSetStatusPass records a cryptographic pass for one signature set.
	SignatureSetStatusPass SignatureSetStatus = "pass"
	// SignatureSetStatusFail records a cryptographic failure for one signature set.
	SignatureSetStatusFail SignatureSetStatus = "fail"
	// SignatureSetStatusUnsupportedAlgorithm records a known non-success unsupported algorithm.
	SignatureSetStatusUnsupportedAlgorithm SignatureSetStatus = "unsupported_algorithm"
	// SignatureSetStatusDisabledAlgorithm records an algorithm disabled by local policy.
	SignatureSetStatusDisabledAlgorithm SignatureSetStatus = "disabled_algorithm"
	// SignatureSetStatusMissingKey records a missing public key.
	SignatureSetStatusMissingKey SignatureSetStatus = "missing_key"
	// SignatureSetStatusInvalidKey records public key material rejected before crypto use.
	SignatureSetStatusInvalidKey SignatureSetStatus = "invalid_key"
	// SignatureSetStatusAmbiguousKey records multiple matching public keys.
	SignatureSetStatusAmbiguousKey SignatureSetStatus = "ambiguous_key"
	// SignatureSetStatusRevokedKey records an explicitly revoked DNS public key.
	SignatureSetStatusRevokedKey SignatureSetStatus = "revoked_key"
	// SignatureSetStatusUnsupportedKeyType records an unsupported DNS key type.
	SignatureSetStatusUnsupportedKeyType SignatureSetStatus = "unsupported_key_type"
	// SignatureSetStatusKeyAlgorithmMismatch records DNS key type disagreement with the requested algorithm.
	SignatureSetStatusKeyAlgorithmMismatch SignatureSetStatus = "key_algorithm_mismatch"
	// SignatureSetStatusWrongKeyType records a public key type mismatch.
	SignatureSetStatusWrongKeyType SignatureSetStatus = "wrong_key_type"
	// SignatureSetStatusKeyPolicyRejected records a key rejected by verifier policy.
	SignatureSetStatusKeyPolicyRejected SignatureSetStatus = "key_policy_rejected"
	// SignatureSetStatusProviderError records a bounded key-provider failure.
	SignatureSetStatusProviderError SignatureSetStatus = "provider_error"
	// SignatureSetStatusProviderTemporary records typed retryable provider failure.
	SignatureSetStatusProviderTemporary SignatureSetStatus = "provider_temporary"
	// SignatureSetStatusProviderPermanent records typed unrecoverable provider failure.
	SignatureSetStatusProviderPermanent SignatureSetStatus = "provider_permanent"
	// SignatureSetStatusProviderContract records inconsistent provider behavior.
	SignatureSetStatusProviderContract SignatureSetStatus = "provider_contract"
)

// KeyStatus records provider and key validation state.
type KeyStatus string

const (
	// KeyStatusNotChecked records a key lookup that has not run.
	KeyStatusNotChecked KeyStatus = "not_checked"
	// KeyStatusFound records a key lookup that returned usable material.
	KeyStatusFound KeyStatus = "found"
	// KeyStatusMissing records absent key material.
	KeyStatusMissing KeyStatus = "missing"
	// KeyStatusInvalid records malformed or mismatched key material.
	KeyStatusInvalid KeyStatus = "invalid"
	// KeyStatusAmbiguous records multiple matching key records.
	KeyStatusAmbiguous KeyStatus = "ambiguous"
	// KeyStatusRevoked records an explicitly revoked DNS public key.
	KeyStatusRevoked KeyStatus = "revoked"
	// KeyStatusUnsupportedKeyType records an unsupported DNS key type.
	KeyStatusUnsupportedKeyType KeyStatus = "unsupported_key_type"
	// KeyStatusAlgorithmMismatch records disagreement between requested algorithm and DNS key type.
	KeyStatusAlgorithmMismatch KeyStatus = "algorithm_mismatch"
	// KeyStatusWrongType records key material with the wrong Go public-key type.
	KeyStatusWrongType KeyStatus = "wrong_type"
	// KeyStatusPolicyRejected records a key or algorithm rejected by local policy.
	KeyStatusPolicyRejected KeyStatus = "policy_rejected"
	// KeyStatusUnsupportedAlgorithm records an unsupported algorithm lookup.
	KeyStatusUnsupportedAlgorithm KeyStatus = "unsupported_algorithm"
	// KeyStatusDisabledAlgorithm records a disabled algorithm lookup.
	KeyStatusDisabledAlgorithm KeyStatus = "disabled_algorithm"
	// KeyStatusProviderError records an internal provider failure.
	KeyStatusProviderError KeyStatus = "provider_error"
	// KeyStatusProviderTemporary records typed retryable provider failure.
	KeyStatusProviderTemporary KeyStatus = "provider_temporary"
	// KeyStatusProviderPermanent records typed unrecoverable provider failure.
	KeyStatusProviderPermanent KeyStatus = "provider_permanent"
	// KeyStatusProviderContract records inconsistent provider behavior.
	KeyStatusProviderContract KeyStatus = "provider_contract"
)

// CustodyStatus records structural nd= coverage established by protocol extraction.
type CustodyStatus string

const (
	// CustodyStatusNotPresent reports successful extraction found no nd=.
	CustodyStatusNotPresent CustodyStatus = "not_present"
	// CustodyStatusNDLinksEvaluated reports one or more intermediate nd= links were checked.
	CustodyStatusNDLinksEvaluated CustodyStatus = "nd_links_evaluated"
	// CustodyStatusTerminalNDRequiresOOB reports the current terminal nd= requires OOB trust.
	CustodyStatusTerminalNDRequiresOOB CustodyStatus = "terminal_nd_requires_oob"
)

// TimestampStatus records local t= policy state.
type TimestampStatus string

const (
	// TimestampStatusNotChecked records a timestamp check that has not run.
	TimestampStatusNotChecked TimestampStatus = "not_checked"
	// TimestampStatusPass records an accepted timestamp.
	TimestampStatusPass TimestampStatus = "pass"
	// TimestampStatusFuture records a timestamp beyond future tolerance.
	TimestampStatusFuture TimestampStatus = "future"
	// TimestampStatusExpired records a timestamp older than maximum age.
	TimestampStatusExpired TimestampStatus = "expired"
	// TimestampStatusNoMaxAge records an explicitly disabled maximum-age cap.
	TimestampStatusNoMaxAge TimestampStatus = "no_max_age"
	// TimestampStatusNotApplicable records a timestamp check outside the target semantics.
	TimestampStatusNotApplicable TimestampStatus = "not_applicable"
	// TimestampStatusInvalid records malformed parser-owned timestamp state.
	TimestampStatusInvalid TimestampStatus = "invalid"
)

// EnvelopeStatus records current SMTP envelope match state.
type EnvelopeStatus string

const (
	// EnvelopeStatusNotChecked records an envelope check that has not run.
	EnvelopeStatusNotChecked EnvelopeStatus = "not_checked"
	// EnvelopeStatusPass records a draft-conformant current-envelope match.
	EnvelopeStatusPass EnvelopeStatus = "pass"
	// EnvelopeStatusMissing records absent required envelope evidence.
	EnvelopeStatusMissing EnvelopeStatus = "missing"
	// EnvelopeStatusMismatch records byte-level envelope mismatch.
	EnvelopeStatusMismatch EnvelopeStatus = "mismatch"
	// EnvelopeStatusInvalid records malformed parser-owned or request-owned path state.
	EnvelopeStatusInvalid EnvelopeStatus = "invalid"
	// EnvelopeStatusReversePathMismatch records a reverse-path byte mismatch.
	EnvelopeStatusReversePathMismatch EnvelopeStatus = "reverse_path_mismatch"
	// EnvelopeStatusRecipientValueMismatch records a current forward path absent from the signed recipient set.
	EnvelopeStatusRecipientValueMismatch EnvelopeStatus = "recipient_value_mismatch"
	// EnvelopeStatusNotApplicable records a disabled or non-current target check.
	EnvelopeStatusNotApplicable EnvelopeStatus = "not_applicable"
)

// DomainAlignmentStatus records signing-domain alignment with the signed reverse-path.
type DomainAlignmentStatus string

const (
	// DomainAlignmentStatusNotChecked records a domain alignment check that has not run.
	DomainAlignmentStatusNotChecked DomainAlignmentStatus = "not_checked"
	// DomainAlignmentStatusPass records exact or label-boundary suffix alignment.
	DomainAlignmentStatusPass DomainAlignmentStatus = "pass"
	// DomainAlignmentStatusMismatch records a non-aligned signing domain.
	DomainAlignmentStatusMismatch DomainAlignmentStatus = "mismatch"
	// DomainAlignmentStatusInvalid records malformed signed reverse-path domain evidence.
	DomainAlignmentStatusInvalid DomainAlignmentStatus = "invalid"
	// DomainAlignmentStatusNotApplicable records the null reverse-path exception.
	DomainAlignmentStatusNotApplicable DomainAlignmentStatus = "not_applicable"
)

// NextDomainStatus records nd= chain validation and OOB state.
type NextDomainStatus string

const (
	// NextDomainStatusNotChecked records an nd= check that has not run.
	NextDomainStatusNotChecked NextDomainStatus = "not_checked"
	// NextDomainStatusPass records exact canonical nd= to next d= matching.
	NextDomainStatusPass NextDomainStatus = "pass"
	// NextDomainStatusMismatch records a non-matching next signing domain.
	NextDomainStatusMismatch NextDomainStatus = "mismatch"
	// NextDomainStatusMissingNext records an absent immediate successor signature.
	NextDomainStatusMissingNext NextDomainStatus = "missing_next"
	// NextDomainStatusOutOfBandRequired records terminal nd= state requiring OOB acceptance.
	NextDomainStatusOutOfBandRequired NextDomainStatus = "out_of_band_required"
	// NextDomainStatusNotApplicable records a signature without nd=.
	NextDomainStatusNotApplicable NextDomainStatus = "not_applicable"
)

// HashStatus records body or header hash validation state.
type HashStatus string

const (
	// HashStatusNotChecked records a hash check that has not run.
	HashStatusNotChecked HashStatus = "not_checked"
	// HashStatusPass records a matching sha256 digest.
	HashStatusPass HashStatus = "pass"
	// HashStatusMismatch records a non-matching sha256 digest.
	HashStatusMismatch HashStatus = "mismatch"
	// HashStatusMissingSHA256 records absence of the required sha256 hash set.
	HashStatusMissingSHA256 HashStatus = "missing_sha256"
	// HashStatusUnsupported records only unsupported hash algorithms.
	HashStatusUnsupported HashStatus = "unsupported"
	// HashStatusInvalid records malformed parser-owned hash state.
	HashStatusInvalid HashStatus = "invalid"
)

// TargetStatus records the overall target verification state.
type TargetStatus string

const (
	// TargetStatusNotEvaluated records a target that has not run.
	TargetStatusNotEvaluated TargetStatus = "not_evaluated"
	// TargetStatusPass records target success for evaluated checks.
	TargetStatusPass TargetStatus = "pass"
	// TargetStatusFail records target failure.
	TargetStatusFail TargetStatus = "fail"
	// TargetStatusMixed records mixed per-signature-set outcomes.
	TargetStatusMixed TargetStatus = "mixed"
	// TargetStatusUnsupported records no checkable supported path.
	TargetStatusUnsupported TargetStatus = "unsupported"
	// TargetStatusIndeterminate records bounded non-success ambiguity.
	TargetStatusIndeterminate TargetStatus = "indeterminate"
	// TargetStatusUnknown records an unrecognized internal status without retaining its spelling.
	TargetStatusUnknown TargetStatus = "unknown"
)

// Target identifies the selected DKIM2 signature and instance numbers.
type Target struct {
	// Sequence records the selected i= DKIM2-Signature value.
	Sequence uint64
	// InstanceNumber records the selected m= Message-Instance value.
	InstanceNumber uint64
}

// CheckResult records one bounded verification check fact.
type CheckResult struct {
	// Kind records the verification check dimension.
	Kind CheckKind
	// Status records the check outcome.
	Status CheckStatus
	// Code records an optional stable error code.
	Code ErrorCode
	// Algorithm records an allowlisted algorithm name when relevant.
	Algorithm Algorithm
	// HashStatus records typed current hash state when relevant.
	HashStatus HashStatus
	// TimestampStatus records local timestamp policy detail when relevant.
	TimestampStatus TimestampStatus
	// EnvelopeStatus records current SMTP envelope detail when relevant.
	EnvelopeStatus EnvelopeStatus
	// DomainAlignmentStatus records bounded d= to mf= domain alignment detail.
	DomainAlignmentStatus DomainAlignmentStatus
	// NextDomainStatus records bounded nd= chain detail without domain values.
	NextDomainStatus NextDomainStatus
	// ProviderFailureClass records typed provider detail without raw causes.
	ProviderFailureClass ProviderFailureClass
	// Target records bounded sequence and instance context.
	Target Target
}

// SignatureSetResult records bounded facts for one signature set.
type SignatureSetResult struct {
	// Index records the zero-based s= set position.
	Index int
	// Algorithm records the signature algorithm name.
	Algorithm Algorithm
	// Status records the per-signature-set outcome.
	Status SignatureSetStatus
	// KeyStatus records associated key lookup and validation state.
	KeyStatus KeyStatus
	// KeyPolicy carries bounded DNS declarations from the selected key record.
	KeyPolicy KeyPolicyMetadata
}

// Result stores immutable bounded verification facts for service coordination.
type Result struct {
	draft               string
	target              Target
	status              TargetStatus
	checks              []CheckResult
	signatureSets       []SignatureSetResult
	custody             CustodyStatus
	targetFlags         TargetFlagCandidate
	hasTargetFlags      bool
	history             HistoryWalk
	hasHistory          bool
	replayProjection    ReplayProjection
	hasReplayProjection bool
}

// TargetFlagCandidate stores bounded parser-owned evidence for the selected target.
type TargetFlagCandidate struct {
	sequence     uint64
	doNotModify  bool
	doNotExplode bool
	feedback     bool
	feedHere     bool
	exploded     bool
}

// Valid reports whether the candidate identifies a positive target sequence.
func (c TargetFlagCandidate) Valid() bool { return c.sequence > 0 }

// Sequence returns the parsed target signature sequence.
func (c TargetFlagCandidate) Sequence() uint64 { return c.sequence }

// DoNotModify reports whether parsed target flags contain donotmodify.
func (c TargetFlagCandidate) DoNotModify() bool { return c.doNotModify }

// DoNotExplode reports whether parsed target flags contain donotexplode.
func (c TargetFlagCandidate) DoNotExplode() bool { return c.doNotExplode }

// Feedback reports whether parsed target flags contain feedback.
func (c TargetFlagCandidate) Feedback() bool { return c.feedback }

// FeedHere reports whether parsed target flags contain feedhere.
func (c TargetFlagCandidate) FeedHere() bool { return c.feedHere }

// Exploded reports whether parsed target flags contain exploded.
func (c TargetFlagCandidate) Exploded() bool { return c.exploded }

// NewResult constructs immutable verification result facts.
func NewResult(target Target, status TargetStatus, checks []CheckResult, signatureSets []SignatureSetResult) Result {
	return Result{
		draft:         DraftBaseline,
		target:        target,
		status:        boundedTargetStatus(status),
		checks:        cloneCheckResults(checks),
		signatureSets: cloneSignatureSetResults(signatureSets),
	}
}

// NewResultWithCustody constructs immutable facts with established structural coverage.
func NewResultWithCustody(target Target, status TargetStatus, checks []CheckResult, signatureSets []SignatureSetResult, custody CustodyStatus) Result {
	result := NewResult(target, status, checks, signatureSets)
	if custody.Known() {
		result.custody = custody
	} else {
		result.custody = ""
	}
	return result
}

// Draft returns the active DKIM2 draft baseline for this result.
func (r Result) Draft() string {
	if r.draft == "" {
		return DraftBaseline
	}

	return r.draft
}

// Target returns selected target identifiers.
func (r Result) Target() Target {
	return r.target
}

// Status returns the overall target status.
func (r Result) Status() TargetStatus {
	return r.status
}

// Checks returns immutable per-check facts.
func (r Result) Checks() []CheckResult {
	return cloneCheckResults(r.checks)
}

// SignatureSets returns immutable per-signature-set facts.
func (r Result) SignatureSets() []SignatureSetResult {
	return cloneSignatureSetResults(r.signatureSets)
}

// CustodyStatus returns whole-sequence structural nd= coverage.
func (r Result) CustodyStatus() CustodyStatus { return r.custody }

// withTargetFlagCandidate attaches coherent parser-owned evidence to a result.
func (r Result) withTargetFlagCandidate(candidate TargetFlagCandidate) Result {
	if !candidate.Valid() || r.target.Sequence == 0 || candidate.sequence != r.target.Sequence {
		return r
	}
	r.targetFlags = candidate
	r.hasTargetFlags = true
	return r
}

// TargetFlagCandidate returns the bounded parsed candidate by value when present.
func (r Result) TargetFlagCandidate() (TargetFlagCandidate, bool) {
	if !r.hasTargetFlags || !r.targetFlags.Valid() || r.targetFlags.sequence != r.target.Sequence {
		return TargetFlagCandidate{}, false
	}
	return r.targetFlags, true
}

// withHistory attaches one immutable walk without changing current facts.
func (r Result) withHistory(walk HistoryWalk) Result {
	if !walk.Valid() || r.target.InstanceNumber == 0 || walk.TargetInstance() != r.target.InstanceNumber {
		return r
	}
	r.history = walk.clone()
	r.hasHistory = true
	return r
}

// historyWalk returns one internal immutable history view.
func (r Result) historyWalk() (HistoryWalk, bool) {
	if !r.hasHistory || !r.history.Valid() || r.target.InstanceNumber == 0 || r.history.TargetInstance() != r.target.InstanceNumber {
		return HistoryWalk{}, false
	}
	return r.history.clone(), true
}

// withReplayProjection attaches one complete sealed replay projection.
func (r Result) withReplayProjection(projection ReplayProjection) Result {
	if !projection.Valid() {
		return r
	}
	r.replayProjection = projection.clone()
	r.hasReplayProjection = true
	return r
}

// ReplayProjection returns one independent sealed replay projection when present.
func (r Result) ReplayProjection() (ReplayProjection, bool) {
	if !r.hasReplayProjection || !r.replayProjection.Valid() {
		return ReplayProjection{}, false
	}
	return r.replayProjection.clone(), true
}

// String returns a constant representation without private verification facts.
func (Result) String() string { return "verify.Result{redacted}" }

// GoString returns a constant representation without private verification facts.
func (Result) GoString() string { return "verify.Result{redacted}" }

// Format prevents formatting from traversing private verification facts.
func (Result) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "verify.Result{redacted}")
}

// Known reports whether status is part of the per-check vocabulary.
func (s CheckStatus) Known() bool {
	switch s {
	case CheckStatusNotEvaluated, CheckStatusPass, CheckStatusFail, CheckStatusUnsupported, CheckStatusSkipped, CheckStatusNotApplicable, CheckStatusIndeterminate:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the per-signature-set vocabulary.
func (s SignatureSetStatus) Known() bool {
	switch s {
	case SignatureSetStatusNotChecked, SignatureSetStatusPass, SignatureSetStatusFail, SignatureSetStatusUnsupportedAlgorithm, SignatureSetStatusDisabledAlgorithm, SignatureSetStatusMissingKey, SignatureSetStatusInvalidKey, SignatureSetStatusAmbiguousKey, SignatureSetStatusRevokedKey, SignatureSetStatusUnsupportedKeyType, SignatureSetStatusKeyAlgorithmMismatch, SignatureSetStatusWrongKeyType, SignatureSetStatusKeyPolicyRejected, SignatureSetStatusProviderError, SignatureSetStatusProviderTemporary, SignatureSetStatusProviderPermanent, SignatureSetStatusProviderContract:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the key-status vocabulary.
func (s KeyStatus) Known() bool {
	switch s {
	case KeyStatusNotChecked, KeyStatusFound, KeyStatusMissing, KeyStatusInvalid, KeyStatusAmbiguous, KeyStatusRevoked, KeyStatusUnsupportedKeyType, KeyStatusAlgorithmMismatch, KeyStatusWrongType, KeyStatusPolicyRejected, KeyStatusUnsupportedAlgorithm, KeyStatusDisabledAlgorithm, KeyStatusProviderError, KeyStatusProviderTemporary, KeyStatusProviderPermanent, KeyStatusProviderContract:
		return true
	default:
		return false
	}
}

// Known reports whether custody status belongs to the closed verification vocabulary.
func (s CustodyStatus) Known() bool {
	switch s {
	case CustodyStatusNotPresent, CustodyStatusNDLinksEvaluated, CustodyStatusTerminalNDRequiresOOB:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the timestamp-status vocabulary.
func (s TimestampStatus) Known() bool {
	switch s {
	case TimestampStatusNotChecked, TimestampStatusPass, TimestampStatusFuture, TimestampStatusExpired, TimestampStatusNoMaxAge, TimestampStatusNotApplicable, TimestampStatusInvalid:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the envelope-status vocabulary.
func (s EnvelopeStatus) Known() bool {
	switch s {
	case EnvelopeStatusNotChecked, EnvelopeStatusPass, EnvelopeStatusMissing, EnvelopeStatusMismatch, EnvelopeStatusInvalid, EnvelopeStatusReversePathMismatch, EnvelopeStatusRecipientValueMismatch, EnvelopeStatusNotApplicable:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the domain-alignment vocabulary.
func (s DomainAlignmentStatus) Known() bool {
	switch s {
	case DomainAlignmentStatusNotChecked, DomainAlignmentStatusPass, DomainAlignmentStatusMismatch, DomainAlignmentStatusInvalid, DomainAlignmentStatusNotApplicable:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the next-domain vocabulary.
func (s NextDomainStatus) Known() bool {
	switch s {
	case NextDomainStatusNotChecked, NextDomainStatusPass, NextDomainStatusMismatch, NextDomainStatusMissingNext, NextDomainStatusOutOfBandRequired, NextDomainStatusNotApplicable:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the hash-status vocabulary.
func (s HashStatus) Known() bool {
	switch s {
	case HashStatusNotChecked, HashStatusPass, HashStatusMismatch, HashStatusMissingSHA256, HashStatusUnsupported, HashStatusInvalid:
		return true
	default:
		return false
	}
}

// Known reports whether status is part of the overall target vocabulary.
func (s TargetStatus) Known() bool {
	switch s {
	case TargetStatusNotEvaluated, TargetStatusPass, TargetStatusFail, TargetStatusMixed, TargetStatusUnsupported, TargetStatusIndeterminate, TargetStatusUnknown:
		return true
	default:
		return false
	}
}

// boundedTargetStatus preserves a detectable fixed token for unknown internal status.
func boundedTargetStatus(status TargetStatus) TargetStatus {
	if status.Known() {
		return status
	}
	return TargetStatusUnknown
}

// cloneCheckResults returns immutable copies of check facts.
func cloneCheckResults(input []CheckResult) []CheckResult {
	cloned := slices.Clone(input)
	for i := range cloned {
		cloned[i].Algorithm = sanitizeResultAlgorithm(cloned[i].Algorithm)
	}

	return cloned
}

// cloneSignatureSetResults returns immutable copies of signature-set facts.
func cloneSignatureSetResults(input []SignatureSetResult) []SignatureSetResult {
	cloned := slices.Clone(input)
	for i := range cloned {
		cloned[i].Algorithm = sanitizeResultAlgorithm(cloned[i].Algorithm)
	}

	return cloned
}

// sanitizeResultAlgorithm maps unrecognized result tokens to a fixed non-secret value.
func sanitizeResultAlgorithm(algorithm Algorithm) Algorithm {
	if algorithm == "" || knownAlgorithm(algorithm) {
		return algorithm
	}

	return AlgorithmUnknown
}
