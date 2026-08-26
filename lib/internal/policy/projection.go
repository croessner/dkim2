package policy

import "slices"

const hardMaxSignatureFacts = 16

// VerificationReason identifies the authoritative aggregate verification reason.
type VerificationReason string

// Closed verification reason constants required by DNS testing policy.
const (
	VerificationReasonNone                    VerificationReason = "none"
	VerificationReasonLimitExceeded           VerificationReason = "limit_exceeded"
	VerificationReasonMalformedMessage        VerificationReason = "malformed_message"
	VerificationReasonMalformedProtocol       VerificationReason = "malformed_protocol"
	VerificationReasonDuplicateHashAlgorithm  VerificationReason = "duplicate_hash_algorithm"
	VerificationReasonInvalidRecipeJSON       VerificationReason = "invalid_recipe_json"
	VerificationReasonDuplicateSelector       VerificationReason = "duplicate_selector"
	VerificationReasonTooManySignatures       VerificationReason = "too_many_signatures"
	VerificationReasonMissingProtocol         VerificationReason = "missing_protocol"
	VerificationReasonSequenceInvalid         VerificationReason = "sequence_invalid"
	VerificationReasonUnsupportedAlgorithm    VerificationReason = "unsupported_algorithm"
	VerificationReasonHashMismatch            VerificationReason = "hash_mismatch"
	VerificationReasonSignatureMismatch       VerificationReason = "signature_mismatch"
	VerificationReasonMissingKey              VerificationReason = "missing_key"
	VerificationReasonInvalidKey              VerificationReason = "invalid_key"
	VerificationReasonAmbiguousKey            VerificationReason = "ambiguous_key"
	VerificationReasonRevokedKey              VerificationReason = "revoked_key"
	VerificationReasonUnsupportedKeyType      VerificationReason = "unsupported_key_type"
	VerificationReasonKeyAlgorithmMismatch    VerificationReason = "key_algorithm_mismatch"
	VerificationReasonProviderTemporary       VerificationReason = "provider_temporary"
	VerificationReasonProviderPermanent       VerificationReason = "provider_permanent"
	VerificationReasonProviderContract        VerificationReason = "provider_contract"
	VerificationReasonTimestampInvalid        VerificationReason = "timestamp_invalid"
	VerificationReasonEnvelopeMismatch        VerificationReason = "envelope_mismatch"
	VerificationReasonDomainAlignmentMismatch VerificationReason = "domain_alignment_mismatch"
	VerificationReasonNextDomainMismatch      VerificationReason = "next_domain_mismatch"
	VerificationReasonOutOfBandRequired       VerificationReason = "out_of_band_required"
	VerificationReasonInternalContract        VerificationReason = "internal_contract"
)

// Known reports whether reason belongs to the closed verification vocabulary.
func (r VerificationReason) Known() bool {
	switch r {
	case VerificationReasonNone, VerificationReasonLimitExceeded, VerificationReasonMalformedMessage,
		VerificationReasonMalformedProtocol, VerificationReasonDuplicateHashAlgorithm, VerificationReasonInvalidRecipeJSON,
		VerificationReasonDuplicateSelector, VerificationReasonTooManySignatures, VerificationReasonMissingProtocol, VerificationReasonSequenceInvalid,
		VerificationReasonUnsupportedAlgorithm, VerificationReasonHashMismatch, VerificationReasonSignatureMismatch,
		VerificationReasonMissingKey, VerificationReasonInvalidKey, VerificationReasonAmbiguousKey,
		VerificationReasonRevokedKey, VerificationReasonUnsupportedKeyType, VerificationReasonKeyAlgorithmMismatch,
		VerificationReasonProviderTemporary, VerificationReasonProviderPermanent, VerificationReasonProviderContract,
		VerificationReasonTimestampInvalid, VerificationReasonEnvelopeMismatch, VerificationReasonDomainAlignmentMismatch,
		VerificationReasonNextDomainMismatch, VerificationReasonOutOfBandRequired, VerificationReasonInternalContract:
		return true
	default:
		return false
	}
}

// HistoryCoverage identifies the authenticated history represented by a projection.
type HistoryCoverage string

const (
	// HistoryNotEvaluated records the current verifier's deliberately unevaluated history.
	HistoryNotEvaluated HistoryCoverage = "not_evaluated"
	// HistoryComplete records exact contiguous authenticated coverage through the target.
	HistoryComplete HistoryCoverage = "complete"
	// HistoryIndeterminate records explicitly partial authenticated coverage.
	HistoryIndeterminate HistoryCoverage = "indeterminate"
)

// Known reports whether coverage belongs to the closed vocabulary.
func (h HistoryCoverage) Known() bool {
	return h == HistoryNotEvaluated || h == HistoryComplete || h == HistoryIndeterminate
}

// PreTargetReason identifies why no authoritative target was available.
type PreTargetReason string

const (
	// PreTargetLimitExceeded reports a pre-target resource limit.
	PreTargetLimitExceeded PreTargetReason = "limit_exceeded"
	// PreTargetMalformedMessage reports malformed RFC 5322 input.
	PreTargetMalformedMessage PreTargetReason = "malformed_message"
	// PreTargetMalformedProtocol reports malformed DKIM2 input.
	PreTargetMalformedProtocol PreTargetReason = "malformed_protocol"
	// PreTargetDuplicateHashAlgorithm reports a repeated h= algorithm before target selection.
	PreTargetDuplicateHashAlgorithm PreTargetReason = "duplicate_hash_algorithm"
	// PreTargetDuplicateSelector reports a repeated selector before target selection.
	PreTargetDuplicateSelector PreTargetReason = "duplicate_selector"
	// PreTargetTooManySignatures reports excessive per-algorithm occurrences before target selection.
	PreTargetTooManySignatures PreTargetReason = "too_many_signatures"
	// PreTargetMissingProtocol reports absent required DKIM2 state.
	PreTargetMissingProtocol PreTargetReason = "missing_protocol"
	// PreTargetSequenceInvalid reports invalid DKIM2 sequencing.
	PreTargetSequenceInvalid PreTargetReason = "sequence_invalid"
	// PreTargetInternalContract reports an impossible internal state.
	PreTargetInternalContract PreTargetReason = "internal_contract"
)

// Known reports whether reason belongs to the closed pre-target vocabulary.
func (r PreTargetReason) Known() bool {
	switch r {
	case PreTargetLimitExceeded, PreTargetMalformedMessage, PreTargetMalformedProtocol, PreTargetDuplicateHashAlgorithm,
		PreTargetDuplicateSelector, PreTargetTooManySignatures,
		PreTargetMissingProtocol, PreTargetSequenceInvalid, PreTargetInternalContract:
		return true
	default:
		return false
	}
}

// SetAlgorithm identifies a bounded signature algorithm family.
type SetAlgorithm string

const (
	// SetAlgorithmRSA identifies RSA-SHA256.
	SetAlgorithmRSA SetAlgorithm = "rsa-sha256"
	// SetAlgorithmEd25519 identifies Ed25519-SHA256.
	SetAlgorithmEd25519 SetAlgorithm = "ed25519-sha256"
	// SetAlgorithmUnknown identifies an ignored unknown algorithm.
	SetAlgorithmUnknown SetAlgorithm = "unknown"
)

// Known reports whether algorithm belongs to the closed vocabulary.
func (a SetAlgorithm) Known() bool {
	return a == SetAlgorithmRSA || a == SetAlgorithmEd25519 || a == SetAlgorithmUnknown
}

// SetStatus identifies one sealed signature-set outcome.
type SetStatus string

const (
	// SetStatusPass reports a supported signature pass.
	SetStatusPass SetStatus = "pass"
	// SetStatusFail reports a supported signature mismatch.
	SetStatusFail SetStatus = "fail"
	// SetStatusPermerror reports a permanent set failure.
	SetStatusPermerror SetStatus = "permerror"
	// SetStatusTemperror reports a temporary provider failure.
	SetStatusTemperror SetStatus = "temperror"
	// SetStatusIgnored reports an ignored unsupported algorithm.
	SetStatusIgnored SetStatus = "ignored"
)

// Known reports whether status belongs to the closed vocabulary.
func (s SetStatus) Known() bool {
	return s == SetStatusPass || s == SetStatusFail || s == SetStatusPermerror || s == SetStatusTemperror || s == SetStatusIgnored
}

// SetReason identifies a bounded signature-set reason.
type SetReason string

// Closed signature-set reason constants retained by the policy projection.
const (
	SetReasonNone                 SetReason = "none"
	SetReasonSignatureMismatch    SetReason = "signature_mismatch"
	SetReasonUnsupportedAlgorithm SetReason = "unsupported_algorithm"
	SetReasonMissingKey           SetReason = "missing_key"
	SetReasonInvalidKey           SetReason = "invalid_key"
	SetReasonAmbiguousKey         SetReason = "ambiguous_key"
	SetReasonRevokedKey           SetReason = "revoked_key"
	SetReasonUnsupportedKeyType   SetReason = "unsupported_key_type"
	SetReasonKeyAlgorithmMismatch SetReason = "key_algorithm_mismatch"
	SetReasonProviderTemporary    SetReason = "provider_temporary"
	SetReasonProviderPermanent    SetReason = "provider_permanent"
	SetReasonProviderContract     SetReason = "provider_contract"
	SetReasonInternalContract     SetReason = "internal_contract"
)

// Known reports whether reason belongs to the closed signature-set vocabulary.
func (r SetReason) Known() bool {
	switch r {
	case SetReasonNone, SetReasonSignatureMismatch, SetReasonUnsupportedAlgorithm,
		SetReasonMissingKey, SetReasonInvalidKey, SetReasonAmbiguousKey, SetReasonRevokedKey,
		SetReasonUnsupportedKeyType, SetReasonKeyAlgorithmMismatch, SetReasonProviderTemporary,
		SetReasonProviderPermanent, SetReasonProviderContract, SetReasonInternalContract:
		return true
	default:
		return false
	}
}

// SignatureFact stores bounded pre-retention signature and DNS policy metadata.
type SignatureFact struct {
	algorithm              SetAlgorithm
	status                 SetStatus
	reason                 SetReason
	testingDeclared        bool
	strictIdentityDeclared bool
}

// NewSignatureFact constructs one coherent sealed signature-set fact.
func NewSignatureFact(algorithm SetAlgorithm, status SetStatus, reason SetReason, testing, strict bool) (SignatureFact, error) {
	fact := SignatureFact{algorithm: algorithm, status: status, reason: reason, testingDeclared: testing, strictIdentityDeclared: strict}
	if !fact.Valid() {
		return SignatureFact{}, newError(ErrorInternalContract)
	}
	return fact, nil
}

// Valid reports whether the fact has coherent closed dimensions.
func (f SignatureFact) Valid() bool {
	if !f.algorithm.Known() || !f.status.Known() || !f.reason.Known() {
		return false
	}
	metadata := f.testingDeclared || f.strictIdentityDeclared
	metadataAllowed := f.status == SetStatusPass || f.status == SetStatusFail || f.status == SetStatusPermerror &&
		(f.reason == SetReasonInvalidKey || f.reason == SetReasonRevokedKey || f.reason == SetReasonUnsupportedKeyType || f.reason == SetReasonKeyAlgorithmMismatch)
	if metadata && !metadataAllowed {
		return false
	}
	switch f.status {
	case SetStatusPass:
		return f.reason == SetReasonNone && f.algorithm != SetAlgorithmUnknown
	case SetStatusFail:
		return f.reason == SetReasonSignatureMismatch && f.algorithm != SetAlgorithmUnknown
	case SetStatusTemperror:
		return f.reason == SetReasonProviderTemporary && f.algorithm != SetAlgorithmUnknown
	case SetStatusIgnored:
		return f.reason == SetReasonUnsupportedAlgorithm && f.algorithm == SetAlgorithmUnknown && !f.testingDeclared && !f.strictIdentityDeclared
	case SetStatusPermerror:
		return f.reason != SetReasonNone && f.reason != SetReasonSignatureMismatch && f.reason != SetReasonUnsupportedAlgorithm && f.reason != SetReasonProviderTemporary &&
			(f.algorithm != SetAlgorithmUnknown || f.reason == SetReasonInternalContract)
	default:
		return false
	}
}

// Algorithm returns the bounded algorithm family.
func (f SignatureFact) Algorithm() SetAlgorithm { return f.algorithm }

// Status returns the bounded set outcome.
func (f SignatureFact) Status() SetStatus { return f.status }

// Reason returns the bounded set reason.
func (f SignatureFact) Reason() SetReason { return f.reason }

// TestingDeclared reports authenticated DNS testing metadata.
func (f SignatureFact) TestingDeclared() bool { return f.testingDeclared }

// StrictIdentityDeclared reports bounded DNS strict-identity metadata.
func (f SignatureFact) StrictIdentityDeclared() bool { return f.strictIdentityDeclared }

// HopFact stores one authenticated flag and transition fact.
type HopFact struct {
	sequence     uint64
	transition   TransitionState
	doNotModify  bool
	doNotExplode bool
	feedback     bool
	feedHere     bool
	exploded     bool
}

// NewAuthenticatedHopFact constructs one authenticated fact for service-owned minting.
func NewAuthenticatedHopFact(sequence uint64, transition TransitionState, doNotModify, doNotExplode, feedback, feedHere, exploded bool) (HopFact, error) {
	fact := HopFact{sequence: sequence, transition: transition, doNotModify: doNotModify, doNotExplode: doNotExplode, feedback: feedback, feedHere: feedHere, exploded: exploded}
	if !fact.Valid() {
		return HopFact{}, newError(ErrorInternalContract)
	}
	return fact, nil
}

// Valid reports whether the authenticated fact is structurally bounded.
func (h HopFact) Valid() bool { return h.sequence > 0 && h.transition.Known() }

// Sequence returns the authenticated signature sequence.
func (h HopFact) Sequence() uint64 { return h.sequence }

// Transition returns the authenticated transition state.
func (h HopFact) Transition() TransitionState { return h.transition }

// DoNotModify reports the authenticated modification request.
func (h HopFact) DoNotModify() bool { return h.doNotModify }

// DoNotExplode reports the authenticated explosion request.
func (h HopFact) DoNotExplode() bool { return h.doNotExplode }

// Feedback reports the authenticated feedback request.
func (h HopFact) Feedback() bool { return h.feedback }

// FeedHere reports the authenticated relay preference.
func (h HopFact) FeedHere() bool { return h.feedHere }

// Exploded reports the authenticated exploded marker.
func (h HopFact) Exploded() bool { return h.exploded }

// Projection is an immutable authenticated policy input sealed by verification service code.
type Projection struct {
	form               TargetForm
	protocol           ProtocolClass
	verificationReason VerificationReason
	targetSequence     uint64
	preTarget          PreTargetReason
	history            HistoryCoverage
	hops               []HopFact
	signatureFacts     []SignatureFact
	revisionFailure    bool
}

// NewSelectedProjection seals a selected target with aggregate reason provenance.
func NewSelectedProjection(protocol ProtocolClass, reason VerificationReason, target uint64, hops []HopFact, signatures []SignatureFact, limits Limits) (Projection, error) {
	projection := Projection{form: TargetSelected, protocol: protocol, verificationReason: reason, targetSequence: target, history: HistoryNotEvaluated, hops: slices.Clone(hops), signatureFacts: slices.Clone(signatures)}
	if err := projection.validate(limits); err != nil {
		return Projection{}, err
	}
	return projection, nil
}

// NewRevisionFailureProjection seals a selected target whose current signature sets passed before inherited history failed.
func NewRevisionFailureProjection(protocol ProtocolClass, reason VerificationReason, current Projection, limits Limits) (Projection, error) {
	if !revisionFailureProtocolReasonAllowed(protocol, reason) || !current.Valid() || current.form != TargetSelected || current.protocol != ProtocolPASS || current.history != HistoryNotEvaluated {
		return Projection{}, newError(ErrorInternalContract)
	}
	projection := Projection{
		form: TargetSelected, protocol: protocol, verificationReason: reason,
		targetSequence: current.targetSequence, history: HistoryNotEvaluated,
		signatureFacts: slices.Clone(current.signatureFacts), revisionFailure: true,
	}
	if err := projection.validate(limits); err != nil {
		return Projection{}, err
	}
	return projection, nil
}

// revisionFailureProtocolReasonAllowed mirrors the closed service revision-outcome mapping.
func revisionFailureProtocolReasonAllowed(protocol ProtocolClass, reason VerificationReason) bool {
	switch protocol {
	case ProtocolFAIL:
		return reason == VerificationReasonHashMismatch || reason == VerificationReasonSignatureMismatch
	case ProtocolTEMPERROR:
		return reason == VerificationReasonProviderTemporary
	case ProtocolPERMERROR:
		switch reason {
		case VerificationReasonUnsupportedAlgorithm, VerificationReasonProviderPermanent,
			VerificationReasonProviderContract, VerificationReasonLimitExceeded,
			VerificationReasonOutOfBandRequired, VerificationReasonInvalidRecipeJSON,
			VerificationReasonMalformedProtocol, VerificationReasonInternalContract:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// NewUnavailableProjection seals one exact pre-target permanent-error projection.
func NewUnavailableProjection(reason PreTargetReason) (Projection, error) {
	if !reason.Known() {
		return Projection{}, newError(ErrorInvalidInput)
	}
	projection := Projection{form: TargetUnavailable, protocol: ProtocolPERMERROR, preTarget: reason, history: HistoryNotEvaluated}
	if err := projection.validate(DefaultLimits()); err != nil {
		return Projection{}, err
	}
	return projection, nil
}

// NewHistoricalProjection constructs an authenticated all-hop policy projection.
func NewHistoricalProjection(target uint64, coverage HistoryCoverage, hops []HopFact, limits Limits) (Projection, error) {
	projection := Projection{form: TargetSelected, protocol: ProtocolPASS, verificationReason: VerificationReasonNone, targetSequence: target, history: coverage, hops: slices.Clone(hops)}
	if err := projection.validate(limits); err != nil {
		return Projection{}, err
	}
	return projection, nil
}

// newHistoricalProjection retains the package-local test seam.
func newHistoricalProjection(target uint64, coverage HistoryCoverage, hops []HopFact, limits Limits) (Projection, error) {
	return NewHistoricalProjection(target, coverage, hops, limits)
}

// validate enforces projection form, resource, and provenance invariants.
func (p Projection) validate(limits Limits) error {
	if limits.Validate() != nil {
		return newError(ErrorInvalidConfig)
	}
	if len(p.hops) > limits.MaxAuthenticatedHops {
		return newLimitError(limitNameAuthenticatedHops, limits.MaxAuthenticatedHops, len(p.hops))
	}
	if len(p.signatureFacts) > hardMaxSignatureFacts {
		return newError(ErrorInternalContract)
	}
	if p.form == TargetUnavailable {
		return p.validateUnavailable()
	}
	return p.validateSelected()
}

// validateUnavailable enforces the exact zero-target permanent form.
func (p Projection) validateUnavailable() error {
	if p.protocol != ProtocolPERMERROR || p.verificationReason != "" || p.targetSequence != 0 || !p.preTarget.Known() || p.history != HistoryNotEvaluated || len(p.hops) != 0 || len(p.signatureFacts) != 0 || p.revisionFailure {
		return newError(ErrorInternalContract)
	}
	return nil
}

// validateSelected enforces current and historical selected-target invariants.
func (p Projection) validateSelected() error {
	if p.form != TargetSelected || !p.protocol.Known() || !p.verificationReason.Known() || !verificationReasonProtocolCoherent(p.protocol, p.verificationReason) || p.targetSequence == 0 || p.preTarget != "" || !p.history.Known() {
		return newError(ErrorInternalContract)
	}
	for _, fact := range p.signatureFacts {
		if !fact.Valid() {
			return newError(ErrorInternalContract)
		}
	}
	if p.history == HistoryNotEvaluated {
		return p.validateCurrent()
	}
	return p.validateHistory()
}

// validateCurrent enforces the current-only PASS authentication boundary.
func (p Projection) validateCurrent() error {
	if p.revisionFailure {
		return p.validateRevisionFailure()
	}
	if len(p.signatureFacts) == 0 {
		return newError(ErrorInternalContract)
	}
	if p.protocol == ProtocolPASS && len(p.hops) != 1 || p.protocol != ProtocolPASS && len(p.hops) != 0 {
		return newError(ErrorInternalContract)
	}
	if len(p.hops) == 1 && (p.hops[0].sequence != p.targetSequence || !p.hops[0].Valid() || p.hops[0].transition != currentTransition(p.targetSequence)) {
		return newError(ErrorInternalContract)
	}
	if !p.signatureProtocolCoherent() {
		return newError(ErrorInternalContract)
	}
	if !p.verificationReasonFactsCoherent() {
		return newError(ErrorInternalContract)
	}
	return nil
}

// validateRevisionFailure distinguishes passing current-set evidence from an outcome-driving inherited failure.
func (p Projection) validateRevisionFailure() error {
	if !revisionFailureProtocolReasonAllowed(p.protocol, p.verificationReason) || len(p.hops) != 0 || len(p.signatureFacts) == 0 {
		return newError(ErrorInternalContract)
	}
	supportedPass := false
	for _, fact := range p.signatureFacts {
		if fact.status == SetStatusPass {
			supportedPass = true
			continue
		}
		if fact.status != SetStatusIgnored {
			return newError(ErrorInternalContract)
		}
	}
	if !supportedPass {
		return newError(ErrorInternalContract)
	}
	return nil
}

// verificationReasonFactsCoherent binds outcome-driving set facts to aggregate reason.
func (p Projection) verificationReasonFactsCoherent() bool {
	switch p.protocol {
	case ProtocolPASS:
		return p.verificationReason == VerificationReasonNone
	case ProtocolFAIL:
		if p.verificationReason == VerificationReasonSignatureMismatch {
			for _, fact := range p.signatureFacts {
				if fact.status == SetStatusFail {
					return true
				}
			}
			return false
		}
		for _, fact := range p.signatureFacts {
			if fact.status == SetStatusFail {
				return false
			}
		}
		return true
	case ProtocolTEMPERROR:
		return p.verificationReason == VerificationReasonProviderTemporary
	case ProtocolPERMERROR:
		return p.eligiblePermanentPrimaryCoherent()
	default:
		return false
	}
}

// eligiblePermanentPrimaryCoherent locks mixed DNS-eligible key reason precedence.
func (p Projection) eligiblePermanentPrimaryCoherent() bool {
	if p.verificationReason == VerificationReasonMalformedMessage || p.verificationReason == VerificationReasonMalformedProtocol ||
		p.verificationReason == VerificationReasonDuplicateHashAlgorithm || p.verificationReason == VerificationReasonInvalidRecipeJSON ||
		p.verificationReason == VerificationReasonDuplicateSelector || p.verificationReason == VerificationReasonTooManySignatures ||
		p.verificationReason == VerificationReasonMissingProtocol || p.verificationReason == VerificationReasonSequenceInvalid {
		return false
	}
	primaryRank := permanentProjectionReasonRank(p.verificationReason)
	for _, fact := range p.signatureFacts {
		factReason := VerificationReason("")
		if fact.status == SetStatusPermerror {
			factReason = VerificationReason(fact.reason)
		}
		if factReason != "" && permanentProjectionReasonRank(factReason) < primaryRank {
			return false
		}
	}
	wantRank := permanentSetReasonRank(p.verificationReason)
	if wantRank < 0 {
		return true
	}
	observedRank := 99
	observed := false
	for _, fact := range p.signatureFacts {
		if fact.status != SetStatusPermerror {
			continue
		}
		rank := permanentSetReasonRank(VerificationReason(fact.reason))
		if rank < 0 {
			return false
		}
		observed = true
		if rank < observedRank {
			observedRank = rank
		}
	}
	return observed && observedRank == wantRank
}

// permanentProjectionReasonRank mirrors authoritative permanent service precedence.
func permanentProjectionReasonRank(reason VerificationReason) int {
	for index, candidate := range []VerificationReason{
		VerificationReasonInternalContract, VerificationReasonLimitExceeded, VerificationReasonMalformedMessage,
		VerificationReasonMalformedProtocol, VerificationReasonDuplicateHashAlgorithm, VerificationReasonInvalidRecipeJSON,
		VerificationReasonDuplicateSelector, VerificationReasonTooManySignatures, VerificationReasonMissingProtocol, VerificationReasonSequenceInvalid,
		VerificationReasonUnsupportedAlgorithm, VerificationReasonMissingKey, VerificationReasonRevokedKey,
		VerificationReasonUnsupportedKeyType, VerificationReasonKeyAlgorithmMismatch, VerificationReasonInvalidKey,
		VerificationReasonAmbiguousKey, VerificationReasonProviderPermanent, VerificationReasonProviderContract,
		VerificationReasonTimestampInvalid, VerificationReasonEnvelopeMismatch, VerificationReasonDomainAlignmentMismatch,
		VerificationReasonNextDomainMismatch, VerificationReasonOutOfBandRequired,
	} {
		if reason == candidate {
			return index
		}
	}
	return 0
}

// permanentSetReasonRank mirrors service precedence for set-derived permanent outcomes.
func permanentSetReasonRank(reason VerificationReason) int {
	switch reason {
	case VerificationReasonMissingKey:
		return 0
	case VerificationReasonRevokedKey:
		return 1
	case VerificationReasonUnsupportedKeyType:
		return 2
	case VerificationReasonKeyAlgorithmMismatch:
		return 3
	case VerificationReasonInvalidKey:
		return 4
	case VerificationReasonAmbiguousKey:
		return 5
	case VerificationReasonProviderPermanent:
		return 6
	case VerificationReasonProviderContract:
		return 7
	default:
		return -1
	}
}

// eligiblePermanentRank mirrors authoritative service primary-reason ordering.
func eligiblePermanentRank(reason VerificationReason) int {
	switch reason {
	case VerificationReasonRevokedKey:
		return 0
	case VerificationReasonUnsupportedKeyType:
		return 1
	case VerificationReasonKeyAlgorithmMismatch:
		return 2
	case VerificationReasonInvalidKey:
		return 3
	default:
		return -1
	}
}

// verificationReasonProtocolCoherent binds aggregate state to its reason class.
func verificationReasonProtocolCoherent(protocol ProtocolClass, reason VerificationReason) bool {
	switch protocol {
	case ProtocolPASS:
		return reason == VerificationReasonNone
	case ProtocolFAIL:
		return reason == VerificationReasonHashMismatch || reason == VerificationReasonSignatureMismatch
	case ProtocolTEMPERROR:
		return reason == VerificationReasonProviderTemporary
	case ProtocolPERMERROR:
		return reason.Known() && reason != VerificationReasonNone && reason != VerificationReasonHashMismatch && reason != VerificationReasonSignatureMismatch && reason != VerificationReasonProviderTemporary
	default:
		return false
	}
}

// signatureProtocolCoherent binds aggregate protocol class to complete set outcomes.
func (p Projection) signatureProtocolCoherent() bool {
	supportedPass := 0
	failures := 0
	temporary := 0
	permanent := 0
	for _, fact := range p.signatureFacts {
		switch fact.status {
		case SetStatusPass:
			supportedPass++
		case SetStatusFail:
			failures++
		case SetStatusTemperror:
			temporary++
		case SetStatusPermerror:
			permanent++
		case SetStatusIgnored:
		default:
			return false
		}
	}
	switch p.protocol {
	case ProtocolPASS:
		return supportedPass > 0 && failures == 0 && temporary == 0 && permanent == 0
	case ProtocolFAIL:
		return supportedPass+failures > 0 && temporary == 0 && permanent == 0
	case ProtocolTEMPERROR:
		return temporary > 0 && failures == 0 && permanent == 0
	case ProtocolPERMERROR:
		return true
	default:
		return false
	}
}

// validateHistory enforces bounded explicit partial or contiguous complete history.
func (p Projection) validateHistory() error {
	if len(p.signatureFacts) != 0 || len(p.hops) == 0 || p.revisionFailure {
		return newError(ErrorInternalContract)
	}
	if p.history == HistoryComplete {
		if p.targetSequence != uint64(len(p.hops)) {
			return newError(ErrorInternalContract)
		}
	}
	previous := uint64(0)
	for index, hop := range p.hops {
		if !hop.Valid() || hop.sequence > p.targetSequence || hop.sequence <= previous {
			return newError(ErrorInternalContract)
		}
		if index == 0 && hop.sequence == 1 {
			if hop.transition != TransitionOrigin {
				return newError(ErrorInternalContract)
			}
		} else if hop.transition == TransitionOrigin {
			return newError(ErrorInternalContract)
		}
		if p.history == HistoryComplete && (hop.sequence != uint64(index+1) || index > 0 && hop.transition == TransitionNotEvaluated) {
			return newError(ErrorInternalContract)
		}
		previous = hop.sequence
	}
	return nil
}

// currentTransition returns the only truthful transition for current-only verification.
func currentTransition(target uint64) TransitionState {
	if target == 1 {
		return TransitionOrigin
	}
	return TransitionNotEvaluated
}

// Valid reports whether the projection satisfies hard-limit invariants.
func (p Projection) Valid() bool { return p.validate(DefaultLimits()) == nil }

// IsZero reports whether the projection is uninitialized.
func (p Projection) IsZero() bool {
	return p.form == "" && p.protocol == "" && p.verificationReason == "" && p.targetSequence == 0 && p.preTarget == "" && p.history == "" && len(p.hops) == 0 && len(p.signatureFacts) == 0 && !p.revisionFailure
}

// Form returns the exact target form.
func (p Projection) Form() TargetForm { return p.form }

// Protocol returns the authoritative protocol class.
func (p Projection) Protocol() ProtocolClass { return p.protocol }

// VerificationReason returns the authoritative aggregate reason for selected targets.
func (p Projection) VerificationReason() VerificationReason { return p.verificationReason }

// TargetSequence returns the authoritative target sequence.
func (p Projection) TargetSequence() uint64 { return p.targetSequence }

// PreTargetReason returns the bounded unavailable-target reason.
func (p Projection) PreTargetReason() PreTargetReason { return p.preTarget }

// HistoryCoverage returns the authenticated history coverage state.
func (p Projection) HistoryCoverage() HistoryCoverage { return p.history }

// Hops returns an independent authenticated-fact clone.
func (p Projection) Hops() []HopFact { return slices.Clone(p.hops) }

// SignatureFacts returns an independent pre-retention signature-fact clone.
func (p Projection) SignatureFacts() []SignatureFact { return slices.Clone(p.signatureFacts) }

// Clone returns an independent projection value with cloned collections.
func (p Projection) Clone() Projection {
	p.hops = slices.Clone(p.hops)
	p.signatureFacts = slices.Clone(p.signatureFacts)
	return p
}
