package service

import (
	"context"

	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

// Verifier owns validated current-verification coordination dependencies.
type Verifier struct {
	core        verify.Verifier
	limits      Limits
	initialized bool
}

// Assessment is one closed inbound applicability decision with an optional verification result.
type Assessment struct {
	result      Result
	applicable  bool
	initialized bool
}

// Valid reports whether the assessment is either not applicable or owns one valid result.
func (a Assessment) Valid() bool {
	return a.initialized && (!a.applicable || a.result.State().Known())
}

// Applicable reports whether DKIM2 protocol fields required an actual verification.
func (a Assessment) Applicable() bool { return a.initialized && a.applicable }

// Verification returns the four-state result only when verification was applicable.
func (a Assessment) Verification() (Result, bool) {
	if !a.Valid() || !a.applicable {
		return Result{}, false
	}
	return a.result, true
}

// NewVerifier constructs a service coordinator with immutable validated policy.
func NewVerifier(provider verify.KeyProvider, config Config) (Verifier, error) {
	if nilKeyProvider(provider) || config.Limits.Validate() != nil || config.Clock == nil {
		return Verifier{}, newError(ErrorInvalidConfig)
	}
	core, err := verify.NewVerifier(provider,
		verify.WithAlgorithmPolicy(config.AlgorithmPolicy),
		verify.WithClock(config.Clock),
		verify.WithLimits(verify.Limits{
			MaxInstanceHashSets:   config.Limits.MaxInstanceHashSets,
			MaxSignatureSets:      config.Limits.MaxSignatureSets,
			MaxEnvelopeRecipients: config.Limits.MaxRecipients,
		}),
	)
	if err != nil {
		return Verifier{}, newError(ErrorInvalidConfig)
	}
	return Verifier{core: core, limits: config.Limits, initialized: true}, nil
}

// Core returns the validated protocol-core verifier so that facades built on
// the same provider, limits, clock, and policy can reuse it for evaluations
// the coordinator does not own, such as received-DSN evaluation.
func (v Verifier) Core() verify.Verifier {
	if !v.initialized {
		return verify.Verifier{}
	}
	return v.core
}

// nilKeyProvider reports nil and typed-nil injected interface dependencies.
func nilKeyProvider(provider verify.KeyProvider) bool {
	return niliface.IsNil(provider)
}

// Verify parses raw input, delegates protocol verification, and returns one disjoint outcome.
func (v Verifier) Verify(ctx context.Context, request Request) (Result, error) {
	return v.verify(ctx, request, false)
}

// Assess classifies complete protocol absence before starting DKIM2 verification.
func (v Verifier) Assess(ctx context.Context, request Request) (Assessment, error) {
	result, applicable, err := v.assess(ctx, request)
	return Assessment{
		result: result, applicable: applicable, initialized: err == nil || applicable,
	}, err
}

// verify preserves the explicit four-state verification entry point.
func (v Verifier) verify(ctx context.Context, request Request, classifyAbsence bool) (Result, error) {
	result, _, err := v.assessWithAbsencePolicy(ctx, request, classifyAbsence)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// assess owns parsing, applicability classification, and current verification.
func (v Verifier) assess(ctx context.Context, request Request) (Result, bool, error) {
	return v.assessWithAbsencePolicy(ctx, request, true)
}

// assessWithAbsencePolicy shares all preflight work without changing explicit Verify semantics.
func (v Verifier) assessWithAbsencePolicy(ctx context.Context, request Request, classifyAbsence bool) (Result, bool, error) {
	if !v.initialized || v.limits.Validate() != nil {
		return Result{}, false, newError(ErrorInvalidConfig)
	}
	if ctx == nil {
		return Result{}, false, newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, false, err
	}
	raw := request.RawMessage()
	forward := request.ForwardPaths()
	if len(raw) > v.limits.MaxRawMessageBytes || len(forward) > v.limits.MaxRecipients {
		return preExtractionResult(ReasonLimitExceeded), true, nil
	}

	options := rawmsg.DefaultParserOptions()
	options.MaxMessageBytes = v.limits.MaxRawMessageBytes
	message, err := rawmsg.ParseWithOptions(raw, options)
	if err != nil {
		reason := ReasonMalformedMessage
		if rawmsg.IsParserErrorCode(err, rawmsg.ErrorCodeLimitExceeded) {
			reason = ReasonLimitExceeded
		}
		return preExtractionResult(reason), true, nil
	}
	if classifyAbsence && !verify.ProtocolApplicable(message) {
		return Result{}, false, nil
	}

	coreRequest := verify.Request{
		Message: message, Envelope: verify.NewEnvelope(request.ReversePath(), forward), RequireEnvelope: true,
	}
	coreResult, err := v.core.VerifyCurrent(ctx, coreRequest)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, true, ctxErr
	}
	if err != nil {
		return mapVerificationError(err), true, nil
	}
	current := mapVerificationResult(coreResult, v.limits)
	if current.State() != StatePASS {
		return current, true, nil
	}
	outcome, proof, err := v.core.VerifyRevisionProofAfterCurrent(ctx, coreRequest, coreResult)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, true, ctxErr
	}
	if err != nil {
		return Result{}, true, err
	}
	if outcome != verify.RevisionProofVerified {
		return mapRevisionProofFailure(current, outcome), true, nil
	}
	return attachRevisionProof(current, proof), true, nil
}

// mapRevisionProofFailure prevents a current-only PASS from escaping after
// all-hop rejection. An inherited signature's permanent key failure keeps
// its specific reason, as the current target does; no privacy rule requires
// collapsing it into provider_permanent. The state of every reason comes
// from its single Draft-08 Section 14.1 owner.
func mapRevisionProofFailure(current Result, outcome verify.RevisionProofOutcome) Result {
	reason, class := ReasonMalformedProtocol, CheckProtocol
	switch outcome {
	case verify.RevisionProofHashMismatch:
		reason, class = ReasonHashMismatch, CheckBodyHash
	case verify.RevisionProofSignatureMismatch:
		reason, class = ReasonSignatureMismatch, CheckSignature
	case verify.RevisionProofUnsupported:
		reason = ReasonUnsupportedAlgorithm
	case verify.RevisionProofProviderTemporary:
		reason, class = ReasonProviderTemporary, CheckProvider
	case verify.RevisionProofProviderRejected:
		reason, class = ReasonProviderPermanent, CheckProvider
	case verify.RevisionProofMissingKey:
		reason, class = ReasonMissingKey, CheckKey
	case verify.RevisionProofInvalidKey:
		reason, class = ReasonInvalidKey, CheckKey
	case verify.RevisionProofRevokedKey:
		reason, class = ReasonRevokedKey, CheckKey
	case verify.RevisionProofAmbiguousKey:
		reason, class = ReasonAmbiguousKey, CheckKey
	case verify.RevisionProofUnsupportedKeyType:
		reason, class = ReasonUnsupportedKeyType, CheckKey
	case verify.RevisionProofKeyAlgorithmMismatch:
		reason, class = ReasonKeyAlgorithmMismatch, CheckKey
	case verify.RevisionProofProviderContract:
		reason, class = ReasonProviderContract, CheckProvider
	case verify.RevisionProofLimitExceeded:
		reason = ReasonLimitExceeded
	case verify.RevisionProofTerminalNextDomainAuthorizationRequired:
		reason, class = ReasonOutOfBandRequired, CheckNextDomain
	case verify.RevisionProofInvalidRecipeJSON:
		reason = ReasonInvalidRecipeJSON
	case verify.RevisionProofInvalidRecipe:
		reason = ReasonInvalidRecipe
	case verify.RevisionProofBodyHistoryUnavailable:
		reason, class = ReasonBodyHistoryUnavailable, CheckBodyHash
	case verify.RevisionProofFromNotAuthentic:
		reason = ReasonFromNotAuthentic
	case verify.RevisionProofProtocolRejected:
	default:
		reason, class = ReasonInternalContract, CheckInternalContract
	}
	state := StateForReason(reason)
	result := newResult(state, current.Custody(), current.Target(), reason, []CheckFact{{Class: class, Reason: reason}}, nil)
	protocol, protocolOK := policyProtocolClass(state)
	verificationReason, reasonOK := policyVerificationReason(reason)
	if !protocolOK || !reasonOK {
		return internalContractResult(current.Target())
	}
	projection, err := policy.NewRevisionFailureProjection(protocol, verificationReason, current.PolicyProjection(), policy.DefaultLimits())
	if err != nil {
		return internalContractResult(current.Target())
	}
	return result.withPolicyProjection(projection)
}

// attachRevisionProof projects only immutable authenticated all-hop facts.
func attachRevisionProof(current Result, proof verify.RevisionProof) Result {
	if !proof.Valid() || proof.State() != verify.RevisionProofVerified {
		return internalContractResult(current.Target())
	}
	facts := proof.Facts()
	if !facts.Valid() || facts.HighestSequence() != current.Target().Sequence || facts.HighestInstance() != current.Target().Instance {
		return internalContractResult(current.Target())
	}
	if current.Target() == (Target{Sequence: 1, Instance: 1}) {
		return attachOriginProof(current, proof)
	}
	// A null body Recipe is refused by the core proof (Draft-08 Section 13);
	// a verified proof that still carries the gap is an internal defect.
	if facts.HistoryHasUnavailableBody() {
		return internalContractResult(current.Target())
	}
	history := HistoricalComplete
	policyCoverage := policy.HistoryComplete
	signatures := facts.Signatures()
	hops := make([]policy.HopFact, len(signatures))
	for index, signatureFact := range signatures {
		transition := policy.TransitionIndeterminate
		if index == 0 {
			transition = policy.TransitionOrigin
		}
		flags := signatureFact.Flags()
		hop, err := policy.NewAuthenticatedHopFact(signatureFact.Sequence(), transition,
			flags.Feedback(), flags.FeedHere(), flags.Exploded())
		if err != nil {
			return internalContractResult(current.Target())
		}
		hops[index] = hop
	}
	projection, err := policy.NewHistoricalProjection(current.Target().Sequence, policyCoverage, hops, policy.DefaultLimits())
	if err != nil {
		return internalContractResult(current.Target())
	}
	result := current.withAuthenticatedHistory(history, projection)
	sourceVerifier, hasVerifier := proof.VerifierProjection()
	if !hasVerifier {
		return internalContractResult(current.Target())
	}
	verifierProjection, mapped := mapVerifierProjection(sourceVerifier)
	if !mapped {
		return internalContractResult(current.Target())
	}
	result = result.withVerifierProjection(verifierProjection)
	if source, ok := proof.ReplayProjection(); ok {
		if replayProjection, mapped := mapReplayProjection(source); mapped {
			result = result.withReplayProjection(replayProjection)
		}
	}
	return result
}

// attachOriginProof upgrades origin coverage while preserving current policy and DNS metadata.
func attachOriginProof(current Result, proof verify.RevisionProof) Result {
	result := current.withAuthenticatedOrigin()
	sourceVerifier, present := proof.VerifierProjection()
	if !present {
		return internalContractResult(current.Target())
	}
	verifierProjection, mapped := mapVerifierProjection(sourceVerifier)
	if !mapped {
		return internalContractResult(current.Target())
	}
	result = result.withVerifierProjection(verifierProjection)
	if sourceReplay, replayPresent := proof.ReplayProjection(); replayPresent {
		if replayProjection, replayMapped := mapReplayProjection(sourceReplay); replayMapped {
			result = result.withReplayProjection(replayProjection)
		}
	}
	return result
}

// preExtractionResult returns truthful indeterminate custody after early failure.
func preExtractionResult(reason Reason) Result {
	class := CheckMessage
	if reason != ReasonMalformedMessage && reason != ReasonLimitExceeded {
		class = CheckInternalContract
	}
	result := newResult(StatePERMERROR, CustodyNotEvaluated, Target{}, reason, []CheckFact{{Class: class, Reason: reason}}, nil)
	projection, err := buildUnavailablePolicyProjection(reason)
	if err != nil {
		return internalContractResult(Target{})
	}
	return result.withPolicyProjection(projection)
}

// mapVerificationError sanitizes protocol errors into populated service results.
func mapVerificationError(err error) Result {
	reason := ReasonMalformedProtocol
	class := CheckProtocol
	var target Target
	custody := CustodyNotEvaluated
	if typed, ok := err.(*verify.Error); ok {
		location := typed.Location()
		target = Target{Sequence: location.TargetSequence, Instance: location.InstanceNumber}
		if typed.CustodyStatus().Known() {
			custody = mapCustody(typed.CustodyStatus())
		}
		reason, class, state := mapVerificationErrorCode(typed.Code())
		if selected, ok := typed.SelectedTarget(); ok && typed.ChainOfCustodyFailure() {
			return chainOfCustodyFailureResult(custody, Target{Sequence: selected.Sequence, Instance: selected.InstanceNumber}, reason, class)
		}
		if verificationErrorHasUnavailableTarget(typed.Code(), target) {
			target = Target{}
			reason, class, state = unavailableVerificationFailure(typed.Code(), reason, class, state)
		}
		result := newResult(state, custody, target, reason, []CheckFact{{Class: class, Reason: reason}}, nil)
		if target == (Target{}) {
			projection, projectionErr := buildUnavailablePolicyProjection(reason)
			if projectionErr != nil {
				return internalContractResult(Target{})
			}
			return result.withPolicyProjection(projection)
		}
		return result
	}
	result := newResult(StatePERMERROR, custody, target, reason, []CheckFact{{Class: class, Reason: reason}}, nil)
	projection, projectionErr := buildUnavailablePolicyProjection(reason)
	if projectionErr != nil {
		return internalContractResult(Target{})
	}
	return result.withPolicyProjection(projection)
}

// chainOfCustodyFailureResult reports a Draft-08 Section 14.4 Chain of
// Custody failure for the already selected target. The verifier stopped
// before any key lookup, so the sealed policy projection carries neither
// signature facts nor authenticated hops.
func chainOfCustodyFailureResult(custody Custody, target Target, reason Reason, class CheckClass) Result {
	verificationReason, ok := policyVerificationReason(reason)
	if !ok || StateForReason(reason) != StateFAIL {
		return internalContractResult(target)
	}
	projection, err := policy.NewChainFailureProjection(verificationReason, target.Sequence)
	if err != nil {
		return internalContractResult(target)
	}
	result := newResult(StateFAIL, custody, target, reason, []CheckFact{{Class: class, Reason: reason}}, nil)
	return result.withPolicyProjection(projection)
}

// verificationErrorHasUnavailableTarget identifies failures before authoritative selection.
func verificationErrorHasUnavailableTarget(code verify.ErrorCode, diagnosticTarget Target) bool {
	if diagnosticTarget.Sequence == 0 || diagnosticTarget.Instance == 0 {
		return true
	}
	switch code {
	case verify.ErrorCodeLimitExceeded, verify.ErrorCodeMissingTarget, verify.ErrorCodeDuplicateTarget,
		verify.ErrorCodeSequenceInvalid, verify.ErrorCodeDuplicateHashAlgorithm,
		verify.ErrorCodeDuplicateSelector:
		return true
	default:
		return false
	}
}

// unavailableVerificationFailure normalizes pre-target errors to one sealable policy taxonomy.
func unavailableVerificationFailure(code verify.ErrorCode, reason Reason, class CheckClass, state State) (Reason, CheckClass, State) {
	switch code {
	case verify.ErrorCodeCustodyMismatch, verify.ErrorCodeNextDomainMismatch, verify.ErrorCodeMissingNextSignature,
		verify.ErrorCodeDomainAlignmentMismatch:
		// A Chain of Custody failure without a selected target cannot be
		// bound to a verified result and stays a permanent protocol error.
		return ReasonMalformedProtocol, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeLimitExceeded, verify.ErrorCodeMissingTarget, verify.ErrorCodeDuplicateTarget,
		verify.ErrorCodeSequenceInvalid, verify.ErrorCodeMalformedState, verify.ErrorCodeDuplicateHashAlgorithm,
		verify.ErrorCodeDuplicateSelector:
		return reason, class, state
	default:
		return ReasonInternalContract, CheckInternalContract, StatePERMERROR
	}
}

// mapVerificationErrorCode exhaustively maps bounded verification error
// codes to a reason and check class; the state comes from the single
// Draft-08 Section 14.1 owner.
func mapVerificationErrorCode(code verify.ErrorCode) (Reason, CheckClass, State) {
	reason, class := verificationErrorReason(code)
	return reason, class, StateForReason(reason)
}

// verificationErrorReason maps one bounded verification error code.
func verificationErrorReason(code verify.ErrorCode) (Reason, CheckClass) {
	switch code {
	case verify.ErrorCodeLimitExceeded:
		return ReasonLimitExceeded, CheckProtocol
	case verify.ErrorCodeDuplicateHashAlgorithm:
		return ReasonDuplicateHashAlgorithm, CheckProtocol
	case verify.ErrorCodeInvalidRecipeJSON:
		return ReasonInvalidRecipeJSON, CheckProtocol
	case verify.ErrorCodeDuplicateSelector:
		return ReasonDuplicateSelector, CheckProtocol
	case verify.ErrorCodeMissingTarget:
		return ReasonMissingProtocol, CheckProtocol
	case verify.ErrorCodeDuplicateTarget, verify.ErrorCodeSequenceInvalid:
		return ReasonSequenceInvalid, CheckProtocol
	case verify.ErrorCodeUnsupportedAlgorithm, verify.ErrorCodeUnsupportedTarget, verify.ErrorCodeDisabledAlgorithm:
		return ReasonUnsupportedAlgorithm, CheckProtocol
	case verify.ErrorCodeHashMismatch:
		return ReasonHashMismatch, CheckBodyHash
	case verify.ErrorCodeSignatureMismatch:
		return ReasonSignatureMismatch, CheckSignature
	case verify.ErrorCodeTimestampInvalid:
		return ReasonTimestampInvalid, CheckTimestamp
	case verify.ErrorCodeEnvelopeMismatch:
		return ReasonEnvelopeMismatch, CheckEnvelope
	case verify.ErrorCodeCustodyMismatch:
		return ReasonCustodyMismatch, CheckProtocol
	case verify.ErrorCodeDomainAlignmentMismatch:
		return ReasonDomainAlignmentMismatch, CheckDomainAlignment
	case verify.ErrorCodeNextDomainMismatch, verify.ErrorCodeMissingNextSignature:
		return ReasonNextDomainMismatch, CheckNextDomain
	case verify.ErrorCodeOutOfBandRequired:
		return ReasonOutOfBandRequired, CheckNextDomain
	case verify.ErrorCodeMissingKey:
		return ReasonMissingKey, CheckKey
	case verify.ErrorCodeAmbiguousKey:
		return ReasonAmbiguousKey, CheckKey
	case verify.ErrorCodeInvalidKey, verify.ErrorCodeWrongKeyType, verify.ErrorCodeKeyPolicyRejected:
		return ReasonInvalidKey, CheckKey
	case verify.ErrorCodeRevokedKey:
		return ReasonRevokedKey, CheckKey
	case verify.ErrorCodeUnsupportedKeyType:
		return ReasonUnsupportedKeyType, CheckKey
	case verify.ErrorCodeKeyAlgorithmMismatch:
		return ReasonKeyAlgorithmMismatch, CheckKey
	case verify.ErrorCodeProviderError:
		return ReasonProviderContract, CheckProvider
	case verify.ErrorCodeMalformedState:
		return ReasonMalformedProtocol, CheckProtocol
	default:
		return ReasonInternalContract, CheckInternalContract
	}
}
