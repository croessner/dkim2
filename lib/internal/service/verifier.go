package service

import (
	"context"

	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

// Verifier owns validated current-verification coordination dependencies.
type Verifier struct {
	core        verify.Verifier
	limits      Limits
	initialized bool
}

// NewVerifier constructs a service coordinator with immutable validated policy.
func NewVerifier(provider verify.KeyProvider, config Config) (Verifier, error) {
	if nilKeyProvider(provider) || config.Limits.Validate() != nil || config.Clock == nil {
		return Verifier{}, newError(ErrorInvalidConfig)
	}
	core, err := verify.NewVerifier(provider,
		verify.WithAlgorithmPolicy(config.AlgorithmPolicy),
		verify.WithTimestampPolicy(config.TimestampPolicy),
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

// nilKeyProvider reports nil and typed-nil injected interface dependencies.
func nilKeyProvider(provider verify.KeyProvider) bool {
	return niliface.IsNil(provider)
}

// Verify parses raw input, delegates protocol verification, and returns one disjoint outcome.
func (v Verifier) Verify(ctx context.Context, request Request) (Result, error) {
	if !v.initialized || v.limits.Validate() != nil {
		return Result{}, newError(ErrorInvalidConfig)
	}
	if ctx == nil {
		return Result{}, newError(ErrorInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	raw := request.RawMessage()
	forward := request.ForwardPaths()
	if len(raw) > v.limits.MaxRawMessageBytes || len(forward) > v.limits.MaxRecipients {
		return preExtractionResult(ReasonLimitExceeded), nil
	}

	options := rawmsg.DefaultParserOptions()
	options.MaxMessageBytes = v.limits.MaxRawMessageBytes
	message, err := rawmsg.ParseWithOptions(raw, options)
	if err != nil {
		reason := ReasonMalformedMessage
		if rawmsg.IsParserErrorCode(err, rawmsg.ErrorCodeLimitExceeded) {
			reason = ReasonLimitExceeded
		}
		return preExtractionResult(reason), nil
	}

	coreResult, err := v.core.Verify(ctx, verify.Request{
		Message: message, Envelope: verify.NewEnvelope(request.ReversePath(), forward), RequireEnvelope: true,
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, ctxErr
	}
	if err != nil {
		return mapVerificationError(err), nil
	}
	return mapVerificationResult(coreResult, v.limits), nil
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

// verificationErrorHasUnavailableTarget identifies failures before authoritative selection.
func verificationErrorHasUnavailableTarget(code verify.ErrorCode, diagnosticTarget Target) bool {
	if diagnosticTarget.Sequence == 0 || diagnosticTarget.Instance == 0 {
		return true
	}
	switch code {
	case verify.ErrorCodeLimitExceeded, verify.ErrorCodeMissingTarget, verify.ErrorCodeDuplicateTarget,
		verify.ErrorCodeSequenceInvalid:
		return true
	default:
		return false
	}
}

// unavailableVerificationFailure normalizes pre-target errors to one sealable policy taxonomy.
func unavailableVerificationFailure(code verify.ErrorCode, reason Reason, class CheckClass, state State) (Reason, CheckClass, State) {
	switch code {
	case verify.ErrorCodeCustodyMismatch, verify.ErrorCodeNextDomainMismatch, verify.ErrorCodeMissingNextSignature:
		return ReasonMalformedProtocol, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeLimitExceeded, verify.ErrorCodeMissingTarget, verify.ErrorCodeDuplicateTarget,
		verify.ErrorCodeSequenceInvalid, verify.ErrorCodeMalformedState:
		return reason, class, state
	default:
		return ReasonInternalContract, CheckInternalContract, StatePERMERROR
	}
}

// mapVerificationErrorCode exhaustively maps bounded verification error codes.
func mapVerificationErrorCode(code verify.ErrorCode) (Reason, CheckClass, State) {
	switch code {
	case verify.ErrorCodeLimitExceeded:
		return ReasonLimitExceeded, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeMissingTarget:
		return ReasonMissingProtocol, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeDuplicateTarget, verify.ErrorCodeSequenceInvalid:
		return ReasonSequenceInvalid, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeUnsupportedAlgorithm, verify.ErrorCodeUnsupportedTarget, verify.ErrorCodeDisabledAlgorithm:
		return ReasonUnsupportedAlgorithm, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeHashMismatch:
		return ReasonHashMismatch, CheckBodyHash, StateFAIL
	case verify.ErrorCodeSignatureMismatch:
		return ReasonSignatureMismatch, CheckSignature, StateFAIL
	case verify.ErrorCodeTimestampInvalid:
		return ReasonTimestampInvalid, CheckTimestamp, StatePERMERROR
	case verify.ErrorCodeEnvelopeMismatch:
		return ReasonEnvelopeMismatch, CheckEnvelope, StatePERMERROR
	case verify.ErrorCodeCustodyMismatch:
		return ReasonMalformedProtocol, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeDomainAlignmentMismatch:
		return ReasonDomainAlignmentMismatch, CheckDomainAlignment, StatePERMERROR
	case verify.ErrorCodeNextDomainMismatch, verify.ErrorCodeMissingNextSignature:
		return ReasonNextDomainMismatch, CheckNextDomain, StatePERMERROR
	case verify.ErrorCodeOutOfBandRequired:
		return ReasonOutOfBandRequired, CheckNextDomain, StatePERMERROR
	case verify.ErrorCodeMissingKey:
		return ReasonMissingKey, CheckKey, StatePERMERROR
	case verify.ErrorCodeAmbiguousKey:
		return ReasonAmbiguousKey, CheckKey, StatePERMERROR
	case verify.ErrorCodeInvalidKey, verify.ErrorCodeWrongKeyType, verify.ErrorCodeKeyPolicyRejected:
		return ReasonInvalidKey, CheckKey, StatePERMERROR
	case verify.ErrorCodeRevokedKey:
		return ReasonRevokedKey, CheckKey, StatePERMERROR
	case verify.ErrorCodeUnsupportedKeyType:
		return ReasonUnsupportedKeyType, CheckKey, StatePERMERROR
	case verify.ErrorCodeKeyAlgorithmMismatch:
		return ReasonKeyAlgorithmMismatch, CheckKey, StatePERMERROR
	case verify.ErrorCodeProviderError:
		return ReasonProviderContract, CheckProvider, StatePERMERROR
	case verify.ErrorCodeMalformedState:
		return ReasonMalformedProtocol, CheckProtocol, StatePERMERROR
	case verify.ErrorCodeInvalidOptions, verify.ErrorCodeInvalidRequest, verify.ErrorCodeInternalMisuse, "":
		return ReasonInternalContract, CheckInternalContract, StatePERMERROR
	default:
		return ReasonInternalContract, CheckInternalContract, StatePERMERROR
	}
}
