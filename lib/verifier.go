package dkim2

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/service"
)

const verifierRedactedText = "dkim2.Verifier{redacted}"

// NewVerifier constructs a fully initialized current-verification facade.
func NewVerifier(provider PublicKeyProvider, options ...VerifierOption) (*Verifier, error) {
	if nilPublicKeyProvider(provider) {
		return nil, newAPIError(APIErrorCodeInvalidProvider)
	}
	config, err := applyVerifierOptions(options...)
	if err != nil {
		return nil, newAPIError(APIErrorCodeInvalidOption)
	}
	limits := config.limits
	serviceConfig := service.DefaultConfig()
	if config.clock != nil {
		serviceConfig.Clock = config.clock.now
	}
	serviceConfig.Limits = service.Limits{
		MaxRawMessageBytes: limits.MaxRawMessageBytes(), MaxRecipients: limits.MaxRecipients(),
		MaxInstanceHashSets: limits.MaxInstanceHashSets(), MaxSignatureSets: limits.MaxSignatureSets(),
		MaxCheckFacts: limits.MaxCheckFacts(), MaxSignatureFacts: limits.MaxSignatureFacts(),
	}
	coordinator, err := service.NewVerifier(
		publicKeyBridge{provider: provider, sink: config.sink},
		serviceConfig,
	)
	if err != nil {
		return nil, newAPIError(APIErrorCodeInvalidOption)
	}
	return &Verifier{state: &verifierState{
		service: coordinator, limits: limits, sink: config.sink, initialized: true,
	}}, nil
}

// Verify delegates current-only verification and preserves the disjoint result/error contract.
func (v *Verifier) Verify(ctx context.Context, request VerifyRequest) (output VerifyResult, resultErr error) {
	if v == nil || v.state == nil || !v.state.initialized {
		return VerifyResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	if ctx == nil {
		return VerifyResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return VerifyResult{}, err
	}
	rawMessage, reversePath, forwardPaths := request.values()
	started := time.Now()
	defer func() {
		observeVerification(
			ctx, v.state.sink, output, resultErr, time.Since(started),
			len(rawMessage), len(forwardPaths),
		)
	}()
	if len(rawMessage) > v.state.limits.MaxRawMessageBytes() || len(forwardPaths) > v.state.limits.MaxRecipients() {
		return publicPreflightLimitResult(), nil
	}
	serviceResult, err := v.state.service.Verify(ctx, service.NewRequest(rawMessage, reversePath, forwardPaths))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifyResult{}, ctxErr
		}
		return VerifyResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	return adaptServiceResult(serviceResult), nil
}

// observeVerification emits one closed current-verification event.
func observeVerification(
	ctx context.Context,
	sink ObservationSink,
	result VerifyResult,
	err error,
	duration time.Duration,
	messageBytes int,
	recipients int,
) {
	resultClass, reason, errorClass := verificationEventOutcome(ctx, result, err)
	event, ok := NewObservationEvent(
		ObservationVerifyCompleted,
		ObservationOperationVerify,
		resultClass,
		reason,
		errorClass,
		ObservationAlgorithmNone,
		ObservationCacheNotUsed,
		observationDurationBucket(duration),
		observationCountBucket(messageBytes, 1<<10, 1<<20, 10<<20),
		observationCountBucket(recipients, 1, 10, 100),
		ObservationBucketNone,
		ObservationBucketNone,
	)
	if ok {
		Observe(ctx, sink, event)
	}
}

// verificationEventOutcome maps the disjoint public result into telemetry classes.
func verificationEventOutcome(
	ctx context.Context,
	result VerifyResult,
	err error,
) (ObservationResult, ObservationReason, ObservationErrorClass) {
	if err != nil {
		switch {
		case ctx != nil && ctx.Err() == context.Canceled:
			return ObservationResultTemporary, ObservationReasonUnavailable, ObservationErrorCanceled
		case ctx != nil && ctx.Err() == context.DeadlineExceeded:
			return ObservationResultTemporary, ObservationReasonUnavailable, ObservationErrorDeadline
		default:
			return ObservationResultInternal, ObservationReasonUnavailable, ObservationErrorInternal
		}
	}
	switch result.State() {
	case ResultStatePASS:
		return ObservationResultSuccess, ObservationReasonNone, ObservationErrorNone
	case ResultStateTEMPERROR:
		return ObservationResultTemporary, ObservationReasonUnavailable, ObservationErrorTemporary
	case ResultStateFAIL, ResultStatePERMERROR:
		return ObservationResultFailure, ObservationReasonProtocol, ObservationErrorNone
	default:
		return ObservationResultInternal, ObservationReasonUnavailable, ObservationErrorInternal
	}
}

// observationDurationBucket maps elapsed time into a fixed coarse class.
func observationDurationBucket(duration time.Duration) ObservationBucket {
	switch {
	case duration < 10*time.Millisecond:
		return ObservationBucketSmall
	case duration < time.Second:
		return ObservationBucketMedium
	case duration < 10*time.Second:
		return ObservationBucketLarge
	default:
		return ObservationBucketOverflow
	}
}

// observationCountBucket maps a nonnegative quantity into fixed coarse bounds.
func observationCountBucket(value, small, medium, large int) ObservationBucket {
	switch {
	case value <= 0:
		return ObservationBucketNone
	case value <= small:
		return ObservationBucketSmall
	case value <= medium:
		return ObservationBucketMedium
	case value <= large:
		return ObservationBucketLarge
	default:
		return ObservationBucketOverflow
	}
}

// String returns a constant representation without injected provider state.
func (Verifier) String() string { return verifierRedactedText }

// GoString returns a constant representation without injected provider state.
func (Verifier) GoString() string { return verifierRedactedText }

// Format prevents formatting from traversing injected provider state.
func (Verifier) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, verifierRedactedText)
}

// MarshalJSON rejects serialization of retained verifier dependencies.
func (Verifier) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of retained verifier dependencies.
func (Verifier) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// publicPreflightLimitResult returns bounded current-scope failure before parsing or provider work.
func publicPreflightLimitResult() VerifyResult {
	projection, _ := policy.NewUnavailableProjection(policy.PreTargetLimitExceeded)
	return newVerifyResult(verifyResultData{
		state: ResultStatePERMERROR, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: CustodyStructureNotEvaluated, primaryReason: ReasonLimitExceeded,
		checks:           []CheckFact{newCheckFact(CheckClassMessage, ReasonLimitExceeded)},
		policyProjection: projection,
	})
}

// nilPublicKeyProvider reports nil and typed-nil interface dependencies.
func nilPublicKeyProvider(provider PublicKeyProvider) bool {
	return niliface.IsNil(provider)
}
