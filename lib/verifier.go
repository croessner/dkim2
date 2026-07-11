package dkim2

import (
	"context"
	"reflect"

	"github.com/croessner/dkim2/internal/service"
)

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
	coordinator, err := service.NewVerifier(publicKeyBridge{provider: provider}, serviceConfig)
	if err != nil {
		return nil, newAPIError(APIErrorCodeInvalidOption)
	}
	return &Verifier{service: coordinator, limits: limits, initialized: true}, nil
}

// Verify delegates current-only verification and preserves the disjoint result/error contract.
func (v *Verifier) Verify(ctx context.Context, request VerifyRequest) (VerifyResult, error) {
	if v == nil || !v.initialized {
		return VerifyResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	if ctx == nil {
		return VerifyResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return VerifyResult{}, err
	}
	if len(request.rawMessage) > v.limits.MaxRawMessageBytes() || len(request.forwardPaths) > v.limits.MaxRecipients() {
		return publicPreflightLimitResult(), nil
	}
	result, err := v.service.Verify(ctx, service.NewRequest(request.rawMessage, request.reversePath, request.forwardPaths))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifyResult{}, ctxErr
		}
		return VerifyResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	return adaptServiceResult(result), nil
}

// publicPreflightLimitResult returns bounded current-scope failure before parsing or provider work.
func publicPreflightLimitResult() VerifyResult {
	return newVerifyResult(verifyResultData{
		state: ResultStatePERMERROR, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: CustodyStructureNotEvaluated, primaryReason: ReasonLimitExceeded,
		checks: []CheckFact{newCheckFact(CheckClassMessage, ReasonLimitExceeded)},
	})
}

// nilPublicKeyProvider reports nil and typed-nil interface dependencies.
func nilPublicKeyProvider(provider PublicKeyProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
