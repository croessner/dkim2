package dkim2

import (
	"context"
	"fmt"
	"io"

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
	coordinator, err := service.NewVerifier(publicKeyBridge{provider: provider}, serviceConfig)
	if err != nil {
		return nil, newAPIError(APIErrorCodeInvalidOption)
	}
	return &Verifier{state: &verifierState{service: coordinator, limits: limits, initialized: true}}, nil
}

// Verify delegates current-only verification and preserves the disjoint result/error contract.
func (v *Verifier) Verify(ctx context.Context, request VerifyRequest) (VerifyResult, error) {
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
	if len(rawMessage) > v.state.limits.MaxRawMessageBytes() || len(forwardPaths) > v.state.limits.MaxRecipients() {
		return publicPreflightLimitResult(), nil
	}
	result, err := v.state.service.Verify(ctx, service.NewRequest(rawMessage, reversePath, forwardPaths))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifyResult{}, ctxErr
		}
		return VerifyResult{}, newAPIError(APIErrorCodeInvalidRequest)
	}
	return adaptServiceResult(result), nil
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
