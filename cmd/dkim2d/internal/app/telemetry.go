package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

const policyModeStrictClass = "strict"

const (
	telemetryResultFailure       = "failure"
	telemetryResultInternal      = "internal"
	telemetryResultSuccess       = "success"
	telemetryResultTemporary     = "temporary"
	telemetryReplayIndeterminate = "indeterminate"
	telemetryDispositionReject   = "reject"
	telemetryVerdictNeutral      = "neutral"
)

// startAppSpan starts one child span without changing application behavior.
func startAppSpan(
	ctx context.Context,
	runtime *observability.Runtime,
	name string,
) (context.Context, trace.Span) {
	if runtime == nil || runtime.Tracing() == nil {
		return ctx, trace.SpanFromContext(context.Background())
	}
	return runtime.Tracing().StartChild(ctx, name)
}

// verificationObservation maps protocol truth into the closed telemetry vocabulary.
func verificationObservation(result dkim2.VerifyResult, err error) (string, string) {
	if err != nil || !result.Valid() {
		return telemetryResultInternal, telemetryVerdictNeutral
	}
	switch result.State() {
	case dkim2.ResultStatePASS:
		return telemetryResultSuccess, "pass"
	case dkim2.ResultStateFAIL:
		return telemetryResultFailure, "fail"
	case dkim2.ResultStateTEMPERROR:
		return telemetryResultTemporary, "temperror"
	case dkim2.ResultStatePERMERROR:
		return telemetryResultFailure, "permerror"
	default:
		return telemetryResultInternal, telemetryVerdictNeutral
	}
}

// replayObservation maps one valid replay outcome into closed labels.
func replayObservation(result ReplayOutcome) (string, string) {
	state := telemetryReplayIndeterminate
	switch result.Class() {
	case ReplayResultNotChecked:
		state = "not_checked"
	case ReplayResultDisabled:
		state = "disabled"
	case ReplayResultFirstSeen:
		state = "first_seen"
	case ReplayResultReplayed:
		state = "replayed"
	case ReplayResultIndeterminate:
		state = telemetryReplayIndeterminate
	}
	disposition := "tempfail"
	switch result.Disposition() {
	case FinalDispositionAccept:
		disposition = "accept"
	case FinalDispositionReject:
		disposition = telemetryDispositionReject
	case FinalDispositionTempfail:
		disposition = "tempfail"
	case FinalDispositionContinue:
		disposition = "continue"
	}
	return state, disposition
}

// replayStoreRequired mirrors the coordinator's protocol-and-policy replay gate.
func replayStoreRequired(domain DomainResult) bool {
	verification, verificationErr := domain.Verification()
	policy, policyErr := domain.Policy()
	return verificationErr == nil && policyErr == nil &&
		verification.State() == dkim2.ResultStatePASS &&
		policy.Verdict() == dkim2.PolicyVerdictAccept
}

// observePolicy records one bounded local-policy outcome.
func observePolicy(
	runtime *observability.Runtime,
	decision dkim2.PolicyDecision,
	_ time.Duration,
) {
	if runtime == nil || !decision.Valid() {
		return
	}
	_, verdict := verificationObservationState(decision.VerificationState())
	reason := policyReasonClass(decision.VerificationState())
	mode := policyModeClass(decision.Mode())
	runtime.Metrics().PolicyCompleted(verdict, reason, mode)
	runtime.Logger().Info(
		"process.completed",
		slog.String("operation", "policy"),
		slog.String("result", telemetryResultSuccess),
		slog.String("verdict", verdict),
		slog.String("reason_class", reason),
		slog.String("policy_mode", mode),
	)
}

// verificationObservationState maps one closed result state without a full result.
func verificationObservationState(state dkim2.ResultState) (string, string) {
	switch state {
	case dkim2.ResultStatePASS:
		return telemetryResultSuccess, "pass"
	case dkim2.ResultStateFAIL:
		return telemetryResultFailure, "fail"
	case dkim2.ResultStateTEMPERROR:
		return telemetryResultTemporary, "temperror"
	case dkim2.ResultStatePERMERROR:
		return telemetryResultFailure, "permerror"
	default:
		return telemetryResultInternal, telemetryVerdictNeutral
	}
}

// policyReasonClass maps protocol outcomes into bounded nonnormative classes.
func policyReasonClass(state dkim2.ResultState) string {
	switch state {
	case dkim2.ResultStatePASS:
		return "none"
	case dkim2.ResultStateTEMPERROR:
		return "availability"
	case dkim2.ResultStateFAIL, dkim2.ResultStatePERMERROR:
		return "protocol"
	default:
		return "internal"
	}
}

// policyModeClass maps one public policy mode into the exact label grammar.
func policyModeClass(mode dkim2.PolicyMode) string {
	switch mode {
	case dkim2.PolicyModeStrict:
		return policyModeStrictClass
	case dkim2.PolicyModePermissive:
		return "permissive"
	case dkim2.PolicyModeTesting:
		return "testing"
	default:
		return policyModeStrictClass
	}
}
