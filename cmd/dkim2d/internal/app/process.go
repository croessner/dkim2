package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

const (
	inboundProcessorErrorText = "dkim2d inbound processing failure"
	inboundProcessorRedacted  = "dkim2d_inbound_processor"
	inboundResultRedacted     = "dkim2d_inbound_result"
)

// InboundProcessorError reports one content-free assembly or processing failure.
type InboundProcessorError struct{}

// Error returns a constant content-free processing diagnostic.
func (*InboundProcessorError) Error() string { return inboundProcessorErrorText }

// Is recognizes the bounded inbound processing error type.
func (*InboundProcessorError) Is(target error) bool {
	_, ok := target.(*InboundProcessorError)
	return ok
}

// ReplayService is the narrow provider-neutral replay use-case boundary.
type ReplayService interface {
	Coordinate(context.Context, DomainResult) (ReplayOutcome, error)
}

// InboundProcessor composes verification, policy, and replay without changing their owners.
type InboundProcessor struct {
	domain  *DomainProcessor
	replay  ReplayService
	runtime *observability.Runtime
}

// attachObservability binds the already acquired instance runtime before publication.
func (p *InboundProcessor) attachObservability(runtime *observability.Runtime) {
	if p == nil {
		return
	}
	p.runtime = runtime
	if p.domain != nil {
		p.domain.attachObservability(runtime)
	}
}

// InboundResult keeps domain and replay truth separate for transport mapping.
type InboundResult struct {
	domain DomainResult
	replay ReplayOutcome
}

// NewInboundProcessor constructs one immutable inbound use case.
func NewInboundProcessor(
	domain *DomainProcessor,
	replay ReplayService,
) (*InboundProcessor, error) {
	if domain == nil || domain.state == nil || nilInterface(replay) {
		return nil, &InboundProcessorError{}
	}
	return &InboundProcessor{domain: domain, replay: replay}, nil
}

// Process performs domain evaluation followed by the exact replay gate and batch.
func (p *InboundProcessor) Process(
	ctx context.Context,
	request dkim2.VerifyRequest,
) (InboundResult, error) {
	if p == nil || p.domain == nil || p.replay == nil {
		return InboundResult{}, &InboundProcessorError{}
	}
	started := time.Now()
	processContext, processSpan := startAppSpan(ctx, p.runtime, "dkim2d.process")
	outcome := observability.SpanInternalError
	var processFacts []observability.SpanFact
	defer func() {
		observability.EndSpanWithFacts(processSpan, outcome, processFacts...)
	}()
	domain, err := p.domain.Process(processContext, request)
	if err != nil {
		p.observeProcessFailure(started)
		return InboundResult{}, err
	}
	if !domain.Applicable() {
		result := InboundResult{
			domain: domain,
			replay: newReplayOutcome(
				ReplayResultNotChecked,
				FinalDispositionContinue,
				false,
			),
		}
		if !result.Valid() {
			p.observeProcessFailure(started)
			return InboundResult{}, &InboundProcessorError{}
		}
		outcome = observability.SpanCompleted
		processResultFact, _ := observability.TextSpanFact(
			"dkim2.result",
			telemetryResultSuccess,
		)
		processVerdictFact, _ := observability.TextSpanFact(
			"dkim2.verdict",
			telemetryVerdictNeutral,
		)
		processReplayFact, _ := observability.TextSpanFact(
			"dkim2.replay_state",
			"not_checked",
		)
		processFacts = []observability.SpanFact{
			processResultFact,
			processVerdictFact,
			processReplayFact,
		}
		p.observeProcessSuccess(result, started, time.Time{})
		return result, nil
	}
	replayContext, replaySpan := startAppSpan(processContext, p.runtime, "dkim2.replay.coordinate")
	replayStarted := time.Now()
	storeContext := replayContext
	var storeSpan trace.Span
	if replayStoreRequired(domain) {
		storeContext, storeSpan = startAppSpan(replayContext, p.runtime, "dkim2.replay.store")
	}
	var replay ReplayOutcome
	if authentication, ok := domain.Authentication(); ok {
		replay, err = replayOutcomeFromAuthentication(authentication, domain)
	} else {
		replay, err = p.replay.Coordinate(storeContext, domain)
	}
	if err != nil {
		internalResult, _ := observability.TextSpanFact(
			"dkim2.result",
			telemetryResultInternal,
		)
		observability.EndSpanWithFacts(
			storeSpan,
			observability.SpanInternalError,
			internalResult,
		)
		observability.EndSpanWithFacts(
			replaySpan,
			observability.SpanInternalError,
			internalResult,
		)
		p.observeProcessFailure(started)
		return InboundResult{}, err
	}
	result := InboundResult{domain: domain, replay: replay}
	if !result.Valid() {
		observability.EndSpan(storeSpan, observability.SpanInternalError)
		observability.EndSpan(replaySpan, observability.SpanInternalError)
		p.observeProcessFailure(started)
		return InboundResult{}, &InboundProcessorError{}
	}
	replayState, _ := replayObservation(replay)
	replayResult := telemetryResultSuccess
	if replayState == telemetryReplayIndeterminate {
		replayResult = telemetryResultTemporary
	}
	replayResultFact, _ := observability.TextSpanFact("dkim2.result", replayResult)
	replayStateFact, _ := observability.TextSpanFact("dkim2.replay_state", replayState)
	observability.EndSpanWithFacts(
		storeSpan,
		observability.SpanCompleted,
		replayResultFact,
	)
	observability.EndSpanWithFacts(
		replaySpan,
		observability.SpanCompleted,
		replayResultFact,
		replayStateFact,
	)
	outcome = observability.SpanCompleted
	resultClass, verdict := telemetryResultSuccess, telemetryVerdictNeutral
	if result.domain.Applicable() {
		verification, verificationErr := result.domain.Verification()
		resultClass, verdict = verificationObservation(verification, verificationErr)
	}
	processResultFact, _ := observability.TextSpanFact("dkim2.result", resultClass)
	processVerdictFact, _ := observability.TextSpanFact("dkim2.verdict", verdict)
	processReplayFact, _ := observability.TextSpanFact("dkim2.replay_state", replayState)
	processFacts = []observability.SpanFact{
		processResultFact,
		processVerdictFact,
		processReplayFact,
	}
	p.observeProcessSuccess(result, started, replayStarted)
	return result, nil
}

// replayOutcomeFromAuthentication projects the library-owned final result without a second store operation.
func replayOutcomeFromAuthentication(authentication dkim2.AuthenticationResult, domain DomainResult) (ReplayOutcome, error) {
	policy, err := domain.Policy()
	if err != nil || !authentication.Valid() || policy.VerificationState() != authentication.State() {
		return ReplayOutcome{}, &InboundProcessorError{}
	}
	disposition, ok := dispositionForPolicy(policy.Verdict())
	if !ok {
		return ReplayOutcome{}, &InboundProcessorError{}
	}
	var class ReplayResultClass
	possibleMutation := false
	switch authentication.ReplayClass() {
	case dkim2.AuthenticationReplayNotChecked:
		class = ReplayResultNotChecked
	case dkim2.AuthenticationReplayDisabled:
		class = ReplayResultDisabled
	case dkim2.AuthenticationReplayFirstSeen:
		class, possibleMutation = ReplayResultFirstSeen, true
	case dkim2.AuthenticationReplayExploded:
		class, possibleMutation = ReplayResultExploded, true
	case dkim2.AuthenticationReplayReplayed:
		class = ReplayResultReplayed
	case dkim2.AuthenticationReplayIndeterminate:
		class = ReplayResultIndeterminate
	default:
		return ReplayOutcome{}, &InboundProcessorError{}
	}
	result := newReplayOutcome(class, disposition, possibleMutation)
	if !result.Valid() {
		return ReplayOutcome{}, &InboundProcessorError{}
	}
	return result, nil
}

// observeProcessFailure records one bounded internal processing outcome.
func (p *InboundProcessor) observeProcessFailure(started time.Time) {
	if p == nil || p.runtime == nil {
		return
	}
	p.runtime.Metrics().ProcessCompleted(
		"internal", "neutral", "not_checked", "tempfail", time.Since(started),
	)
	p.runtime.Logger().Error(
		"process.completed",
		slog.String("operation", "process"),
		slog.String("result", "internal"),
		slog.String("verdict", "neutral"),
		slog.String("replay_state", "not_checked"),
		slog.String("disposition", "tempfail"),
	)
}

// observeProcessSuccess records only closed result, replay, and disposition classes.
func (p *InboundProcessor) observeProcessSuccess(
	result InboundResult,
	started time.Time,
	replayStarted time.Time,
) {
	if p == nil || p.runtime == nil {
		return
	}
	resultClass, verdict := telemetryResultSuccess, telemetryVerdictNeutral
	if result.domain.Applicable() {
		verification, verificationErr := result.domain.Verification()
		resultClass, verdict = verificationObservation(verification, verificationErr)
	}
	replayState, disposition := replayObservation(result.replay)
	p.runtime.Metrics().ProcessCompleted(
		resultClass, verdict, replayState, disposition, time.Since(started),
	)
	p.runtime.Logger().Info(
		"process.completed",
		slog.String("operation", "process"),
		slog.String("result", resultClass),
		slog.String("verdict", verdict),
		slog.String("replay_state", replayState),
		slog.String("disposition", disposition),
	)
	if !result.domain.Applicable() {
		return
	}
	replayResult := telemetryResultSuccess
	if replayState == telemetryReplayIndeterminate {
		replayResult = telemetryResultTemporary
	}
	p.runtime.Metrics().ReplayCompleted(replayState, replayResult, time.Since(replayStarted))
	if p.runtime.DebugEnabled("replay") {
		p.runtime.Logger().Debug(
			"replay.coordinate.completed",
			slog.String("operation", "replay_coordinate"),
			slog.String("result", replayResult),
			slog.String("replay_state", replayState),
			slog.String("disposition", disposition),
		)
	}
}

// Valid reports whether both retained result owners are coherent.
func (r InboundResult) Valid() bool {
	return r.domain.valid() && r.replay.Valid()
}

// Applicable reports whether this inbound result contains an actual DKIM2 verification.
func (r InboundResult) Applicable() bool { return r.Valid() && r.domain.Applicable() }

// Domain returns the immutable verification and policy result.
func (r InboundResult) Domain() (DomainResult, error) {
	if !r.Valid() {
		return DomainResult{}, &InboundProcessorError{}
	}
	return r.domain, nil
}

// Replay returns the immutable replay aggregate and final disposition.
func (r InboundResult) Replay() (ReplayOutcome, error) {
	if !r.Valid() {
		return ReplayOutcome{}, &InboundProcessorError{}
	}
	return r.replay, nil
}

// String returns a content-free inbound-processor representation.
func (InboundProcessor) String() string { return inboundProcessorRedacted }

// GoString returns a content-free inbound-processor representation.
func (InboundProcessor) GoString() string { return inboundProcessorRedacted }

// Format prevents formatting from traversing processing dependencies.
func (InboundProcessor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, inboundProcessorRedacted)
}

// MarshalJSON rejects serialization of processing dependencies.
func (InboundProcessor) MarshalJSON() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// MarshalText rejects diagnostic serialization of processing dependencies.
func (InboundProcessor) MarshalText() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// String returns a content-free inbound-result representation.
func (InboundResult) String() string { return inboundResultRedacted }

// GoString returns a content-free inbound-result representation.
func (InboundResult) GoString() string { return inboundResultRedacted }

// Format prevents formatting from traversing protocol results.
func (InboundResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, inboundResultRedacted)
}

// MarshalJSON rejects serialization outside the HTTP mapper.
func (InboundResult) MarshalJSON() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// MarshalText rejects diagnostic serialization of protocol results.
func (InboundResult) MarshalText() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// IsInboundProcessorError reports whether err is a bounded use-case failure.
func IsInboundProcessorError(err error) bool {
	return errors.Is(err, &InboundProcessorError{})
}
