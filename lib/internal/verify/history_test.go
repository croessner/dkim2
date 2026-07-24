package verify

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
)

const testHistorySHA256 = "sha256"
const testHistoryBodyEmpty = `{"b":[]}`

// TestHistoryWalkCompletesAuthenticatedDescent verifies m=N recipe ownership and per-hop hashes.
func TestHistoryWalkCompletesAuthenticatedDescent(t *testing.T) {
	coordinator := mustHistoryCoordinator(t, HistoryLimits{})
	state, collection := historyFixture(t, `{"h":{"Subject":[{"d":["previous"]}]},"b":[{"d":["old"]}]}`, []byte("Subject:previous\r\n\r\nold\r\n"), testHistorySHA256)
	walk, err := coordinator.Walk(context.Background(), historyPassResult(2), collection, state)
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoverageComplete || walk.StopReason() != HistoryStopOriginReached || walk.TargetInstance() != 2 || walk.ReachedInstance() != 1 {
		t.Fatalf("complete walk mismatch: valid=%t coverage=%s stop=%s err=%v", walk.Valid(), walk.Coverage(), walk.StopReason(), err)
	}
	transitions := walk.Transitions()
	if len(transitions) != 1 || transitions[0].FromInstance() != 2 || transitions[0].ToInstance() != 1 || transitions[0].HeaderState() != HistoryDimensionMatched || transitions[0].BodyState() != HistoryDimensionMatched {
		t.Fatalf("transition mismatch: count=%d", len(transitions))
	}
	if !walk.Usage().Valid() || walk.Usage().DecodedBytes() == 0 || walk.Usage().EmittedBytes() == 0 {
		t.Fatal("walk usage missing")
	}
}

// TestHistoryWalkSealsAuthenticatedFailures verifies closed coverage and stop precedence.
func TestHistoryWalkSealsAuthenticatedFailures(t *testing.T) {
	tests := []struct {
		name, recipeJSON, algorithm string
		previous                    []byte
		coverage                    HistoryCoverage
		stop                        HistoryStopReason
	}{
		{"missing recipe", "", testHistorySHA256, []byte("Subject:previous\r\n\r\nold\r\n"), HistoryCoverageUnreconstructable, HistoryStopRecipeMissing},
		{"malformed recipe", `{`, testHistorySHA256, []byte("Subject:previous\r\n\r\nold\r\n"), HistoryCoverageUnreconstructable, HistoryStopRecipeInvalid},
		{"hash mismatch", testHistoryBodyEmpty, testHistorySHA256, []byte("Subject:different\r\n\r\n"), HistoryCoverageFailed, HistoryStopHashMismatch},
		{"unsupported", testHistoryBodyEmpty, "future", []byte("Subject:current\r\n\r\n"), HistoryCoverageUnsupported, HistoryStopHashUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, collection := historyFixture(t, test.recipeJSON, test.previous, test.algorithm)
			walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(2), collection, state)
			if err != nil || !walk.Valid() || walk.Coverage() != test.coverage || walk.StopReason() != test.stop {
				t.Fatalf("sealed mismatch: coverage=%s stop=%s err=%v", walk.Coverage(), walk.StopReason(), err)
			}
		})
	}
}

// TestHistoryWalkRecordsUnavailableBodyAsPartial verifies independent dimension coverage.
func TestHistoryWalkRecordsUnavailableBodyAsPartial(t *testing.T) {
	state, collection := historyFixture(t, `{"h":{"Subject":[{"d":["previous"]}]},"b":null}`, []byte("Subject:previous\r\n\r\n"), testHistorySHA256)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(2), collection, state)
	if err != nil || walk.Coverage() != HistoryCoveragePartial || walk.StopReason() != HistoryStopOriginReached || len(walk.Transitions()) != 1 || walk.Transitions()[0].BodyState() != HistoryDimensionUnavailable {
		t.Fatalf("partial walk mismatch: coverage=%s stop=%s err=%v", walk.Coverage(), walk.StopReason(), err)
	}
}

// TestHistoryWalkDirectContractsAndCancellation verifies zero-walk error lane and PASS gate.
func TestHistoryWalkDirectContractsAndCancellation(t *testing.T) {
	coordinator := mustHistoryCoordinator(t, HistoryLimits{})
	state, collection := historyFixture(t, testHistoryBodyEmpty, []byte("Subject:current\r\n\r\n"), testHistorySHA256)
	for _, result := range []Result{{}, NewResult(Target{Sequence: 1, InstanceNumber: 2}, TargetStatusFail, nil, nil)} {
		walk, err := coordinator.Walk(context.Background(), result, collection, state)
		if walk.Valid() || !IsErrorCode(err, ErrorCodeHistoryInvalidState) {
			t.Fatalf("direct misuse mismatch: walk=%t err=%v", walk.Valid(), err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	walk, err := coordinator.Walk(ctx, historyPassResult(2), collection, state)
	if walk.Valid() || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation mismatch: walk=%t err=%v", walk.Valid(), err)
	}
}

// TestHistoryWalkRejectsUnboundInitialState verifies direct current-content binding.
func TestHistoryWalkRejectsUnboundInitialState(t *testing.T) {
	coordinator := mustHistoryCoordinator(t, HistoryLimits{})
	state, collection := historyFixture(t, testHistoryBodyEmpty, []byte("Subject:current\r\n\r\n"), testHistorySHA256)
	wrong := mustHistoryState(t, []byte("Subject:other\r\n\r\nbody\r\n"))
	if walk, err := coordinator.Walk(context.Background(), historyPassResult(2), collection, wrong); walk.Valid() || !IsErrorCode(err, ErrorCodeHistoryInvalidState) {
		t.Fatalf("unbound state accepted: walk=%t err=%v", walk.Valid(), err)
	}
	plan, _, _ := coordinator.parser.Parse([]byte(`{"b":null}`))
	unavailable, _, applyErr := coordinator.applier.Apply(state, plan)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	if walk, err := coordinator.Walk(context.Background(), historyPassResult(2), collection, unavailable); walk.Valid() || !IsErrorCode(err, ErrorCodeHistoryInvalidState) {
		t.Fatalf("unavailable current accepted: walk=%t err=%v", walk.Valid(), err)
	}
}

// TestHistoryWalkOriginAndCumulativeLimit verifies zero-hop origin and immediate limits.
func TestHistoryWalkOriginAndCumulativeLimit(t *testing.T) {
	state := mustHistoryState(t, []byte("Subject:origin\r\n\r\nbody\r\n"))
	origin := parseHistoryCollection(t, historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:origin\r\n\r\nbody\r\n")), `{`))
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(1), origin, state)
	if err != nil || walk.Coverage() != HistoryCoverageComplete || walk.StopReason() != HistoryStopOriginReached || len(walk.Transitions()) != 0 || walk.Usage().DecodedBytes() != 0 || walk.Usage().WorkUnits() != 0 {
		t.Fatalf("origin mismatch: err=%v", err)
	}
	state, collection := historyFixture(t, testHistoryBodyEmpty, []byte("Subject:current\r\n\r\n"), testHistorySHA256)
	limits := DefaultHistoryLimits()
	limits.MaxCumulativeDecodedBytes = 1
	walk, err = mustHistoryCoordinator(t, limits).Walk(context.Background(), historyPassResult(2), collection, state)
	if err != nil || walk.Coverage() != HistoryCoverageUnreconstructable || walk.StopReason() != HistoryStopLimitExceeded || walk.Usage().DecodedBytes() == 0 {
		t.Fatalf("limit mismatch: coverage=%s stop=%s err=%v", walk.Coverage(), walk.StopReason(), err)
	}
}

// TestHistoryWalkDescendsThreeToOrigin verifies current-instance recipe ownership at every hop.
func TestHistoryWalkDescendsThreeToOrigin(t *testing.T) {
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleBytes := []byte("Subject:middle\r\n\r\nmiddle\r\n")
	originBytes := []byte("Subject:origin\r\n\r\norigin\r\n")
	recipeThree := `{"h":{"Subject":[{"d":["middle"]}]},"b":[{"d":["middle"]}]}`
	recipeTwo := `{"h":{"Subject":[{"d":["origin"]}]},"b":[{"d":["origin"]}]}`
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, originBytes), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleBytes), recipeTwo),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), recipeThree),
	)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoverageComplete || walk.ReachedInstance() != 1 || len(walk.Transitions()) != 2 {
		t.Fatalf("three-hop mismatch: coverage=%s reached=%d transitions=%d err=%v", walk.Coverage(), walk.ReachedInstance(), len(walk.Transitions()), err)
	}
	limits := DefaultHistoryLimits()
	limits.MaxRetainedTransitions = 1
	narrow, err := mustHistoryCoordinator(t, limits).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if err != nil || !narrow.Valid() || narrow.Coverage() != HistoryCoverageComplete || narrow.ReachedInstance() != 1 || len(narrow.Transitions()) != 1 {
		t.Fatalf("retention changed fold: coverage=%s reached=%d retained=%d", narrow.Coverage(), narrow.ReachedInstance(), len(narrow.Transitions()))
	}
	exactTransitions := DefaultHistoryLimits()
	exactTransitions.MaxTransitions = 2
	exactTransitions.MaxRetainedTransitions = 2
	if exact, err := mustHistoryCoordinator(t, exactTransitions).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes)); err != nil || exact.Coverage() != HistoryCoverageComplete {
		t.Fatalf("exact transition limit rejected: coverage=%s err=%v", exact.Coverage(), err)
	}
	overTransitions := DefaultHistoryLimits()
	overTransitions.MaxTransitions = 1
	overTransitions.MaxRetainedTransitions = 1
	over, err := mustHistoryCoordinator(t, overTransitions).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if err != nil || !over.Valid() || over.Coverage() != HistoryCoveragePartial || over.StopReason() != HistoryStopLimitExceeded || over.ReachedInstance() != 2 {
		t.Fatalf("transition one-over mismatch: coverage=%s stop=%s reached=%d err=%v", over.Coverage(), over.StopReason(), over.ReachedInstance(), err)
	}
}

// TestHistoryWalkContinuesAfterNullWithDataRecovery verifies partial origin coverage.
func TestHistoryWalkContinuesAfterNullWithDataRecovery(t *testing.T) {
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleHeader := []byte("Subject:middle\r\n\r\nplaceholder\r\n")
	originBytes := []byte("Subject:origin\r\n\r\nrecovered\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, originBytes), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleHeader), `{"h":{"Subject":[{"d":["origin"]}]},"b":[{"d":["recovered"]}]}`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"Subject":[{"d":["middle"]}]},"b":null}`),
	)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoveragePartial || walk.StopReason() != HistoryStopOriginReached || walk.ReachedInstance() != 1 || len(walk.Transitions()) != 2 || walk.Transitions()[0].BodyState() != HistoryDimensionUnavailable || walk.Transitions()[1].BodyState() != HistoryDimensionMatched {
		t.Fatalf("null recovery mismatch: coverage=%s stop=%s err=%v", walk.Coverage(), walk.StopReason(), err)
	}
}

// TestHistoryWalkContinuesHeadersOnCopyAfterUnavailableBody verifies persistent body-gap semantics.
func TestHistoryWalkContinuesHeadersOnCopyAfterUnavailableBody(t *testing.T) {
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleBytes := []byte("Subject:middle\r\n\r\nplaceholder\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:origin\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleBytes), `{"h":{"Subject":[{"d":["origin"]}]},"b":[{"c":[1,1]}]}`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"Subject":[{"d":["middle"]}]},"b":null}`),
	)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoveragePartial || walk.StopReason() != HistoryStopOriginReached || walk.ReachedInstance() != 1 || len(walk.Transitions()) != 2 || !walk.hadUnavailable || walk.Usage().DecodedBytes() == 0 {
		t.Fatalf("later unavailable copy mismatch: coverage=%s stop=%s reached=%d err=%v", walk.Coverage(), walk.StopReason(), walk.ReachedInstance(), err)
	}
	for _, transition := range walk.Transitions() {
		if transition.HeaderState() != HistoryDimensionMatched || transition.BodyState() != HistoryDimensionUnavailable {
			t.Fatalf("transition %d->%d = %s/%s", transition.FromInstance(), transition.ToInstance(), transition.HeaderState(), transition.BodyState())
		}
	}
}

// TestHistoryWalkCancellationBetweenHopsDiscardsFacts verifies context precedence.
func TestHistoryWalkCancellationBetweenHopsDiscardsFacts(t *testing.T) {
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleBytes := []byte("Subject:middle\r\n\r\nmiddle\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:origin\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleBytes), `{"h":{"Subject":[{"d":["origin"]}]},"b":[{"d":["origin"]}]}`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"Subject":[{"d":["middle"]}]},"b":[{"d":["middle"]}]}`),
	)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(&cancelBetweenHopsContext{cancelAt: 3}, historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if walk.Valid() || !errors.Is(err, context.Canceled) {
		t.Fatalf("between-hop cancellation mismatch: walk=%t err=%v", walk.Valid(), err)
	}
}

type cancelBetweenHopsContext struct {
	calls    int
	cancelAt int
}

// Deadline reports no deadline for the deterministic cancellation context.
func (c *cancelBetweenHopsContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done returns nil because Walk consults Err at deterministic boundaries.
func (c *cancelBetweenHopsContext) Done() <-chan struct{} { return nil }

// Err flips to canceled at the configured boundary.
func (c *cancelBetweenHopsContext) Err() error {
	c.calls++
	if c.calls >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

// Value returns no context values.
func (c *cancelBetweenHopsContext) Value(any) any { return nil }

// TestHistoryWalkLaterFailureIsPartial verifies fold precedence after one matched hop.
func TestHistoryWalkLaterFailureIsPartial(t *testing.T) {
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleBytes := []byte("Subject:middle\r\n\r\nmiddle\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:origin\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleBytes), ""),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"Subject":[{"d":["middle"]}]},"b":[{"d":["middle"]}]}`),
	)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoveragePartial || walk.StopReason() != HistoryStopRecipeMissing || walk.ReachedInstance() != 2 || len(walk.Transitions()) != 1 {
		t.Fatalf("later failure mismatch: coverage=%s stop=%s reached=%d err=%v", walk.Coverage(), walk.StopReason(), walk.ReachedInstance(), err)
	}
}

// TestHistoryWalkLaterFailureMatrix verifies sealed partial precedence after one match.
func TestHistoryWalkLaterFailureMatrix(t *testing.T) {
	for _, test := range []struct {
		name, recipe string
		stop         HistoryStopReason
	}{
		{"malformed", `{`, HistoryStopRecipeInvalid},
		{"application", `{"b":[{"c":[9,9]}]}`, HistoryStopApplicationInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, collection := laterHistoryFailureFixture(t, test.recipe)
			walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), collection, state)
			if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoveragePartial || walk.StopReason() != test.stop || walk.ReachedInstance() != 2 || len(walk.Transitions()) != 1 {
				t.Fatalf("later failure mismatch: coverage=%s stop=%s err=%v", walk.Coverage(), walk.StopReason(), err)
			}
		})
	}
}

// TestHistoryFailedAttemptUsageIsAddedExactlyOnce verifies parser and applier accounting ownership.
func TestHistoryFailedAttemptUsageIsAddedExactlyOnce(t *testing.T) {
	malformedState, malformedCollection := historyFixture(t, `{`, []byte("Subject:previous\r\n\r\n"), testHistorySHA256)
	coordinator := mustHistoryCoordinator(t, HistoryLimits{})
	currentInstance, _ := malformedCollection.ByNumber(2)
	encoded, _ := currentInstance.Recipe()
	_, parseUsage, _ := coordinator.parser.Parse(encoded.Decoded())
	walk, err := coordinator.Walk(context.Background(), historyPassResult(2), malformedCollection, malformedState)
	if err != nil || walk.Usage().DecodedBytes() != parseUsage.DecodedBytes() || walk.Usage().Items() != parseUsage.Items() || walk.Usage().WorkUnits() != parseUsage.WorkUnits() {
		t.Fatalf("failed parse usage double-counted: walk=%#v parse=%#v", walk.Usage(), parseUsage)
	}
	applyState, applyCollection := historyFixture(t, `{"b":[{"c":[9,9]}]}`, []byte("Subject:previous\r\n\r\n"), testHistorySHA256)
	applyCurrent, _ := applyCollection.ByNumber(2)
	applyEncoded, _ := applyCurrent.Recipe()
	plan, parserUsage, _ := coordinator.parser.Parse(applyEncoded.Decoded())
	_, applierUsage, _ := coordinator.applier.Apply(applyState, plan)
	walk, err = coordinator.Walk(context.Background(), historyPassResult(2), applyCollection, applyState)
	if err != nil || walk.Usage().DecodedBytes() != parserUsage.DecodedBytes()+applierUsage.DecodedBytes() || walk.Usage().EmittedBytes() != parserUsage.EmittedBytes()+applierUsage.EmittedBytes() || walk.Usage().Items() != parserUsage.Items()+applierUsage.Items() || walk.Usage().WorkUnits() != parserUsage.WorkUnits()+applierUsage.WorkUnits() {
		t.Fatalf("failed apply usage double-counted: walk=%#v parse=%#v apply=%#v", walk.Usage(), parserUsage, applierUsage)
	}
}

// TestValidatePreviousSeparatesDimensions verifies usage-free direct comparison semantics.
func TestValidatePreviousSeparatesDimensions(t *testing.T) {
	state, collection := historyFixture(t, testHistoryBodyEmpty, []byte("Subject:current\r\n\r\n"), testHistorySHA256)
	current, _ := collection.ByNumber(2)
	previous, _ := collection.ByNumber(1)
	transition, err := mustHistoryCoordinator(t, HistoryLimits{}).ValidatePrevious(mustHistoryState(t, []byte("Subject:current\r\n\r\n")), current, previous)
	if err != nil || !transition.Valid() || transition.RecipeMode() != HistoryRecipeModeApplied || transition.HeaderState() != HistoryDimensionMatched || transition.BodyState() != HistoryDimensionMatched {
		t.Fatalf("direct match mismatch: transition=%t err=%v", transition.Valid(), err)
	}
	mismatch, err := mustHistoryCoordinator(t, HistoryLimits{}).ValidatePrevious(state, current, previous)
	if err != nil || !mismatch.Valid() || mismatch.BodyState() != HistoryDimensionMismatch {
		t.Fatalf("direct mismatch lane failed: body=%s err=%v", mismatch.BodyState(), err)
	}
	unsupportedState, unsupportedCollection := historyFixture(t, testHistoryBodyEmpty, []byte("Subject:current\r\n\r\n"), "future")
	unsupportedCurrent, _ := unsupportedCollection.ByNumber(2)
	unsupportedPrevious, _ := unsupportedCollection.ByNumber(1)
	unsupported, err := mustHistoryCoordinator(t, HistoryLimits{}).ValidatePrevious(unsupportedState, unsupportedCurrent, unsupportedPrevious)
	if err != nil || unsupported.HeaderState() != HistoryDimensionUnsupported || unsupported.BodyState() != HistoryDimensionUnsupported {
		t.Fatalf("direct unsupported mismatch: header=%s body=%s err=%v", unsupported.HeaderState(), unsupported.BodyState(), err)
	}
	if transition, err = mustHistoryCoordinator(t, HistoryLimits{}).ValidatePrevious(state, previous, current); transition.Valid() || !IsErrorCode(err, ErrorCodeHistoryInstanceNotAdjacent) {
		t.Fatalf("adjacency mismatch: transition=%t err=%v", transition.Valid(), err)
	}
	missing, err := mustHistoryCoordinator(t, HistoryLimits{}).validatePreviousSelection(state, current, previous, instance.HashSet{}, instance.HashSelectionStatusMissing)
	if missing.Valid() || !IsErrorCode(err, ErrorCodeHistoryMissingSHA256) || historyTransitionStop(err) != HistoryStopHashMissing {
		t.Fatalf("missing selection mismatch: transition=%t err=%v", missing.Valid(), err)
	}
}

// TestHistoryMissingSelectionFoldIsFirstHopSensitive verifies future-compatible coverage mapping.
func TestHistoryMissingSelectionFoldIsFirstHopSensitive(t *testing.T) {
	usage := HistoryUsage{initialized: true}
	first := sealedHistory(2, 2, nil, usage, HistoryStopHashMissing, false)
	if !first.Valid() || first.Coverage() != HistoryCoverageUnreconstructable {
		t.Fatal("first-hop missing hash fold mismatch")
	}
	state := mustHistoryState(t, []byte("Subject:x\r\n\r\nbody\r\n"))
	matched := HistoryTransition{from: 3, to: 2, mode: HistoryRecipeModeApplied, header: HistoryDimensionMatched, body: HistoryDimensionMatched, state: state, initialized: true}
	later := sealedHistory(3, 2, []HistoryTransition{matched}, usage, HistoryStopHashMissing, false)
	if !later.Valid() || later.Coverage() != HistoryCoveragePartial {
		t.Fatal("later missing hash fold mismatch")
	}
}

// TestHistoryMismatchPrecedesUnavailableCoverage verifies failed precedence over partial.
func TestHistoryMismatchPrecedesUnavailableCoverage(t *testing.T) {
	state, collection := historyFixture(t, `{"h":{"Subject":[{"d":["wrong"]}]},"b":null}`, []byte("Subject:expected\r\n\r\n"), testHistorySHA256)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(2), collection, state)
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoverageFailed || walk.StopReason() != HistoryStopHashMismatch || walk.Transitions()[0].BodyState() != HistoryDimensionUnavailable {
		t.Fatalf("mismatch/unavailable precedence: coverage=%s stop=%s err=%v", walk.Coverage(), walk.StopReason(), err)
	}
}

// TestHistoryWalkContinuesHeaderProofAcrossBodyUnavailableCopy locks strict b:null boundary semantics.
func TestHistoryWalkContinuesHeaderProofAcrossBodyUnavailableCopy(t *testing.T) {
	current := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middle := []byte("Subject:middle\r\n\r\nmiddle\r\n")
	origin := []byte("Subject:origin\r\n\r\norigin\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, origin), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middle), `{"h":{"Subject":[{"d":["origin"]}]},"b":[{"c":[1,1]}]}`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, current), `{"h":{"Subject":[{"d":["middle"]}]},"b":null}`),
	)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, current))
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoveragePartial || walk.StopReason() != HistoryStopOriginReached || walk.ReachedInstance() != 1 || len(walk.Transitions()) != 2 || !walk.hadUnavailable {
		t.Fatalf("Walk() = coverage=%q stop=%q reached=%d transitions=%d gap=%t error=%v", walk.Coverage(), walk.StopReason(), walk.ReachedInstance(), len(walk.Transitions()), walk.hadUnavailable, err)
	}
	for _, transition := range walk.Transitions() {
		if transition.HeaderState() != HistoryDimensionMatched || transition.BodyState() != HistoryDimensionUnavailable {
			t.Fatalf("transition %d->%d = %q/%q", transition.FromInstance(), transition.ToInstance(), transition.HeaderState(), transition.BodyState())
		}
	}

	wrongOrigin := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:wrong\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middle), `{"h":{"Subject":[{"d":["origin"]}]},"b":[{"c":[1,1]}]}`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, current), `{"h":{"Subject":[{"d":["middle"]}]},"b":null}`),
	)
	failed, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), wrongOrigin, mustHistoryState(t, current))
	if err != nil || failed.Coverage() != HistoryCoverageFailed || failed.StopReason() != HistoryStopHashMismatch || failed.Transitions()[1].HeaderState() != HistoryDimensionMismatch {
		t.Fatalf("wrong older header = coverage=%q stop=%q error=%v", failed.Coverage(), failed.StopReason(), err)
	}

	malformed := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, origin), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middle), `{`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, current), `{"h":{"Subject":[{"d":["middle"]}]},"b":null}`),
	)
	stopped, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), malformed, mustHistoryState(t, current))
	if err != nil || stopped.Coverage() != HistoryCoveragePartial || stopped.StopReason() != HistoryStopRecipeInvalid || stopped.ReachedInstance() != 2 {
		t.Fatalf("malformed older recipe = coverage=%q stop=%q reached=%d error=%v", stopped.Coverage(), stopped.StopReason(), stopped.ReachedInstance(), err)
	}
}

// TestHistoryLaterUnsupportedIgnoresRetentionWidth verifies fold uses evaluated hops.
func TestHistoryLaterUnsupportedIgnoresRetentionWidth(t *testing.T) {
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleBytes := []byte("Subject:middle\r\n\r\nmiddle\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, "future", historyDigests(t, []byte("Subject:origin\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleBytes), `{"h":{"Subject":[{"d":["origin"]}]},"b":[{"d":["origin"]}]}`),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"Subject":[{"d":["middle"]}]},"b":[{"d":["middle"]}]}`),
	)
	limits := DefaultHistoryLimits()
	limits.MaxRetainedTransitions = 1
	walk, err := mustHistoryCoordinator(t, limits).Walk(context.Background(), historyPassResult(3), collection, mustHistoryState(t, currentBytes))
	if err != nil || !walk.Valid() || walk.Coverage() != HistoryCoveragePartial || walk.StopReason() != HistoryStopHashUnsupported || walk.ReachedInstance() != 1 || len(walk.Transitions()) != 1 {
		t.Fatalf("later unsupported retention mismatch: coverage=%s stop=%s err=%v", walk.Coverage(), walk.StopReason(), err)
	}
}

// TestAggregateCurrentPassRejectsForgedFacts verifies the authenticated gate is not status-only.
func TestAggregateCurrentPassRejectsForgedFacts(t *testing.T) {
	valid := historyPassResult(2)
	if !aggregateCurrentPass(valid) {
		t.Fatal("coherent PASS rejected")
	}
	withIgnored := func() Result {
		got := historyPassResult(2)
		got.checks = append(got.checks, CheckResult{
			Kind: CheckKindSignature, Status: CheckStatusUnsupported,
			Code: ErrorCodeUnsupportedAlgorithm, Algorithm: AlgorithmUnknown,
			Target: got.target,
		})
		got.signatureSets = append(got.signatureSets, SignatureSetResult{
			Index: 1, Algorithm: AlgorithmUnknown,
			Status:    SignatureSetStatusUnsupportedAlgorithm,
			KeyStatus: KeyStatusUnsupportedAlgorithm,
		})
		return got
	}
	if !aggregateCurrentPass(withIgnored()) {
		t.Fatal("coherent PASS with exact ignored unsupported pair rejected")
	}
	for _, forged := range []Result{
		NewResult(valid.target, TargetStatusPass, nil, nil),
		func() Result { got := valid; got.checks[0].Target.InstanceNumber = 1; return got }(),
		func() Result { got := valid; got.checks[0].HashStatus = HashStatusMismatch; return got }(),
		func() Result { got := valid; got.checks = append(got.checks, got.checks[0]); return got }(),
		func() Result {
			got := valid
			got.signatureSets = append(got.signatureSets, SignatureSetResult{Algorithm: AlgorithmRSASHA256, Status: SignatureSetStatusFail})
			return got
		}(),
		func() Result { got := withIgnored(); got.signatureSets = got.signatureSets[:1]; return got }(),
		func() Result { got := withIgnored(); got.checks = got.checks[:len(got.checks)-1]; return got }(),
		func() Result {
			got := withIgnored()
			got.checks[len(got.checks)-1].Code = ErrorCodeSignatureMismatch
			return got
		}(),
		func() Result {
			got := withIgnored()
			got.checks[len(got.checks)-1].Algorithm = AlgorithmRSASHA256
			return got
		}(),
		func() Result {
			got := withIgnored()
			got.signatureSets[len(got.signatureSets)-1].KeyStatus = KeyStatusNotChecked
			return got
		}(),
		func() Result {
			got := withIgnored()
			got.signatureSets[len(got.signatureSets)-1].Algorithm = AlgorithmRSASHA256
			return got
		}(),
		func() Result {
			got := withIgnored()
			got.signatureSets[len(got.signatureSets)-1].KeyPolicy.TestingDeclared = true
			return got
		}(),
	} {
		if aggregateCurrentPass(forged) {
			t.Fatal("forged aggregate PASS accepted")
		}
	}
}

// TestHistoryClosedContractsRejectZeroAndIncoherentValues verifies domain ownership.
func TestHistoryClosedContractsRejectZeroAndIncoherentValues(t *testing.T) {
	if HistoryCoverage("future").Known() || HistoryStopReason("future").Known() || HistoryDimensionState("future").Known() || HistoryRecipeMode("future").Known() || (HistoryUsage{}).Valid() || (HistoryTransition{}).Valid() || (HistoryWalk{}).Valid() {
		t.Fatal("unknown or zero history value became valid")
	}
	parser, _ := recipe.NewParser(recipe.Limits{})
	applier, _ := recipe.NewApplier(recipe.Limits{})
	canonicalizer, _ := canonical.NewCanonicalizer()
	for _, test := range []struct {
		name    string
		parser  recipe.Parser
		applier recipe.Applier
		limits  HistoryLimits
	}{
		{"parser", recipe.Parser{}, applier, HistoryLimits{}},
		{"applier", parser, recipe.Applier{}, HistoryLimits{}},
		{"limits", parser, applier, HistoryLimits{MaxTransitions: -1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewHistoryCoordinator(test.parser, test.applier, canonicalizer, test.limits)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != ErrorCodeHistoryInvalidOptions || typed.Class() != ErrorClassInvariant {
				t.Fatalf("constructor contract mismatch: err=%v", err)
			}
		})
	}
	coordinator := mustHistoryCoordinator(t, HistoryLimits{})
	state, collection := historyFixture(t, testHistoryBodyEmpty, []byte("Subject:current\r\n\r\n"), testHistorySHA256)
	//nolint:staticcheck // Deliberately verifies the direct nil-context fail-closed contract.
	if walk, err := coordinator.Walk(nil, historyPassResult(2), collection, state); walk.Valid() || !IsErrorCode(err, ErrorCodeHistoryInvalidState) {
		t.Fatalf("nil context contract mismatch: err=%v", err)
	}
	if walk, err := coordinator.Walk(context.Background(), historyPassResult(3), collection, state); walk.Valid() || !IsErrorCode(err, ErrorCodeHistoryInvalidState) {
		t.Fatalf("target mismatch contract: err=%v", err)
	}
	current, _ := collection.ByNumber(2)
	previous, _ := collection.ByNumber(1)
	if transition, err := (HistoryCoordinator{}).ValidatePrevious(state, current, previous); transition.Valid() || !IsErrorCode(err, ErrorCodeHistoryInvalidState) {
		t.Fatalf("zero coordinator contract: err=%v", err)
	}
	if transition, err := coordinator.ValidatePrevious(recipe.State{}, current, previous); transition.Valid() || !IsErrorCode(err, ErrorCodeHistoryInvalidState) {
		t.Fatalf("zero state contract: err=%v", err)
	}
}

// TestHistoryWalkRejectsImpossibleFoldPairs verifies closed constructor invariants.
func TestHistoryWalkRejectsImpossibleFoldPairs(t *testing.T) {
	usage := HistoryUsage{initialized: true}
	for _, walk := range []HistoryWalk{
		newHistoryWalk(HistoryCoveragePartial, HistoryStopHashMismatch, 2, 1, nil, usage),
		newHistoryWalk(HistoryCoverageUnsupported, HistoryStopHashUnsupported, 3, 1, nil, usage).withTerminal(HistoryTransition{header: HistoryDimensionUnsupported}),
		newHistoryWalk(HistoryCoverageComplete, HistoryStopOriginReached, 2, 1, nil, usage),
		newHistoryWalk(HistoryCoveragePartial, HistoryStopRecipeMissing, 2, 1, nil, usage),
	} {
		if walk.Valid() {
			t.Fatalf("impossible fold accepted: coverage=%s stop=%s", walk.Coverage(), walk.StopReason())
		}
	}
}

// TestHistoryLimitErrorCarriesStableDetails verifies bounded cumulative diagnostics.
func TestHistoryLimitErrorCarriesStableDetails(t *testing.T) {
	usage := HistoryUsage{initialized: true}
	parser, _ := recipe.NewParser(recipe.Limits{})
	_, recipeUsage, _ := parser.Parse([]byte(`{"b":null}`))
	limits := DefaultHistoryLimits()
	limits.MaxCumulativeWorkUnits = recipeUsage.WorkUnits() - 1
	_, err := usage.addRecipe(recipeUsage, limits)
	var typed *Error
	if !errors.As(err, &typed) || typed.LimitName() != historyLimitWork || typed.Limit() != limits.MaxCumulativeWorkUnits || typed.Count() != recipeUsage.WorkUnits() || typed.Class() != ErrorClassLimit {
		t.Fatalf("limit details mismatch: err=%v", err)
	}
}

// TestHistoryResultAttachmentDoesNotChangeCurrentFacts verifies sealed noninterference.
func TestHistoryResultAttachmentDoesNotChangeCurrentFacts(t *testing.T) {
	current := historyPassResult(2)
	state, collection := historyFixture(t, `{`, []byte("Subject:previous\r\n\r\n"), testHistorySHA256)
	walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), current, collection, state)
	if err != nil {
		t.Fatal(err)
	}
	attached := current.withHistory(walk)
	if attached.Draft() != current.Draft() || attached.Status() != current.Status() || attached.Target() != current.Target() || !reflect.DeepEqual(attached.Checks(), current.Checks()) || !reflect.DeepEqual(attached.SignatureSets(), current.SignatureSets()) || attached.CustodyStatus() != current.CustodyStatus() {
		t.Fatal("history changed current truth")
	}
	beforeFlags, beforeOK := current.TargetFlagCandidate()
	afterFlags, afterOK := attached.TargetFlagCandidate()
	if beforeOK != afterOK || beforeFlags != afterFlags {
		t.Fatal("history changed current flag evidence")
	}
	got, ok := attached.historyWalk()
	if !ok || !got.Valid() {
		t.Fatal("history not retained internally")
	}
	if wrong := current.withHistory(newInternalContractHistoryWalk(1)); wrong.hasHistory {
		t.Fatal("cross-target history attached")
	}
}

// TestVerifierIntegratesHistoryOnlyAfterAggregatePass verifies hot-path gate and fallback.
func TestVerifierIntegratesHistoryOnlyAfterAggregatePass(t *testing.T) {
	fixture := newRSAVerificationFixture(t)
	verifier := mustVerifierForFixture(t, fixture)
	passed, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	if err != nil || passed.Status() != TargetStatusPass {
		t.Fatalf("PASS fixture failed: status=%s err=%v", passed.Status(), err)
	}
	walk, ok := passed.historyWalk()
	if !ok || !walk.Valid() || walk.TargetInstance() != 1 || walk.Usage().WorkUnits() != 0 {
		t.Fatal("PASS did not attach zero-hop origin walk")
	}
	failed, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: NewEnvelope([]byte("<wrong@example.test>"), [][]byte{[]byte("<other@example.test>")})})
	if err != nil || failed.Status() == TargetStatusPass {
		t.Fatalf("non-PASS fixture mismatch: status=%s err=%v", failed.Status(), err)
	}
	if _, ok := failed.historyWalk(); ok {
		t.Fatal("non-PASS performed history work")
	}
	verifier.history = HistoryCoordinator{}
	fallback, err := verifier.Verify(context.Background(), Request{Message: fixture.message, Envelope: matchingEnvelope()})
	fallbackWalk, ok := fallback.historyWalk()
	if err != nil || fallback.Status() != TargetStatusPass || !ok || fallbackWalk.StopReason() != HistoryStopInternalContract {
		t.Fatalf("internal fallback mismatch: status=%s stop=%s err=%v", fallback.Status(), fallbackWalk.StopReason(), err)
	}
}

// TestAttachAuthenticatedHistorySealsPostPassOutcomes verifies the m>1 integration boundary.
func TestAttachAuthenticatedHistorySealsPostPassOutcomes(t *testing.T) {
	currentBytes := []byte("Subject:current\r\n\r\nbody\r\n")
	currentMessage, err := rawmsg.Parse(currentBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, recipeJSON, algorithm string
		previous                    []byte
		stop                        HistoryStopReason
		limits                      HistoryLimits
	}{
		{"malformed", `{`, testHistorySHA256, []byte("Subject:previous\r\n\r\n"), HistoryStopRecipeInvalid, HistoryLimits{}},
		{"mismatch", testHistoryBodyEmpty, testHistorySHA256, []byte("Subject:different\r\n\r\n"), HistoryStopHashMismatch, HistoryLimits{}},
		{"unsupported", testHistoryBodyEmpty, "future", []byte("Subject:current\r\n\r\n"), HistoryStopHashUnsupported, HistoryLimits{}},
		{"limit", testHistoryBodyEmpty, testHistorySHA256, []byte("Subject:current\r\n\r\nbody\r\n"), HistoryStopLimitExceeded, HistoryLimits{MaxCumulativeDecodedBytes: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := []string{
				historyInstanceLine(1, test.algorithm, historyDigests(t, test.previous), ""),
				historyInstanceLine(2, testHistorySHA256, historyDigests(t, currentBytes), test.recipeJSON),
			}
			input := verificationInput{request: Request{Message: currentMessage}, instances: parseHistoryInstances(t, lines...)}
			current := historyPassResult(2)
			verifier := Verifier{history: mustHistoryCoordinator(t, test.limits)}
			attached, err := verifier.attachAuthenticatedHistory(context.Background(), current, input)
			walk, ok := attached.historyWalk()
			if err != nil || !ok || !walk.Valid() || walk.StopReason() != test.stop {
				t.Fatalf("sealed integration mismatch: stop=%s err=%v", walk.StopReason(), err)
			}
			if attached.Draft() != current.Draft() || attached.Target() != current.Target() || attached.Status() != current.Status() || !reflect.DeepEqual(attached.Checks(), current.Checks()) || !reflect.DeepEqual(attached.SignatureSets(), current.SignatureSets()) || attached.CustodyStatus() != current.CustodyStatus() {
				t.Fatal("sealed history changed current facts")
			}
		})
	}
}

// TestHistoryMissingSelectionAttachmentPreservesCurrentFacts verifies the future-compatible sealed lane.
func TestHistoryMissingSelectionAttachmentPreservesCurrentFacts(t *testing.T) {
	current := historyPassResult(2)
	walk := newHistoryWalk(
		HistoryCoverageUnreconstructable,
		HistoryStopHashMissing,
		2,
		2,
		nil,
		HistoryUsage{initialized: true},
	)
	if !walk.Valid() {
		t.Fatal("future-compatible missing-selection walk is invalid")
	}
	attached := current.withHistory(walk)
	got, ok := attached.historyWalk()
	if !ok || got.StopReason() != HistoryStopHashMissing || got.Coverage() != HistoryCoverageUnreconstructable {
		t.Fatalf("missing-selection attachment = %#v/%t", got, ok)
	}
	if attached.Draft() != current.Draft() || attached.Target() != current.Target() || attached.Status() != current.Status() || !reflect.DeepEqual(attached.Checks(), current.Checks()) || !reflect.DeepEqual(attached.SignatureSets(), current.SignatureSets()) || attached.CustodyStatus() != current.CustodyStatus() {
		t.Fatal("missing-selection history changed current facts")
	}
}

// TestHistoryCumulativeUsageLimitsAreImmediate verifies each failed attempt is charged once.
func TestHistoryCumulativeUsageLimitsAreImmediate(t *testing.T) {
	state, collection := historyFixture(t, testHistoryBodyEmpty, []byte("Subject:current\r\n\r\n"), testHistorySHA256)
	baseline, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(2), collection, state)
	if err != nil || !baseline.Valid() {
		t.Fatal("baseline walk failed")
	}
	usage := baseline.Usage()
	checks := []struct {
		name  string
		exact int
		set   func(*HistoryLimits, int)
	}{
		{"decoded", usage.DecodedBytes(), func(l *HistoryLimits, n int) { l.MaxCumulativeDecodedBytes = n }},
		{"emitted", usage.EmittedBytes(), func(l *HistoryLimits, n int) { l.MaxCumulativeEmittedBytes = n }},
		{"items", usage.Items(), func(l *HistoryLimits, n int) { l.MaxCumulativeItems = n }},
		{"work", usage.WorkUnits(), func(l *HistoryLimits, n int) { l.MaxCumulativeWorkUnits = n }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			exact := DefaultHistoryLimits()
			check.set(&exact, check.exact)
			walk, err := mustHistoryCoordinator(t, exact).Walk(context.Background(), historyPassResult(2), collection, state)
			if err != nil || walk.Coverage() != HistoryCoverageComplete {
				t.Fatalf("exact rejected: coverage=%s err=%v", walk.Coverage(), err)
			}
			over := DefaultHistoryLimits()
			check.set(&over, check.exact-1)
			walk, err = mustHistoryCoordinator(t, over).Walk(context.Background(), historyPassResult(2), collection, state)
			if err != nil || !walk.Valid() || walk.StopReason() != HistoryStopLimitExceeded || walk.Usage().WorkUnits() == 0 {
				t.Fatalf("one-over mismatch: stop=%s err=%v", walk.StopReason(), err)
			}
		})
	}
}

// mustHistoryCoordinator constructs the fixed internal coordinator.
func mustHistoryCoordinator(t *testing.T, limits HistoryLimits) HistoryCoordinator {
	t.Helper()
	parser, err := recipe.NewParser(recipe.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	applier, err := recipe.NewApplier(recipe.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewHistoryCoordinator(parser, applier, canonicalizer, limits)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

// historyPassResult constructs one aggregate-current PASS gate fixture.
func historyPassResult(number uint64) Result {
	target := Target{Sequence: 1, InstanceNumber: number}
	checks := []CheckResult{
		{Kind: CheckKindHeaderHash, Status: CheckStatusPass, HashStatus: HashStatusPass, Target: target},
		{Kind: CheckKindBodyHash, Status: CheckStatusPass, HashStatus: HashStatusPass, Target: target},
		{Kind: CheckKindSignature, Status: CheckStatusPass, Algorithm: AlgorithmRSASHA256, Target: target},
	}
	sets := []SignatureSetResult{{Index: 0, Algorithm: AlgorithmRSASHA256, Status: SignatureSetStatusPass, KeyStatus: KeyStatusFound}}
	return NewResult(target, TargetStatusPass, checks, sets)
}

// historyFixture returns controlled current state and two parsed instances.
func historyFixture(t *testing.T, recipeJSON string, previous []byte, algorithm string) (recipe.State, instance.Collection) {
	t.Helper()
	state := mustHistoryState(t, []byte("Subject:current\r\n\r\nbody\r\n"))
	digests := historyDigests(t, previous)
	return state, parseHistoryCollection(t,
		historyInstanceLine(1, algorithm, digests, ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, []byte("Subject:current\r\n\r\nbody\r\n")), recipeJSON),
	)
}

// laterHistoryFailureFixture constructs one matched hop followed by a selected failure recipe.
func laterHistoryFailureFixture(t *testing.T, secondRecipe string) (recipe.State, instance.Collection) {
	t.Helper()
	currentBytes := []byte("Subject:current\r\n\r\ncurrent\r\n")
	middleBytes := []byte("Subject:middle\r\n\r\nmiddle\r\n")
	collection := parseHistoryCollection(t,
		historyInstanceLine(1, testHistorySHA256, historyDigests(t, []byte("Subject:origin\r\n\r\norigin\r\n")), ""),
		historyInstanceLine(2, testHistorySHA256, historyDigests(t, middleBytes), secondRecipe),
		historyInstanceLine(3, testHistorySHA256, historyDigests(t, currentBytes), `{"h":{"Subject":[{"d":["middle"]}]},"b":[{"d":["middle"]}]}`),
	)
	return mustHistoryState(t, currentBytes), collection
}

type historyHashFixture struct{ header, body string }

// historyDigests returns canonical SHA-256 fixture strings.
func historyDigests(t *testing.T, message []byte) historyHashFixture {
	t.Helper()
	parsed, err := rawmsg.Parse(message)
	if err != nil {
		t.Fatal(err)
	}
	canonicalizer, _ := canonical.NewCanonicalizer()
	header, _ := canonicalizer.HeaderHashFromMessage(parsed)
	body, _ := canonicalizer.BodyHashFromMessage(parsed)
	headerDigest, _ := header.Digest()
	bodyDigest, _ := body.Digest()
	return historyHashFixture{base64.StdEncoding.EncodeToString(headerDigest.Bytes()), base64.StdEncoding.EncodeToString(bodyDigest.Bytes())}
}

// historyInstanceLine constructs one parser-owned Message-Instance field.
func historyInstanceLine(number uint64, algorithm string, hashes historyHashFixture, recipeJSON string) string {
	line := "Message-Instance: m=" + strconv.FormatUint(number, 10) + "; h=" + algorithm + ":" + hashes.header + ":" + hashes.body
	if recipeJSON != "" {
		line += "; r=" + base64.StdEncoding.EncodeToString([]byte(recipeJSON))
	}
	return line + ";\r\n"
}

// parseHistoryCollection parses synthetic Message-Instance fields.
func parseHistoryCollection(t *testing.T, fields ...string) instance.Collection {
	t.Helper()
	items := parseHistoryInstances(t, fields...)
	collection, err := instance.NewCollection(items)
	if err != nil {
		t.Fatal(err)
	}
	return collection
}

// parseHistoryInstances parses synthetic Message-Instance fields.
func parseHistoryInstances(t *testing.T, fields ...string) []instance.MessageInstance {
	t.Helper()
	parsed, err := rawmsg.Parse([]byte(strings.Join(fields, "") + "Subject:carrier\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	items, err := instance.Extract(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// mustHistoryState parses one controlled reconstruction state.
func mustHistoryState(t *testing.T, message []byte) recipe.State {
	t.Helper()
	parsed, err := rawmsg.Parse(message)
	if err != nil {
		t.Fatal(err)
	}
	state, err := recipe.NewState(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
