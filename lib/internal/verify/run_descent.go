package verify

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/recipe"
)

const runDescentRedactedText = "verify.RunDescent{redacted}"

// RunDescentOutcome is the closed result of one floor-bounded descent.
type RunDescentOutcome string

const (
	// RunDescentReconstructed reports a proven state at the requested floor instance.
	RunDescentReconstructed RunDescentOutcome = "reconstructed"
	// RunDescentNotReconstructable reports that the descent could not prove the floor state.
	RunDescentNotReconstructable RunDescentOutcome = "not_reconstructable"
)

// Known reports whether the outcome belongs to the closed vocabulary.
func (o RunDescentOutcome) Known() bool {
	return o == RunDescentReconstructed || o == RunDescentNotReconstructable
}

// RunDescentFailure is the closed reason a descent was not reconstructable.
type RunDescentFailure string

const (
	// RunDescentRecipeInvalid reports malformed authenticated recipe JSON.
	RunDescentRecipeInvalid RunDescentFailure = "recipe_invalid"
	// RunDescentApplicationInvalid reports a recipe that cannot be applied to its state.
	RunDescentApplicationInvalid RunDescentFailure = "application_invalid"
	// RunDescentSourceUnavailable reports a copy from unavailable body state.
	RunDescentSourceUnavailable RunDescentFailure = "source_unavailable"
	// RunDescentLimitExceeded reports a transition, cumulative, or canonical ceiling.
	RunDescentLimitExceeded RunDescentFailure = "limit_exceeded"
	// RunDescentHashMismatch reports a reconstructed state whose supported digest differs.
	RunDescentHashMismatch RunDescentFailure = "hash_mismatch"
	// RunDescentUnsupportedHash reports an instance without any supported hash tuple.
	RunDescentUnsupportedHash RunDescentFailure = "unsupported_hash"
	// RunDescentInternalContract reports an impossible internal state.
	RunDescentInternalContract RunDescentFailure = "internal_contract"
)

// Known reports whether the failure belongs to the closed vocabulary.
func (f RunDescentFailure) Known() bool {
	switch f {
	case RunDescentRecipeInvalid, RunDescentApplicationInvalid, RunDescentSourceUnavailable, RunDescentLimitExceeded,
		RunDescentHashMismatch, RunDescentUnsupportedHash, RunDescentInternalContract:
		return true
	default:
		return false
	}
}

// RunDescent is the immutable result of walking an already proven current
// state down to one floor instance while re-proving every intermediate state.
// Unlike a chain-verification walk it never emits a partial state: either the
// floor state was proven or nothing is exposed.
type RunDescent struct {
	outcome     RunDescentOutcome
	failure     RunDescentFailure
	state       recipe.State
	reached     uint64
	degraded    bool
	rewritten   []string
	initialized bool
}

// Valid reports whether the descent was produced by a coordinator and is coherent.
func (d RunDescent) Valid() bool {
	if !d.initialized || !d.outcome.Known() {
		return false
	}
	if d.outcome == RunDescentReconstructed {
		return d.failure == "" && d.state.Valid() && d.reached > 0 && (d.degraded || d.state.BodyState() != recipe.BodyAvailabilityUnavailable)
	}
	return d.failure.Known() && !d.state.Valid()
}

// Outcome returns the closed descent outcome.
func (d RunDescent) Outcome() RunDescentOutcome { return d.outcome }

// Failure returns the closed reason when the descent was not reconstructable.
func (d RunDescent) Failure() RunDescentFailure { return d.failure }

// ReachedInstance returns the floor instance reached by a reconstructed descent or zero.
func (d RunDescent) ReachedInstance() uint64 {
	if !d.Valid() || d.outcome != RunDescentReconstructed {
		return 0
	}
	return d.reached
}

// Degraded reports whether body evidence was unavailable at any point of the
// descent: the initial state was headers-only, a transition carried a null or
// body-unavailable recipe, or the floor state carries no body. It stays true
// even when a later data-only recipe re-materialized a body, because that
// body was never observed by the system that received the message.
func (d RunDescent) Degraded() bool {
	return d.Valid() && d.outcome == RunDescentReconstructed && d.degraded
}

// RewrittenHeaderNames returns the sorted, deduplicated canonical header
// names that any recipe applied during a reconstructed descent rewrote. The
// applier regroups exactly these names; every other name passed through in
// its source order. It is nil for a non-reconstructable descent.
func (d RunDescent) RewrittenHeaderNames() []string {
	if !d.Valid() || d.outcome != RunDescentReconstructed {
		return nil
	}
	return slices.Clone(d.rewritten)
}

// State returns the proven floor state and false for a non-reconstructable descent.
func (d RunDescent) State() (recipe.State, bool) {
	if !d.Valid() || d.outcome != RunDescentReconstructed {
		return recipe.State{}, false
	}
	return d.state, true
}

// String returns a constant secret-safe descent summary.
func (RunDescent) String() string { return runDescentRedactedText }

// GoString returns the constant secret-safe descent Go representation.
func (d RunDescent) GoString() string { return d.String() }

// Format routes every descent formatting form through the redacted summary.
func (d RunDescent) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, d.String()) }

// notReconstructable seals one closed failure without a state.
func notReconstructable(failure RunDescentFailure) RunDescent {
	if !failure.Known() {
		failure = RunDescentInternalContract
	}
	return RunDescent{outcome: RunDescentNotReconstructable, failure: failure, initialized: true}
}

// Descend walks initial, the proven state of the highest instance of
// collection, down to the floor instance by applying each authenticated
// recipe and re-proving every intermediate state against its
// Message-Instance hashes. The initial state may be headers-only; its header
// hash, and its body hash when known, are re-proven against the highest
// instance before the first transition so that a caller cannot inject an
// unproven state. An unsupported tuple, a limit, a malformed recipe, an
// unavailable source, or a mismatch makes the descent not reconstructable.
// maxCanonicalBytes is the aggregate Section 6 canonical work ceiling shared
// by the initial-state proof and every transition; exhausting it is a limit
// failure, never a partial state.
func (c HistoryCoordinator) Descend(ctx context.Context, collection instance.Collection, initial recipe.State, floor uint64, maxCanonicalBytes int) (RunDescent, error) {
	if ctx == nil || !c.initialized || !collection.Valid() || !initial.Valid() {
		return RunDescent{}, historyError(ErrorCodeHistoryInvalidState)
	}
	target := collection.HighestNumber()
	if floor == 0 || floor > target {
		return RunDescent{}, historyError(ErrorCodeHistoryInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return RunDescent{}, err
	}
	if maxCanonicalBytes <= 0 {
		return notReconstructable(RunDescentLimitExceeded), nil
	}
	currentInstance, ok := collection.ByNumber(target)
	if !ok {
		return RunDescent{}, historyError(ErrorCodeHistoryInvalidState)
	}
	matched, supported, work, err := c.initialStateMatches(initial, currentInstance, maxCanonicalBytes)
	if err != nil {
		if IsErrorCode(err, ErrorCodeHistoryLimitExceeded) {
			return notReconstructable(RunDescentLimitExceeded), nil
		}
		return RunDescent{}, err
	}
	if !supported {
		return notReconstructable(RunDescentUnsupportedHash), nil
	}
	if !matched {
		return RunDescent{}, historyError(ErrorCodeHistoryInvalidState)
	}
	state := initial
	usage, err := HistoryUsage{initialized: true}.addCanonical(work, maxCanonicalBytes)
	if err != nil {
		return notReconstructable(RunDescentLimitExceeded), nil
	}
	degraded := initial.BodyState() == recipe.BodyAvailabilityUnavailable
	rewritten := make([]string, 0)
	for number := target; number > floor; number-- {
		if err := ctx.Err(); err != nil {
			return RunDescent{}, err
		}
		if target-number+1 > uint64(c.limits.MaxTransitions) {
			return notReconstructable(RunDescentLimitExceeded), nil
		}
		step, stop := c.transitionStep(collection, number, state, usage, maxCanonicalBytes)
		usage = step.usage
		if stop != "" {
			return notReconstructable(descentFailureForStop(stop)), nil
		}
		next, transition := step.state, step.facts
		rewritten = append(rewritten, step.rewritten...)
		if transition.header == HistoryDimensionMismatch || transition.body == HistoryDimensionMismatch {
			return notReconstructable(RunDescentHashMismatch), nil
		}
		if transition.header == HistoryDimensionUnsupported || transition.body == HistoryDimensionUnsupported {
			return notReconstructable(RunDescentUnsupportedHash), nil
		}
		if transition.body == HistoryDimensionUnavailable {
			degraded = true
		}
		state = next
	}
	if !state.Valid() {
		return notReconstructable(RunDescentInternalContract), nil
	}
	degraded = degraded || state.BodyState() == recipe.BodyAvailabilityUnavailable
	slices.Sort(rewritten)
	descent := RunDescent{outcome: RunDescentReconstructed, state: state, reached: floor, degraded: degraded, rewritten: slices.Compact(rewritten), initialized: true}
	if !descent.Valid() {
		return notReconstructable(RunDescentInternalContract), nil
	}
	return descent, nil
}

// initialStateMatches re-proves the header hash, and the body hash when the
// body is known, of the initial state against every supported tuple of the
// current instance under the remaining canonical work ceiling. It reports
// (matched, supported, canonical work, error); exhausting the ceiling is a
// history limit error the caller maps onto its own closed outcome.
func (c HistoryCoordinator) initialStateMatches(state recipe.State, current instance.MessageInstance, remaining int) (bool, bool, int, error) {
	sets, selection := current.SupportedHashSets()
	if selection != instance.HashSelectionStatusSelected {
		return false, false, 0, nil
	}
	headerInput, bodyInput, bodyKnown, work, err := c.canonicalInputsWithin(state, remaining)
	if err != nil {
		if canonical.IsErrorCode(err, canonical.ErrorCodeLimitExceeded) || IsErrorCode(err, ErrorCodeHistoryLimitExceeded) {
			return false, true, 0, historyLimitError("max_cumulative_canonical_bytes", remaining, remaining+1)
		}
		return false, true, 0, historyError(ErrorCodeHistoryInvalidState)
	}
	for _, set := range sets {
		algorithm, ok := canonicalHashAlgorithm(set.Name())
		headerExpected, headerOK := set.HeaderHash()
		bodyExpected, bodyOK := set.BodyHash()
		if !ok || !headerOK || !bodyOK {
			return false, true, work, historyError(ErrorCodeHistoryInternalContract)
		}
		digester, newErr := canonical.NewCanonicalizer(canonical.WithLimits(c.canonicalizer.Options().Limits), canonical.WithHashAlgorithm(algorithm))
		if newErr != nil {
			return false, true, work, historyError(ErrorCodeHistoryInternalContract)
		}
		headerDigest, headerErr := digester.Digest(headerInput)
		if headerErr != nil || historyDigestState(headerDigest.Bytes(), headerExpected.Decoded()) != HistoryDimensionMatched {
			return false, true, work, nil
		}
		if !bodyKnown {
			continue
		}
		bodyDigest, bodyErr := digester.Digest(bodyInput)
		if bodyErr != nil || historyDigestState(bodyDigest.Bytes(), bodyExpected.Decoded()) != HistoryDimensionMatched {
			return false, true, work, nil
		}
	}
	return true, true, work, nil
}

// descentFailureForStop maps one sealed history stop onto the closed descent failure.
func descentFailureForStop(stop HistoryStopReason) RunDescentFailure {
	switch stop {
	case HistoryStopRecipeInvalid:
		return RunDescentRecipeInvalid
	case HistoryStopApplicationInvalid:
		return RunDescentApplicationInvalid
	case HistoryStopSourceUnavailable:
		return RunDescentSourceUnavailable
	case HistoryStopLimitExceeded:
		return RunDescentLimitExceeded
	case HistoryStopHashMismatch:
		return RunDescentHashMismatch
	case HistoryStopHashUnsupported:
		return RunDescentUnsupportedHash
	default:
		return RunDescentInternalContract
	}
}

// DescendEmbeddedRun descends an already verified embedded original from its
// proven current state to the floor instance referenced by the previous hop
// signature. The initial state may be headers-only when the original was
// embedded as text/rfc822-headers. It reuses the verifier's history
// coordinator under the verifier's all-hop canonical work ceiling and never
// changes chain-verification semantics.
func (v Verifier) DescendEmbeddedRun(ctx context.Context, embedded EmbeddedInput, initial recipe.State, floor uint64) (RunDescent, error) {
	if ctx == nil || !v.valid() || !embedded.Valid() || !initial.Valid() {
		return RunDescent{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if err := ctx.Err(); err != nil {
		return RunDescent{}, err
	}
	collection, err := instance.NewCollection(embedded.input.instances)
	if err != nil {
		return RunDescent{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, err)
	}
	return v.history.Descend(ctx, collection, initial, floor, v.options.RevisionLimits.MaxCanonicalWorkBytes)
}
