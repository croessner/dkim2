package verify

import (
	"context"
	"math"
	"reflect"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/recipe"
)

// TestEveryHistoryHardMaximumAcceptsExactAndRejectsOneOver locks cumulative and retention ceilings.
func TestEveryHistoryHardMaximumAcceptsExactAndRejectsOneOver(t *testing.T) {
	exact := DefaultHistoryLimits()
	if _, err := exact.normalized(); err != nil {
		t.Fatalf("exact history maxima rejected: %v", err)
	}
	typeOfLimits := reflect.TypeOf(exact)
	for index := 0; index < typeOfLimits.NumField(); index++ {
		field := typeOfLimits.Field(index)
		t.Run(field.Name, func(t *testing.T) {
			over := DefaultHistoryLimits()
			value := reflect.ValueOf(&over).Elem().Field(index)
			value.SetInt(value.Int() + 1)
			if _, err := over.normalized(); !IsErrorCode(err, ErrorCodeHistoryInvalidOptions) {
				t.Fatalf("one-over history maximum accepted: %v", err)
			}
		})
	}
}

// TestHistoryWalkManyInstancesHonorsExactAndOneOverTransitionLimit proves bounded long-chain work.
func TestHistoryWalkManyInstancesHonorsExactAndOneOverTransitionLimit(t *testing.T) {
	const exactInstances = 129
	exactState, exactCollection := manyHistoryFixture(t, exactInstances)
	exact, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(uint64(exactInstances)), exactCollection, exactState)
	if err != nil || !exact.Valid() || exact.Coverage() != HistoryCoverageComplete || exact.ReachedInstance() != 1 || len(exact.Transitions()) != 128 {
		t.Fatalf("exact long-chain limit failed: coverage=%s reached=%d retained=%d", exact.Coverage(), exact.ReachedInstance(), len(exact.Transitions()))
	}

	overState, overCollection := manyHistoryFixture(t, exactInstances+1)
	over, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(uint64(exactInstances+1)), overCollection, overState)
	if err != nil || !over.Valid() || over.Coverage() != HistoryCoveragePartial || over.StopReason() != HistoryStopLimitExceeded || over.ReachedInstance() != 2 || len(over.Transitions()) != 128 {
		t.Fatalf("one-over long-chain limit failed: coverage=%s stop=%s reached=%d retained=%d", over.Coverage(), over.StopReason(), over.ReachedInstance(), len(over.Transitions()))
	}
}

// TestHistoryWalkCumulativeWorkStopsBetweenOtherwiseValidHops proves per-operation limits cannot bypass walk limits.
func TestHistoryWalkCumulativeWorkStopsBetweenOtherwiseValidHops(t *testing.T) {
	state, collection := manyHistoryFixture(t, 3)
	baseline, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(3), collection, state)
	if err != nil || baseline.Coverage() != HistoryCoverageComplete {
		t.Fatal("cumulative baseline failed")
	}
	limits := DefaultHistoryLimits()
	limits.MaxCumulativeWorkUnits = baseline.Usage().WorkUnits() - 1
	limited, err := mustHistoryCoordinator(t, limits).Walk(context.Background(), historyPassResult(3), collection, state)
	if err != nil || !limited.Valid() || limited.Coverage() != HistoryCoveragePartial || limited.StopReason() != HistoryStopLimitExceeded || limited.ReachedInstance() != 2 {
		t.Fatalf("cumulative work limit failed: coverage=%s stop=%s reached=%d", limited.Coverage(), limited.StopReason(), limited.ReachedInstance())
	}
}

// TestHistoryCoordinatorConcurrentReuseIsDeterministic exercises immutable shared coordination under race detection.
func TestHistoryCoordinatorConcurrentReuseIsDeterministic(t *testing.T) {
	const workers = 32
	state, collection := manyHistoryFixture(t, 3)
	coordinator := mustHistoryCoordinator(t, HistoryLimits{})
	want, err := coordinator.Walk(context.Background(), historyPassResult(3), collection, state)
	if err != nil || !want.Valid() {
		t.Fatal("concurrent history fixture failed")
	}
	var wait sync.WaitGroup
	failures := make(chan string, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			walk, walkErr := coordinator.Walk(context.Background(), historyPassResult(3), collection, state)
			if walkErr != nil || !walk.Valid() || walk.Coverage() != want.Coverage() || walk.StopReason() != want.StopReason() || walk.Usage() != want.Usage() || len(walk.Transitions()) != len(want.Transitions()) {
				failures <- "walk"
			}
		}()
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("concurrent history reuse failed: %s", failure)
	}
}

// TestHistoryArithmeticEdgesStayChecked verifies cumulative counters reject overflow and negatives.
func TestHistoryArithmeticEdgesStayChecked(t *testing.T) {
	if value, ok := historyAdd(math.MaxInt-1, 1); !ok || value != math.MaxInt {
		t.Fatal("exact history addition failed")
	}
	if _, ok := historyAdd(math.MaxInt, 1); ok {
		t.Fatal("overflowing history addition succeeded")
	}
	if _, ok := historyAdd(-1, 1); ok {
		t.Fatal("negative history addition succeeded")
	}
}

// manyHistoryFixture constructs a contiguous identity-recipe chain of the requested length.
func manyHistoryFixture(t *testing.T, count int) (recipe.State, instance.Collection) {
	t.Helper()
	message := []byte("Subject:current\r\n\r\nbody\r\n")
	digests := historyDigests(t, message)
	fields := make([]string, count)
	for number := 1; number <= count; number++ {
		recipeJSON := ""
		if number > 1 {
			recipeJSON = `{"h":{"Subject":[{"c":[1,1]}]}}`
		}
		fields[number-1] = historyInstanceLine(uint64(number), testHistorySHA256, digests, recipeJSON)
	}
	return mustHistoryState(t, message), parseHistoryCollection(t, fields...)
}
