package verify

import (
	"context"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
)

// TestEveryHistoryHardMaximumAcceptsExactAndRejectsOneOver locks cumulative and retention ceilings.
func TestEveryHistoryHardMaximumAcceptsExactAndRejectsOneOver(t *testing.T) {
	exact := DefaultHistoryLimits()
	if _, err := exact.normalized(); err != nil {
		t.Fatalf("exact history maxima rejected: %v", err)
	}
	typeOfLimits := reflect.TypeFor[HistoryLimits]()
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

// TestHistoryWalkHonorsMessageInstanceCollectionCap proves bounded long-chain parsing and work.
func TestHistoryWalkHonorsMessageInstanceCollectionCap(t *testing.T) {
	const exactInstances = 128
	exactState, exactCollection := manyHistoryFixture(t, exactInstances)
	exact, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(uint64(exactInstances)), exactCollection, exactState)
	if err != nil || !exact.Valid() || exact.Coverage() != HistoryCoverageComplete || exact.ReachedInstance() != 1 || len(exact.Transitions()) != 127 {
		t.Fatalf("exact long-chain limit failed: coverage=%s reached=%d retained=%d", exact.Coverage(), exact.ReachedInstance(), len(exact.Transitions()))
	}

	_, overFields := manyHistoryFields(t, exactInstances+1)
	message, parseErr := rawmsg.Parse([]byte(strings.Join(overFields, "") + "Subject:carrier\r\n\r\nbody\r\n"))
	if parseErr != nil {
		t.Fatal("one-over history fixture raw message failed")
	}
	if _, err := instance.Extract(message); !instance.IsErrorCode(err, instance.ErrorCodeLimitExceeded) {
		t.Fatal("one-over history fixture bypassed Message-Instance collection cap")
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
		wait.Go(func() {
			walk, walkErr := coordinator.Walk(context.Background(), historyPassResult(3), collection, state)
			if walkErr != nil || !walk.Valid() || walk.Coverage() != want.Coverage() || walk.StopReason() != want.StopReason() || walk.Usage() != want.Usage() || len(walk.Transitions()) != len(want.Transitions()) {
				failures <- "walk"
			}
		})
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
	state, fields := manyHistoryFields(t, count)
	return state, parseHistoryCollection(t, fields...)
}

// manyHistoryFields constructs contiguous identity-recipe fields without parsing them.
func manyHistoryFields(t *testing.T, count int) (recipe.State, []string) {
	t.Helper()
	message := []byte("Subject:current\r\n\r\nbody\r\n")
	digests := historyDigests(t, message)
	fields := make([]string, count)
	for number := 1; number <= count; number++ {
		recipeJSON := ""
		if number > 1 {
			recipeJSON = `{"h":{"subject":[{"c":[1,1]}]}}`
		}
		fields[number-1] = historyInstanceLine(uint64(number), testHistorySHA256, digests, recipeJSON)
	}
	return mustHistoryState(t, message), fields
}
