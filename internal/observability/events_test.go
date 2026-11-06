package observability

import (
	"context"
	"testing"
)

// TestEventGrammarRejectsCrossKindFacts proves event construction has no arbitrary escape hatch.
func TestEventGrammarRejectsCrossKindFacts(t *testing.T) {
	valid, ok := NewEvent(
		KindVerifyCompleted, OperationVerify, ResultSuccess, ReasonNone,
		ErrorNone, AlgorithmRSA, CacheNotUsed, BucketSmall,
		BucketNone, BucketNone, BucketNone, BucketNone,
	)
	if !ok || !valid.Valid() {
		t.Fatal("valid verification event was rejected")
	}
	_, ok = NewEvent(
		KindDNSLookupCompleted, OperationDNSLookup, ResultSuccess, ReasonNone,
		ErrorNone, AlgorithmRSA, CacheHit, BucketSmall,
		BucketSmall, BucketNone, BucketNone, BucketNone,
	)
	if ok {
		t.Fatal("DNS event accepted a message-shape fact")
	}
}

// TestEventGrammarRejectsContradictoryOutcomeFacts proves immutable events stay coherent.
func TestEventGrammarRejectsContradictoryOutcomeFacts(t *testing.T) {
	for _, testCase := range []struct {
		result     Result
		reason     Reason
		errorClass ErrorClass
	}{
		{result: ResultSuccess, reason: ReasonUnavailable, errorClass: ErrorNone},
		{result: ResultSuccess, reason: ReasonNone, errorClass: ErrorInternal},
		{result: ResultTemporary, reason: ReasonNone, errorClass: ErrorNone},
		{result: ResultInternal, reason: ReasonProtocol, errorClass: ErrorInternal},
		{result: ResultInternal, reason: ReasonUnavailable, errorClass: ErrorNone},
	} {
		_, ok := NewEvent(
			KindVerifyCompleted,
			OperationVerify,
			testCase.result,
			testCase.reason,
			testCase.errorClass,
			AlgorithmNone,
			CacheNotUsed,
			BucketSmall,
			BucketNone,
			BucketNone,
			BucketNone,
			BucketNone,
		)
		if ok {
			t.Fatalf(
				"contradictory outcome accepted: result=%d reason=%d error=%d",
				testCase.result,
				testCase.reason,
				testCase.errorClass,
			)
		}
	}
}

type panicSink struct{}

// Observe injects one hostile sink panic.
func (panicSink) Observe(context.Context, Event) { panic("private-marker") }

// TestObserveContainsSinkPanic proves telemetry cannot affect caller results.
func TestObserveContainsSinkPanic(t *testing.T) {
	event, ok := NewEvent(
		KindVerifyCompleted, OperationVerify, ResultFailure, ReasonProtocol,
		ErrorNone, AlgorithmUnknown, CacheNotUsed, BucketMedium,
		BucketNone, BucketNone, BucketNone, BucketNone,
	)
	if !ok {
		t.Fatal("test event invalid")
	}
	Observe(context.Background(), panicSink{}, event)
}
