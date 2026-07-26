package observability

import "testing"

// FuzzObservationEventValidation proves arbitrary enum projections stay closed.
func FuzzObservationEventValidation(f *testing.F) {
	f.Add(byte(KindVerifyCompleted), byte(OperationVerify), byte(ResultSuccess), byte(ReasonNone))
	f.Fuzz(func(f *testing.T, kind, operation, result, reason byte) {
		event, ok := NewEvent(
			Kind(kind), Operation(operation), Result(result), Reason(reason),
			ErrorNone, AlgorithmNone, CacheNotUsed,
			BucketSmall, BucketNone, BucketNone, BucketNone, BucketNone,
		)
		if ok && !event.Valid() {
			f.Fatal("constructor admitted an invalid event")
		}
	})
}
