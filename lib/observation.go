package dkim2

import (
	"context"

	internalobs "github.com/croessner/dkim2/internal/observability"
)

// ObservationEvent is the immutable closed library observation value.
type ObservationEvent = internalobs.Event

// ObservationKind identifies one library-owned observation point.
type ObservationKind = internalobs.Kind

// ObservationOperation identifies one bounded operation.
type ObservationOperation = internalobs.Operation

// ObservationResult identifies one bounded result.
type ObservationResult = internalobs.Result

// ObservationReason identifies one bounded reason.
type ObservationReason = internalobs.Reason

// ObservationErrorClass identifies one bounded error class.
type ObservationErrorClass = internalobs.ErrorClass

// ObservationAlgorithm identifies one bounded algorithm family.
type ObservationAlgorithm = internalobs.Algorithm

// ObservationCacheResult identifies one bounded cache result.
type ObservationCacheResult = internalobs.CacheResult

// ObservationBucket identifies one bounded duration, size, or count class.
type ObservationBucket = internalobs.Bucket

const (
	// ObservationVerifyCompleted identifies a completed verification observation.
	ObservationVerifyCompleted = internalobs.KindVerifyCompleted
	// ObservationDNSLookupCompleted identifies a completed DNS lookup observation.
	ObservationDNSLookupCompleted = internalobs.KindDNSLookupCompleted
	// ObservationOperationVerify identifies signature verification work.
	ObservationOperationVerify = internalobs.OperationVerify
	// ObservationOperationDNSLookup identifies DNS key lookup work.
	ObservationOperationDNSLookup = internalobs.OperationDNSLookup
	// ObservationResultSuccess identifies successful work.
	ObservationResultSuccess = internalobs.ResultSuccess
	// ObservationResultFailure identifies a closed expected failure.
	ObservationResultFailure = internalobs.ResultFailure
	// ObservationResultTemporary identifies temporary failure.
	ObservationResultTemporary = internalobs.ResultTemporary
	// ObservationResultInternal identifies contained internal failure.
	ObservationResultInternal = internalobs.ResultInternal
	// ObservationReasonNone identifies an outcome without a failure reason.
	ObservationReasonNone = internalobs.ReasonNone
	// ObservationReasonProtocol identifies protocol-driven failure.
	ObservationReasonProtocol = internalobs.ReasonProtocol
	// ObservationReasonPolicy identifies local-policy failure.
	ObservationReasonPolicy = internalobs.ReasonPolicy
	// ObservationReasonUnavailable identifies unavailable infrastructure.
	ObservationReasonUnavailable = internalobs.ReasonUnavailable
	// ObservationErrorNone identifies an outcome without an error.
	ObservationErrorNone = internalobs.ErrorNone
	// ObservationErrorCanceled identifies caller cancellation.
	ObservationErrorCanceled = internalobs.ErrorCanceled
	// ObservationErrorDeadline identifies deadline expiry.
	ObservationErrorDeadline = internalobs.ErrorDeadline
	// ObservationErrorTemporary identifies retryable failure.
	ObservationErrorTemporary = internalobs.ErrorTemporary
	// ObservationErrorPermanent identifies non-retryable failure.
	ObservationErrorPermanent = internalobs.ErrorPermanent
	// ObservationErrorInternal identifies contained internal failure.
	ObservationErrorInternal = internalobs.ErrorInternal
	// ObservationAlgorithmNone identifies absence of an algorithm.
	ObservationAlgorithmNone = internalobs.AlgorithmNone
	// ObservationAlgorithmRSA identifies the RSA family.
	ObservationAlgorithmRSA = internalobs.AlgorithmRSA
	// ObservationAlgorithmEd25519 identifies the Ed25519 family.
	ObservationAlgorithmEd25519 = internalobs.AlgorithmEd25519
	// ObservationAlgorithmUnknown identifies a bounded unknown family.
	ObservationAlgorithmUnknown = internalobs.AlgorithmUnknown
	// ObservationCacheNotUsed identifies a lookup without caching.
	ObservationCacheNotUsed = internalobs.CacheNotUsed
	// ObservationCacheHit identifies a cache hit.
	ObservationCacheHit = internalobs.CacheHit
	// ObservationCacheMiss identifies a cache miss.
	ObservationCacheMiss = internalobs.CacheMiss
	// ObservationBucketNone identifies an empty or absent quantity.
	ObservationBucketNone = internalobs.BucketNone
	// ObservationBucketSmall identifies a bounded small quantity.
	ObservationBucketSmall = internalobs.BucketSmall
	// ObservationBucketMedium identifies a bounded medium quantity.
	ObservationBucketMedium = internalobs.BucketMedium
	// ObservationBucketLarge identifies a bounded large quantity.
	ObservationBucketLarge = internalobs.BucketLarge
	// ObservationBucketOverflow identifies a quantity above the largest bound.
	ObservationBucketOverflow = internalobs.BucketOverflow
)

// ObservationSink receives immutable bounded observations.
type ObservationSink interface {
	Observe(context.Context, ObservationEvent)
}

// NewObservationEvent validates and constructs one closed library event.
func NewObservationEvent(kind ObservationKind, operation ObservationOperation, result ObservationResult, reason ObservationReason, errorClass ObservationErrorClass, algorithm ObservationAlgorithm, cache ObservationCacheResult, duration, message, recipients, signatures, chain ObservationBucket) (ObservationEvent, bool) {
	return internalobs.NewEvent(kind, operation, result, reason, errorClass, algorithm, cache, duration, message, recipients, signatures, chain)
}

// Observe invokes one sink while containing invalid input and sink panics.
func Observe(ctx context.Context, sink ObservationSink, event ObservationEvent) {
	internalobs.Observe(ctx, sink, event)
}

// NoopObservationSink discards observations.
type NoopObservationSink struct{}

// Observe discards one bounded event.
func (NoopObservationSink) Observe(context.Context, ObservationEvent) {}
