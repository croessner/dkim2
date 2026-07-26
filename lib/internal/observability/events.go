package observability

import (
	"context"
	"fmt"
	"io"
)

const eventRedactedText = "dkim2_observation_event"

// Kind identifies one library-owned observation point.
type Kind uint8

const (
	// KindVerifyCompleted records a completed verification operation.
	KindVerifyCompleted Kind = iota + 1
	// KindDNSLookupCompleted records a completed DNS public-key lookup.
	KindDNSLookupCompleted
)

// Operation identifies the closed operation family.
type Operation uint8

const (
	// OperationVerify identifies DKIM2 verification.
	OperationVerify Operation = iota + 1
	// OperationDNSLookup identifies DNS public-key lookup.
	OperationDNSLookup
)

// Result identifies a bounded operational result class.
type Result uint8

const (
	// ResultSuccess identifies a successful completed operation.
	ResultSuccess Result = iota + 1
	// ResultFailure identifies a completed protocol or provider failure.
	ResultFailure
	// ResultTemporary identifies a bounded temporary failure.
	ResultTemporary
	// ResultInternal identifies a contained internal failure.
	ResultInternal
)

// Reason identifies a bounded non-error outcome reason.
type Reason uint8

const (
	// ReasonNone indicates that no reason class applies.
	ReasonNone Reason = iota + 1
	// ReasonProtocol identifies a protocol-defined negative outcome.
	ReasonProtocol
	// ReasonPolicy identifies a local policy outcome.
	ReasonPolicy
	// ReasonUnavailable identifies required unavailable state.
	ReasonUnavailable
)

// ErrorClass identifies a bounded failure class without carrying an error.
type ErrorClass uint8

const (
	// ErrorNone indicates that no error class applies.
	ErrorNone ErrorClass = iota + 1
	// ErrorCanceled identifies caller cancellation.
	ErrorCanceled
	// ErrorDeadline identifies deadline exhaustion.
	ErrorDeadline
	// ErrorTemporary identifies a classified temporary dependency failure.
	ErrorTemporary
	// ErrorPermanent identifies a classified permanent dependency failure.
	ErrorPermanent
	// ErrorInternal identifies a contained invariant failure.
	ErrorInternal
)

// Algorithm identifies a closed signature algorithm family.
type Algorithm uint8

const (
	// AlgorithmNone indicates that no algorithm fact applies.
	AlgorithmNone Algorithm = iota + 1
	// AlgorithmRSA identifies RSA-SHA256.
	AlgorithmRSA
	// AlgorithmEd25519 identifies Ed25519-SHA256.
	AlgorithmEd25519
	// AlgorithmUnknown identifies a bounded unsupported family.
	AlgorithmUnknown
)

// CacheResult identifies one bounded cache outcome.
type CacheResult uint8

const (
	// CacheNotUsed indicates that no cache fact applies.
	CacheNotUsed CacheResult = iota + 1
	// CacheHit identifies a cache hit.
	CacheHit
	// CacheMiss identifies a cache miss.
	CacheMiss
)

// Bucket identifies a bounded duration, size, or count bucket.
type Bucket uint8

const (
	// BucketNone indicates that the optional bucket is disabled or unavailable.
	BucketNone Bucket = iota + 1
	// BucketSmall identifies the smallest bounded class.
	BucketSmall
	// BucketMedium identifies the middle bounded class.
	BucketMedium
	// BucketLarge identifies the largest bounded class.
	BucketLarge
	// BucketOverflow identifies values above the largest regular class.
	BucketOverflow
)

// Event is one immutable validated library observation.
type Event struct {
	kind       Kind
	operation  Operation
	result     Result
	reason     Reason
	errorClass ErrorClass
	algorithm  Algorithm
	cache      CacheResult
	duration   Bucket
	message    Bucket
	recipients Bucket
	signatures Bucket
	chain      Bucket
}

// NewEvent constructs one exact event after validating every closed fact.
func NewEvent(kind Kind, operation Operation, result Result, reason Reason, errorClass ErrorClass, algorithm Algorithm, cache CacheResult, duration, message, recipients, signatures, chain Bucket) (Event, bool) {
	event := Event{
		kind: kind, operation: operation, result: result, reason: reason,
		errorClass: errorClass, algorithm: algorithm, cache: cache,
		duration: duration, message: message, recipients: recipients,
		signatures: signatures, chain: chain,
	}
	return event, event.Valid()
}

// Valid reports whether all event facts belong to the exact closed grammar.
func (e Event) Valid() bool {
	if !validKind(e.kind) || !validOperation(e.operation) || !validResult(e.result) ||
		!validReason(e.reason) || !validError(e.errorClass) ||
		!validAlgorithm(e.algorithm) || !validCache(e.cache) ||
		!validBucket(e.duration) || !validBucket(e.message) ||
		!validBucket(e.recipients) || !validBucket(e.signatures) ||
		!validBucket(e.chain) {
		return false
	}
	if !validOutcome(e.result, e.reason, e.errorClass) {
		return false
	}
	switch e.kind {
	case KindVerifyCompleted:
		return e.operation == OperationVerify && e.cache == CacheNotUsed
	case KindDNSLookupCompleted:
		return e.operation == OperationDNSLookup &&
			e.message == BucketNone && e.recipients == BucketNone &&
			e.signatures == BucketNone && e.chain == BucketNone
	default:
		return false
	}
}

// validOutcome rejects contradictory result, reason, and error combinations.
func validOutcome(result Result, reason Reason, errorClass ErrorClass) bool {
	switch result {
	case ResultSuccess:
		return reason == ReasonNone && errorClass == ErrorNone
	case ResultFailure:
		return (reason == ReasonProtocol || reason == ReasonPolicy) &&
			(errorClass == ErrorNone || errorClass == ErrorPermanent)
	case ResultTemporary:
		return reason == ReasonUnavailable &&
			(errorClass == ErrorCanceled || errorClass == ErrorDeadline ||
				errorClass == ErrorTemporary)
	case ResultInternal:
		return reason == ReasonUnavailable && errorClass == ErrorInternal
	default:
		return false
	}
}

// Kind returns the closed event kind.
func (e Event) Kind() Kind { return e.kind }

// Operation returns the closed operation family.
func (e Event) Operation() Operation { return e.operation }

// Result returns the closed result class.
func (e Event) Result() Result { return e.result }

// Reason returns the closed reason class.
func (e Event) Reason() Reason { return e.reason }

// ErrorClass returns the closed error class.
func (e Event) ErrorClass() ErrorClass { return e.errorClass }

// Algorithm returns the closed algorithm family.
func (e Event) Algorithm() Algorithm { return e.algorithm }

// CacheResult returns the bounded cache outcome.
func (e Event) CacheResult() CacheResult { return e.cache }

// DurationBucket returns the bounded duration class.
func (e Event) DurationBucket() Bucket { return e.duration }

// MessageSizeBucket returns the optional message-size class.
func (e Event) MessageSizeBucket() Bucket { return e.message }

// RecipientCountBucket returns the optional recipient-count class.
func (e Event) RecipientCountBucket() Bucket { return e.recipients }

// SignatureCountBucket returns the optional signature-count class.
func (e Event) SignatureCountBucket() Bucket { return e.signatures }

// ChainLengthBucket returns the optional chain-length class.
func (e Event) ChainLengthBucket() Bucket { return e.chain }

// String returns a constant representation without event facts.
func (Event) String() string { return eventRedactedText }

// GoString returns a constant representation without event facts.
func (Event) GoString() string { return eventRedactedText }

// Format prevents formatting from traversing event state.
func (Event) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, eventRedactedText)
}

// Sink receives immutable bounded observations.
type Sink interface {
	Observe(context.Context, Event)
}

// Observe contains sink panics and rejects invalid inputs.
func Observe(ctx context.Context, sink Sink, event Event) {
	if ctx == nil || sink == nil || !event.Valid() {
		return
	}
	defer func() { _ = recover() }()
	sink.Observe(ctx, event)
}

// NoopSink discards observations.
type NoopSink struct{}

// Observe discards one bounded event.
func (NoopSink) Observe(context.Context, Event) {}

// validKind validates one kind.
func validKind(value Kind) bool {
	return value >= KindVerifyCompleted && value <= KindDNSLookupCompleted
}

// validOperation validates one operation.
func validOperation(value Operation) bool {
	return value >= OperationVerify && value <= OperationDNSLookup
}

// validResult validates one result.
func validResult(value Result) bool { return value >= ResultSuccess && value <= ResultInternal }

// validReason validates one reason.
func validReason(value Reason) bool { return value >= ReasonNone && value <= ReasonUnavailable }

// validError validates one error class.
func validError(value ErrorClass) bool { return value >= ErrorNone && value <= ErrorInternal }

// validAlgorithm validates one algorithm.
func validAlgorithm(value Algorithm) bool { return value >= AlgorithmNone && value <= AlgorithmUnknown }

// validCache validates one cache outcome.
func validCache(value CacheResult) bool { return value >= CacheNotUsed && value <= CacheMiss }

// validBucket validates one bucket.
func validBucket(value Bucket) bool { return value >= BucketNone && value <= BucketOverflow }
