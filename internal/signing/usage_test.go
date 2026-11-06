package signing

import (
	"math"
	"testing"
)

// TestUsageCounterChargesTransactionally verifies exact and one-over accounting.
func TestUsageCounterChargesTransactionally(t *testing.T) {
	counter, err := NewUsageCounter(DefaultLimits())
	if err != nil {
		t.Fatalf("NewUsageCounter() code=%s", testErrorCode(err))
	}
	if err := counter.Charge(ResourcePublicKeyLookups, 256); err != nil {
		t.Fatalf("exact charge code=%s", testErrorCode(err))
	}
	before := counter.Usage()
	if got := before.Count(ResourcePublicKeyLookups); got != 256 {
		t.Fatalf("lookup count = %d, want 256", got)
	}
	if err := counter.Charge(ResourcePublicKeyLookups, 1); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over code=%s", testErrorCode(err))
	}
	if got := counter.Usage().Count(ResourcePublicKeyLookups); got != 256 {
		t.Fatalf("failed charge mutated count to %d", got)
	}
	if err := counter.Charge(ResourceCanonicalWorkBytes, math.MaxInt); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("overflowing charge code=%s", testErrorCode(err))
	}
	if _, ok := checkedAdd(math.MaxInt, 1); ok {
		t.Fatal("checkedAdd accepted integer overflow")
	}
}

// TestUsageCounterRejectsUnknownAndNegativeCharges verifies fail-closed counter inputs.
func TestUsageCounterRejectsUnknownAndNegativeCharges(t *testing.T) {
	counter, err := NewUsageCounter(Limits{})
	if err != nil {
		t.Fatalf("NewUsageCounter() code=%s", testErrorCode(err))
	}
	if err := counter.Charge(Resource("secret-marker-resource"), 1); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("unknown resource code=%s", testErrorCode(err))
	}
	if err := counter.Charge(ResourceGeneratedRecipients, -1); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("negative charge code=%s", testErrorCode(err))
	}
	if counter.Usage().Count(ResourceGeneratedRecipients) != 0 {
		t.Fatal("rejected charge mutated usage")
	}
}

// TestUsageCounterFinalizationRequiresExactlyOneNewSignature locks the completion invariant.
func TestUsageCounterFinalizationRequiresExactlyOneNewSignature(t *testing.T) {
	counter, err := NewUsageCounter(Limits{})
	if err != nil {
		t.Fatalf("NewUsageCounter() code=%s", testErrorCode(err))
	}
	if err := counter.Finalize(); !IsErrorCode(err, ErrorCodeInternalInvariant) {
		t.Fatalf("zero-signature finalization code=%s", testErrorCode(err))
	}
	if err := counter.Charge(ResourceNewSignatures, 1); err != nil {
		t.Fatalf("exact signature charge code=%s", testErrorCode(err))
	}
	if err := counter.Finalize(); err != nil {
		t.Fatalf("exact-signature finalization code=%s", testErrorCode(err))
	}
	if err := counter.Charge(ResourceNewSignatures, 1); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("second-signature charge code=%s", testErrorCode(err))
	}
}

// TestUsageCounterHasNoPerInstanceHashAccounting keeps object-local limits with instance.
func TestUsageCounterHasNoPerInstanceHashAccounting(t *testing.T) {
	counter, err := NewUsageCounter(Limits{})
	if err != nil {
		t.Fatalf("NewUsageCounter() code=%s", testErrorCode(err))
	}
	if err := counter.Charge(Resource("hash_sets"), 1); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("operation counter accepted per-instance hash resource")
	}
}
