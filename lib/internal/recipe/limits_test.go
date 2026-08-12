package recipe

import (
	"math"
	"reflect"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestEveryRecipeHardMaximumAcceptsExactAndRejectsOneOver locks every configurable ceiling.
func TestEveryRecipeHardMaximumAcceptsExactAndRejectsOneOver(t *testing.T) {
	exact := DefaultLimits()
	if err := exact.Validate(); err != nil {
		t.Fatalf("exact hard maxima rejected: %v", err)
	}
	typeOfLimits := reflect.TypeFor[Limits]()
	for index := 0; index < typeOfLimits.NumField(); index++ {
		field := typeOfLimits.Field(index)
		t.Run(field.Name, func(t *testing.T) {
			over := DefaultLimits()
			value := reflect.ValueOf(&over).Elem().Field(index)
			value.SetInt(value.Int() + 1)
			if err := over.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
				t.Fatalf("one-over hard maximum accepted: %v", err)
			}
		})
	}
}

// TestDefaultLimitsMatchDurableContract locks every per-operation hard ceiling.
func TestDefaultLimitsMatchDurableContract(t *testing.T) {
	got := DefaultLimits()
	want := Limits{
		MaxDecodedRecipeBytes: 49_152, MaxJSONDepth: 16, MaxJSONMembers: 2_048,
		MaxJSONTokens: 8_192, MaxHeaderNames: 256, MaxHeaderNameBytes: 998,
		MaxTotalHeaderNameBytes: 16_384, MaxStepsPerHeader: 256, MaxBodySteps: 2_048,
		MaxTotalSteps: 4_096, MaxCopyRanges: 2_048, MaxCopiedItemsPerRange: 2_000,
		MaxTotalCopiedItems: 8_192, MaxDataStrings: 4_096, MaxDataStringBytes: 16_384,
		MaxTotalLiteralBytes: 32_768, MaxHeaderFields: 2_000, MaxHeaderFieldBytes: 65_536,
		MaxHeaderLineBytes: 998, MaxHeaderBytes: 1 << 20, MaxBodyLines: 65_536,
		MaxBodyLineBytes: 998, MaxStateBytes: 32 << 20, MaxOperationWorkUnits: 4_194_304,
	}
	if got != want {
		t.Fatalf("DefaultLimits() = %#v, want %#v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("DefaultLimits().Validate() error = %v", err)
	}
	if normalized, err := (Limits{}).normalized(); err != nil || normalized != want {
		t.Fatalf("zero normalized = %#v, %v, want %#v", normalized, err, want)
	}
}

// TestRecipeRawMessageLimitsStayAligned verifies rawmsg remains the authoritative ceiling owner.
func TestRecipeRawMessageLimitsStayAligned(t *testing.T) {
	recipeLimits := DefaultLimits()
	rawLimits := rawmsg.DefaultParserOptions()
	if recipeLimits.MaxHeaderNameBytes != rawLimits.MaxHeaderLineBytes ||
		recipeLimits.MaxHeaderFields != rawLimits.MaxHeaderFields ||
		recipeLimits.MaxHeaderFieldBytes != rawLimits.MaxHeaderFieldBytes ||
		recipeLimits.MaxHeaderLineBytes != rawLimits.MaxHeaderLineBytes ||
		recipeLimits.MaxHeaderBytes != rawLimits.MaxHeaderBytes ||
		recipeLimits.MaxBodyLines != rawLimits.MaxBodyLines ||
		recipeLimits.MaxBodyLineBytes != rawLimits.MaxBodyLineBytes ||
		recipeLimits.MaxStateBytes != rawLimits.MaxMessageBytes {
		t.Fatalf("recipe/rawmsg ceilings drifted: %#v / %#v", recipeLimits, rawLimits)
	}
}

// TestApplierPropagatesNarrowRawMessageLimits verifies reconstruction cannot widen recipe policy.
func TestApplierPropagatesNarrowRawMessageLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxBodyLines = 7

	applier, err := NewApplier(limits)
	if err != nil {
		t.Fatalf("NewApplier() error = %v", err)
	}
	if applier.rawOptions.MaxBodyLines != limits.MaxBodyLines {
		t.Fatalf("raw MaxBodyLines = %d, want %d", applier.rawOptions.MaxBodyLines, limits.MaxBodyLines)
	}
}

// TestLimitsRejectInvalidAndIncoherentValues verifies narrowing cannot widen or split related budgets.
func TestLimitsRejectInvalidAndIncoherentValues(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Limits)
	}{
		{"negative", func(l *Limits) { l.MaxJSONDepth = -1 }},
		{"wider", func(l *Limits) { l.MaxHeaderFields++ }},
		{"literal wider than total", func(l *Limits) { l.MaxTotalLiteralBytes = 8; l.MaxDataStringBytes = 9 }},
		{"total literals wider than recipe", func(l *Limits) { l.MaxDecodedRecipeBytes = 16; l.MaxTotalLiteralBytes = 17; l.MaxDataStringBytes = 8 }},
		{"header steps wider than total", func(l *Limits) { l.MaxTotalSteps = 4; l.MaxStepsPerHeader = 5 }},
		{"range wider than total copies", func(l *Limits) { l.MaxTotalCopiedItems = 4; l.MaxCopiedItemsPerRange = 5 }},
		{"field wider than rawmsg", func(l *Limits) { l.MaxHeaderFieldBytes++ }},
		{"line wider than rawmsg", func(l *Limits) { l.MaxBodyLineBytes++ }},
		{"state wider than rawmsg", func(l *Limits) { l.MaxStateBytes++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			test.mut(&limits)
			if err := limits.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
				t.Fatalf("Validate() error = %v, want invalid_options", err)
			}
		})
	}
}

// TestUsageCounterCheckedArithmetic verifies exact budgets pass and one-over or overflow fails closed.
func TestUsageCounterCheckedArithmetic(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxDecodedRecipeBytes = 4
	limits.MaxTotalLiteralBytes = 4
	limits.MaxDataStringBytes = 4
	limits.MaxOperationWorkUnits = 8
	counter, err := newUsageCounter(limits)
	if err != nil {
		t.Fatalf("newUsageCounter() error = %v", err)
	}
	if err := counter.chargeDecoded(4); err != nil {
		t.Fatalf("chargeDecoded exact error = %v", err)
	}
	if usage := counter.usage(); !usage.Valid() || usage.DecodedBytes() != 4 || usage.WorkUnits() != 4 {
		t.Fatalf("usage = %#v", usage)
	}
	if err := counter.chargeItems(4); err != nil {
		t.Fatalf("chargeItems exact error = %v", err)
	}
	if err := counter.chargeItems(1); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("chargeItems over error = %v", err)
	}
	if usage := counter.usage(); usage.Items() != 4 || usage.WorkUnits() != 8 {
		t.Fatalf("rejected charge mutated usage: %#v", usage)
	}

	overflow, err := newUsageCounter(DefaultLimits())
	if err != nil {
		t.Fatalf("newUsageCounter() overflow setup error = %v", err)
	}
	overflow.items = math.MaxInt
	if err := overflow.chargeItems(1); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("overflow error = %v", err)
	}
}

// TestUsageContractCoversAllCountersAndTransactionalFailures verifies initialized zero and failure accounting.
func TestUsageContractCoversAllCountersAndTransactionalFailures(t *testing.T) {
	if (Usage{}).Valid() {
		t.Fatal("zero Usage unexpectedly valid")
	}
	zero := newUsage(0, 0, 0, 0)
	if !zero.Valid() || zero.DecodedBytes() != 0 || zero.EmittedBytes() != 0 || zero.Items() != 0 || zero.WorkUnits() != 0 {
		t.Fatalf("initialized zero usage = %#v", zero)
	}
	limits := DefaultLimits()
	limits.MaxDecodedRecipeBytes = 2
	limits.MaxTotalLiteralBytes = 2
	limits.MaxDataStringBytes = 2
	limits.MaxStateBytes = 3
	limits.MaxOperationWorkUnits = 6
	counter, err := newUsageCounter(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := counter.chargeDecoded(2); err != nil {
		t.Fatal(err)
	}
	if err := counter.chargeEmitted(3); err != nil {
		t.Fatal(err)
	}
	if err := counter.chargeWork(1); err != nil {
		t.Fatal(err)
	}
	before := counter.usage()
	for _, charge := range []func() error{
		func() error { return counter.chargeDecoded(1) }, func() error { return counter.chargeEmitted(1) },
		func() error { return counter.chargeItems(1) }, func() error { return counter.chargeWork(1) },
	} {
		if err := charge(); !IsErrorCode(err, ErrorCodeLimitExceeded) {
			t.Fatalf("charge error = %v", err)
		}
		if got := counter.usage(); got != before {
			t.Fatalf("failed charge mutated %#v to %#v", before, got)
		}
	}
	if err := (*usageCounter)(nil).chargeItems(1); !IsErrorCode(err, ErrorCodeInvalidState) {
		t.Fatalf("nil charge error = %v", err)
	}
	if err := counter.chargeItems(-1); !IsErrorCode(err, ErrorCodeInvalidState) {
		t.Fatalf("negative charge error = %v", err)
	}
	if got, ok := checkedAdd(math.MaxInt, 1); ok || got != math.MaxInt {
		t.Fatalf("checkedAdd overflow = %d,%t", got, ok)
	}
}
