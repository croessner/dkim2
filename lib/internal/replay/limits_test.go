package replay

import (
	"math"
	"reflect"
	"testing"
)

// TestReplayDefaultAndHardLimitsMatchFrozenValues verifies every reusable resource bound.
func TestReplayDefaultAndHardLimitsMatchFrozenValues(t *testing.T) {
	defaults := Limits{
		MaxEntries:          65_536,
		MaxWaiters:          1_024,
		PruneBudget:         4_096,
		MaxInFlight:         1_024,
		MaxAdmissionWaiters: 1_024,
	}
	hard := Limits{
		MaxEntries:          1_048_576,
		MaxWaiters:          65_536,
		PruneBudget:         65_536,
		MaxInFlight:         65_536,
		MaxAdmissionWaiters: 65_536,
	}
	if got := DefaultLimits(); got != defaults {
		t.Fatalf("DefaultLimits() = %+v", got)
	}
	if got := HardLimits(); got != hard {
		t.Fatalf("HardLimits() = %+v", got)
	}
	if err := defaults.Validate(); err != nil {
		t.Fatalf("default limits rejected: %v", err)
	}
	if err := hard.Validate(); err != nil {
		t.Fatalf("hard limits rejected: %v", err)
	}
}

// TestResolveLimitsDefaultsZeroAndAllowsExactNarrowing verifies config normalization.
func TestResolveLimitsDefaultsZeroAndAllowsExactNarrowing(t *testing.T) {
	if got, err := ResolveLimits(Limits{}); err != nil || got != DefaultLimits() {
		t.Fatalf("ResolveLimits(zero) = %+v, %v", got, err)
	}
	narrow := Limits{
		MaxEntries:          1,
		MaxWaiters:          2,
		PruneBudget:         3,
		MaxInFlight:         4,
		MaxAdmissionWaiters: 5,
	}
	if got, err := ResolveLimits(narrow); err != nil || got != narrow {
		t.Fatalf("ResolveLimits(narrow) = %+v, %v", got, err)
	}
	mixed := Limits{MaxEntries: 7}
	want := DefaultLimits()
	want.MaxEntries = 7
	if got, err := ResolveLimits(mixed); err != nil || got != want {
		t.Fatalf("ResolveLimits(mixed) = %+v, %v", got, err)
	}
}

// TestReplayLimitsRejectEveryNegativeAndHardMaximumPlusOne verifies fail-closed bounds.
func TestReplayLimitsRejectEveryNegativeAndHardMaximumPlusOne(t *testing.T) {
	type fieldCase struct {
		name string
		set  func(*Limits, int)
		hard int
	}
	hard := HardLimits()
	fields := []fieldCase{
		{"entries", func(l *Limits, value int) { l.MaxEntries = value }, hard.MaxEntries},
		{"waiters", func(l *Limits, value int) { l.MaxWaiters = value }, hard.MaxWaiters},
		{"prune", func(l *Limits, value int) { l.PruneBudget = value }, hard.PruneBudget},
		{"in-flight", func(l *Limits, value int) { l.MaxInFlight = value }, hard.MaxInFlight},
		{"admission waiters", func(l *Limits, value int) { l.MaxAdmissionWaiters = value }, hard.MaxAdmissionWaiters},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []int{-1, field.hard + 1, math.MaxInt} {
				candidate := DefaultLimits()
				field.set(&candidate, value)
				if got, err := ResolveLimits(candidate); got != (Limits{}) || ErrorCodeOf(err) != ErrorCodeMisconfigured {
					t.Fatalf("ResolveLimits(%d) = %+v, %v", value, got, err)
				}
			}

			invalidDomain := DefaultLimits()
			field.set(&invalidDomain, 0)
			if code := ErrorCodeOf(invalidDomain.Validate()); code != ErrorCodeMisconfigured {
				t.Fatalf("Limits.Validate(zero) code = %q", code)
			}
		})
	}
}

// TestReplayLimitsFieldsRemainExactAndMachineSized verifies the reusable value has no hidden policy.
func TestReplayLimitsFieldsRemainExactAndMachineSized(t *testing.T) {
	valueType := reflect.TypeOf(Limits{})
	want := []string{"MaxEntries", "MaxWaiters", "PruneBudget", "MaxInFlight", "MaxAdmissionWaiters"}
	if valueType.NumField() != len(want) {
		t.Fatalf("Limits fields = %d", valueType.NumField())
	}
	for index, name := range want {
		field := valueType.Field(index)
		if field.Name != name || field.Type.Kind() != reflect.Int {
			t.Fatalf("Limits field %d = %s %s", index, field.Name, field.Type)
		}
	}
}
