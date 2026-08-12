package datasource

import (
	"math"
	"reflect"
	"testing"
)

// TestLimitProfilesMatchFrozenMaxima verifies every declared datasource ceiling.
func TestLimitProfilesMatchFrozenMaxima(t *testing.T) {
	wantDefault := Limits{
		MaxIdentifierBytes: 128, MaxDomainBytes: 253, MaxDomainLabels: 127,
		MaxSelectorBytes: 253, MaxSelectorLabels: 127, MaxProfiles: 1024,
		MaxCredentialsPerProfile: 2, MaxHandles: 2048, MaxPolicies: 4096,
		MaxJSONFileBytes: 1_048_576, MaxJSONDepth: 16, MaxJSONStringBytes: 16_384,
		MaxDecodedStringBytes: 1_048_576, MaxDecodedPublicKeyBytes: 2_048,
		MaxRecords: 9_216,
	}
	wantProduction := wantDefault
	wantProduction.MaxProfiles, wantProduction.MaxHandles, wantProduction.MaxPolicies = 32768, 65536, 65536
	wantProduction.MaxJSONFileBytes, wantProduction.MaxDecodedStringBytes, wantProduction.MaxRecords = 128<<20, 128<<20, 229376
	wantHard := wantDefault
	wantHard.MaxProfiles, wantHard.MaxHandles, wantHard.MaxPolicies = 131072, 262144, 262144
	wantHard.MaxJSONFileBytes, wantHard.MaxDecodedStringBytes, wantHard.MaxRecords = 512<<20, 512<<20, 1<<20
	if hard, defaults, production := HardLimits(), DefaultLimits(), ProductionLimits(); hard != wantHard || defaults != wantDefault || production != wantProduction {
		t.Fatalf("limit profile drift")
	}
	if err := wantHard.Validate(); err != nil {
		t.Fatalf("hard limits rejected: %v", err)
	}
}

// TestLimitsAllowNarrowingAndRejectZeroNegativeOrWidenedValues verifies every field independently.
func TestLimitsAllowNarrowingAndRejectZeroNegativeOrWidenedValues(t *testing.T) {
	type fieldCase struct {
		name   string
		mutate func(*Limits, int)
		hard   int
	}
	hard := HardLimits()
	fields := []fieldCase{
		{name: "identifier bytes", mutate: func(l *Limits, v int) { l.MaxIdentifierBytes = v }, hard: hard.MaxIdentifierBytes},
		{name: "domain bytes", mutate: func(l *Limits, v int) { l.MaxDomainBytes = v }, hard: hard.MaxDomainBytes},
		{name: "domain labels", mutate: func(l *Limits, v int) { l.MaxDomainLabels = v }, hard: hard.MaxDomainLabels},
		{name: "selector bytes", mutate: func(l *Limits, v int) { l.MaxSelectorBytes = v }, hard: hard.MaxSelectorBytes},
		{name: "selector labels", mutate: func(l *Limits, v int) { l.MaxSelectorLabels = v }, hard: hard.MaxSelectorLabels},
		{name: "profiles", mutate: func(l *Limits, v int) { l.MaxProfiles = v }, hard: hard.MaxProfiles},
		{name: "credentials", mutate: func(l *Limits, v int) { l.MaxCredentialsPerProfile = v }, hard: hard.MaxCredentialsPerProfile},
		{name: "handles", mutate: func(l *Limits, v int) { l.MaxHandles = v }, hard: hard.MaxHandles},
		{name: "policies", mutate: func(l *Limits, v int) { l.MaxPolicies = v }, hard: hard.MaxPolicies},
		{name: "file bytes", mutate: func(l *Limits, v int) { l.MaxJSONFileBytes = v }, hard: hard.MaxJSONFileBytes},
		{name: "JSON depth", mutate: func(l *Limits, v int) { l.MaxJSONDepth = v }, hard: hard.MaxJSONDepth},
		{name: "string bytes", mutate: func(l *Limits, v int) { l.MaxJSONStringBytes = v }, hard: hard.MaxJSONStringBytes},
		{name: "decoded strings", mutate: func(l *Limits, v int) { l.MaxDecodedStringBytes = v }, hard: hard.MaxDecodedStringBytes},
		{name: "public key bytes", mutate: func(l *Limits, v int) { l.MaxDecodedPublicKeyBytes = v }, hard: hard.MaxDecodedPublicKeyBytes},
		{name: "records", mutate: func(l *Limits, v int) { l.MaxRecords = v }, hard: hard.MaxRecords},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			narrowed := hard
			field.mutate(&narrowed, field.hard-1)
			if err := narrowed.Validate(); err != nil {
				t.Fatalf("narrowed limit rejected: %v", err)
			}
			for _, invalid := range []int{0, -1, field.hard + 1, math.MaxInt} {
				candidate := hard
				field.mutate(&candidate, invalid)
				if err := candidate.Validate(); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
					t.Fatalf("value %d error = %v", invalid, err)
				}
			}
		})
	}
}

// TestUsageConstructionDerivesExactRecordCountAndKeepsFieldsPrivate verifies immutable checked accounting.
func TestUsageConstructionDerivesExactRecordCountAndKeepsFieldsPrivate(t *testing.T) {
	usageType := reflect.TypeFor[Usage]()
	for field := range usageType.Fields() {
		if field.IsExported() {
			t.Fatalf("Usage field %q is exported", field.Name)
		}
	}
	limits := HardLimits()
	usage, err := NewUsage(
		limits.MaxProfiles,
		limits.MaxProfiles*limits.MaxCredentialsPerProfile,
		limits.MaxHandles,
		limits.MaxPolicies,
		limits.MaxDecodedStringBytes,
		limits,
	)
	if err != nil {
		t.Fatalf("NewUsage(exact maxima) error = %v", err)
	}
	if usage.Profiles() != limits.MaxProfiles || usage.Credentials() != limits.MaxProfiles*limits.MaxCredentialsPerProfile ||
		usage.Handles() != limits.MaxHandles || usage.Policies() != limits.MaxPolicies ||
		usage.Records() != 917504 || usage.Bytes() != limits.MaxDecodedStringBytes {
		t.Fatalf("usage maxima = profiles=%d credentials=%d handles=%d policies=%d records=%d bytes=%d",
			usage.Profiles(), usage.Credentials(), usage.Handles(), usage.Policies(), usage.Records(), usage.Bytes())
	}
}

// TestUsageRejectsOneOverNegativeOverflowAndInconsistentValues verifies every accounting failure is closed.
func TestUsageRejectsOneOverNegativeOverflowAndInconsistentValues(t *testing.T) {
	limits := HardLimits()
	tests := []struct {
		name                                     string
		profiles, credentials, handles, policies int
		bytes                                    int
		code                                     ErrorCode
	}{
		{name: "profiles one over", profiles: limits.MaxProfiles + 1, code: ErrorCodeLimitExceeded},
		{name: "credentials one over", credentials: limits.MaxProfiles*limits.MaxCredentialsPerProfile + 1, code: ErrorCodeLimitExceeded},
		{name: "handles one over", handles: limits.MaxHandles + 1, code: ErrorCodeLimitExceeded},
		{name: "policies one over", policies: limits.MaxPolicies + 1, code: ErrorCodeLimitExceeded},
		{name: "bytes one over", bytes: limits.MaxDecodedStringBytes + 1, code: ErrorCodeLimitExceeded},
		{name: "negative profiles", profiles: -1, code: ErrorCodeInvalidRequest},
		{name: "negative credentials", credentials: -1, code: ErrorCodeInvalidRequest},
		{name: "negative handles", handles: -1, code: ErrorCodeInvalidRequest},
		{name: "negative policies", policies: -1, code: ErrorCodeInvalidRequest},
		{name: "negative bytes", bytes: -1, code: ErrorCodeInvalidRequest},
		{name: "integer overflow", profiles: math.MaxInt, credentials: math.MaxInt, handles: math.MaxInt, policies: math.MaxInt, bytes: math.MaxInt, code: ErrorCodeLimitExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			usage, err := NewUsage(test.profiles, test.credentials, test.handles, test.policies, test.bytes, limits)
			if usage != (Usage{}) || ErrorCodeOf(err) != test.code {
				t.Fatalf("NewUsage() = %+v, %v", usage, err)
			}
		})
	}

	left, err := NewUsage(limits.MaxProfiles-1, 0, 0, 0, 0, limits)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewUsage(2, 0, 0, 0, 0, limits)
	if err != nil {
		t.Fatal(err)
	}
	if sum, addErr := left.Add(right, limits); sum != (Usage{}) || ErrorCodeOf(addErr) != ErrorCodeLimitExceeded {
		t.Fatalf("Usage.Add(one over) = %+v, %v", sum, addErr)
	}
	inconsistent := Usage{profiles: 1, records: 0}
	if sum, addErr := inconsistent.Add(Usage{}, limits); sum != (Usage{}) || ErrorCodeOf(addErr) != ErrorCodeInvalidRequest {
		t.Fatalf("Usage.Add(inconsistent) = %+v, %v", sum, addErr)
	}
}

// TestUsageAddPreservesCheckedComponentAndDerivedTotals verifies valid accumulation exactly.
func TestUsageAddPreservesCheckedComponentAndDerivedTotals(t *testing.T) {
	limits := HardLimits()
	left, err := NewUsage(1, 2, 3, 4, 5, limits)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewUsage(10, 20, 30, 40, 50, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, err := left.Add(right, limits)
	if err != nil {
		t.Fatal(err)
	}
	if got.Profiles() != 11 || got.Credentials() != 22 || got.Handles() != 33 ||
		got.Policies() != 44 || got.Records() != 110 || got.Bytes() != 55 {
		t.Fatalf("Usage.Add() = %+v", got)
	}
}

// TestUsageEnforcesNarrowedRecordTotalsIndependently verifies the derived work ceiling at exact and one-over values.
func TestUsageEnforcesNarrowedRecordTotalsIndependently(t *testing.T) {
	limits := HardLimits()
	limits.MaxRecords = 4
	exact, err := NewUsage(1, 1, 1, 1, 0, limits)
	if err != nil || exact.Records() != 4 {
		t.Fatalf("NewUsage(exact records) records=%d error=%v", exact.Records(), err)
	}
	oneOver, err := NewUsage(2, 1, 1, 1, 0, limits)
	if oneOver != (Usage{}) || ErrorCodeOf(err) != ErrorCodeLimitExceeded {
		t.Fatalf("NewUsage(records one over) = %+v, %v", oneOver, err)
	}
}
