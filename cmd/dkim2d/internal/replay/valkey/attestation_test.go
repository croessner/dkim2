package valkey

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
)

const syntheticSaveSchedule = "60 1000"

// TestOperatorAttestationAcceptsEveryExactPersistenceCombination freezes the closed modes.
func TestOperatorAttestationAcceptsEveryExactPersistenceCombination(t *testing.T) {
	tests := []struct {
		name       string
		mode       PersistenceMode
		fsync      AppendFsyncPolicy
		save       string
		rotation   RotationState
		minReplica uint8
		maxLag     uint16
	}{
		{name: "rdb unchanged", mode: PersistenceModeRDB, fsync: AppendFsyncInactive, save: syntheticSaveSchedule, rotation: RotationUnchanged, maxLag: 1},
		{name: "rdb drained", mode: PersistenceModeRDB, fsync: AppendFsyncInactive, save: "1 1 " + syntheticSaveSchedule, rotation: RotationDrainCompleted, minReplica: 3, maxLag: 3600},
		{name: "aof always", mode: PersistenceModeAOF, fsync: AppendFsyncAlways, rotation: RotationUnchanged, maxLag: 30},
		{name: "aof everysec", mode: PersistenceModeAOF, fsync: AppendFsyncEverySecond, rotation: RotationDrainCompleted, maxLag: 30},
		{name: "both always", mode: PersistenceModeRDBAOF, fsync: AppendFsyncAlways, save: syntheticSaveSchedule, rotation: RotationUnchanged, maxLag: 30},
		{name: "both everysec", mode: PersistenceModeRDBAOF, fsync: AppendFsyncEverySecond, save: syntheticSaveSchedule, rotation: RotationDrainCompleted, maxLag: 30},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validOperatorAttestationInput()
			input.values.PersistenceMode = test.mode
			input.values.AppendFsyncPolicy = test.fsync
			input.values.SaveSchedule = test.save
			input.values.RotationState = test.rotation
			input.values.MinReplicasToWrite = test.minReplica
			input.values.MinReplicasMaxLagSeconds = test.maxLag
			attestation, err := NewOperatorAttestation(input)
			if err != nil {
				t.Fatal("valid operator attestation was rejected")
			}
			if attestation.values.persistenceMode != test.mode ||
				attestation.values.appendFsyncPolicy != test.fsync ||
				attestation.values.saveSchedule != test.save ||
				attestation.values.rotationState != test.rotation ||
				attestation.values.minReplicasToWrite != test.minReplica ||
				attestation.values.minReplicasMaxLagSeconds != test.maxLag {
				t.Fatal("operator attestation did not retain exact closed policy")
			}
		})
	}
}

// TestOperatorAttestationRejectsEveryInvalidEnumCombinationAndAssertion proves fail-closed input.
func TestOperatorAttestationRejectsEveryInvalidEnumCombinationAndAssertion(t *testing.T) {
	inputType := reflect.TypeFor[OperatorAttestationInput]()
	if inputType.NumField() != 1 || inputType.Field(0).Name != "values" ||
		inputType.Field(0).Type.Kind() != reflect.Pointer {
		t.Fatal("operator attestation input is not structurally opaque")
	}
	tests := []struct {
		name   string
		mutate func(*OperatorAttestationInput)
	}{
		{name: "zero persistence", mutate: func(i *OperatorAttestationInput) { i.values.PersistenceMode = 0 }},
		{name: "unknown persistence", mutate: func(i *OperatorAttestationInput) { i.values.PersistenceMode = 255 }},
		{name: "zero fsync", mutate: func(i *OperatorAttestationInput) { i.values.AppendFsyncPolicy = 0 }},
		{name: "unknown fsync", mutate: func(i *OperatorAttestationInput) { i.values.AppendFsyncPolicy = 255 }},
		{name: "rdb active fsync", mutate: func(i *OperatorAttestationInput) { i.values.AppendFsyncPolicy = AppendFsyncAlways }},
		{name: "aof inactive fsync", mutate: func(i *OperatorAttestationInput) {
			i.values.PersistenceMode = PersistenceModeAOF
			i.values.AppendFsyncPolicy = AppendFsyncInactive
			i.values.SaveSchedule = ""
		}},
		{name: "both inactive fsync", mutate: func(i *OperatorAttestationInput) {
			i.values.PersistenceMode = PersistenceModeRDBAOF
			i.values.AppendFsyncPolicy = AppendFsyncInactive
		}},
		{name: "rdb empty save", mutate: func(i *OperatorAttestationInput) { i.values.SaveSchedule = "" }},
		{name: "aof nonempty save", mutate: func(i *OperatorAttestationInput) {
			i.values.PersistenceMode = PersistenceModeAOF
			i.values.AppendFsyncPolicy = AppendFsyncAlways
		}},
		{name: "both empty save", mutate: func(i *OperatorAttestationInput) {
			i.values.PersistenceMode = PersistenceModeRDBAOF
			i.values.AppendFsyncPolicy = AppendFsyncAlways
			i.values.SaveSchedule = ""
		}},
		{name: "too many replicas", mutate: func(i *OperatorAttestationInput) { i.values.MinReplicasToWrite = 4 }},
		{name: "zero max lag", mutate: func(i *OperatorAttestationInput) { i.values.MinReplicasMaxLagSeconds = 0 }},
		{name: "excess max lag", mutate: func(i *OperatorAttestationInput) { i.values.MinReplicasMaxLagSeconds = 3601 }},
		{name: "zero loss acceptance", mutate: func(i *OperatorAttestationInput) { i.values.LossWindowAcceptance = 0 }},
		{name: "unknown loss acceptance", mutate: func(i *OperatorAttestationInput) { i.values.LossWindowAcceptance = 255 }},
		{name: "zero rotation", mutate: func(i *OperatorAttestationInput) { i.values.RotationState = 0 }},
		{name: "unknown rotation", mutate: func(i *OperatorAttestationInput) { i.values.RotationState = 255 }},
		{name: "global claim", mutate: func(i *OperatorAttestationInput) { i.values.NoGlobalExactlyOnceClaim = false }},
	}
	requiredAssertions := []struct {
		name  string
		clear func(*OperatorAttestationInput)
	}{
		{name: "dedicated deployment", clear: func(i *OperatorAttestationInput) { i.values.DedicatedDeployment = false }},
		{name: "dedicated database", clear: func(i *OperatorAttestationInput) { i.values.DedicatedDatabaseZero = false }},
		{name: "direct authority", clear: func(i *OperatorAttestationInput) { i.values.DirectIPAuthority = false }},
		{name: "no substitution", clear: func(i *OperatorAttestationInput) { i.values.NoEndpointSubstitution = false }},
		{name: "standalone", clear: func(i *OperatorAttestationInput) { i.values.StandaloneAuthority = false }},
		{name: "shared draft", clear: func(i *OperatorAttestationInput) { i.values.SharedDraft = false }},
		{name: "shared algorithm", clear: func(i *OperatorAttestationInput) { i.values.SharedAlgorithm = false }},
		{name: "shared namespace", clear: func(i *OperatorAttestationInput) { i.values.SharedNamespace = false }},
		{name: "shared epoch", clear: func(i *OperatorAttestationInput) { i.values.SharedEpoch = false }},
		{name: "shared secret", clear: func(i *OperatorAttestationInput) { i.values.SharedSecretSet = false }},
		{name: "shared retention", clear: func(i *OperatorAttestationInput) { i.values.SharedRetention = false }},
	}
	for _, assertion := range requiredAssertions {
		tests = append(tests, struct {
			name   string
			mutate func(*OperatorAttestationInput)
		}{name: assertion.name, mutate: assertion.clear})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validOperatorAttestationInput()
			test.mutate(&input)
			if _, err := NewOperatorAttestation(input); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
				t.Fatal("invalid operator attestation was not rejected as misconfigured")
			}
		})
	}
}

// TestOperatorAttestationSaveScheduleGrammar freezes canonical bounded CONFIG syntax.
func TestOperatorAttestationSaveScheduleGrammar(t *testing.T) {
	valid := []string{
		"1 1",
		syntheticSaveSchedule,
		"1 1 " + syntheticSaveSchedule,
		"9223372036854775807 2147483647",
		strings.Repeat("1 1 ", 127) + "1 1",
	}
	for _, schedule := range valid {
		input := validOperatorAttestationInput()
		input.values.SaveSchedule = schedule
		if _, err := NewOperatorAttestation(input); err != nil {
			t.Fatal("canonical save schedule was rejected")
		}
	}

	invalid := []string{
		"", "0 1", "1 0", "+1 1", "-1 1", "01 1", "1 01",
		"1", "1 1 ", " 1 1", "1  1", "1\t1", "1\n1",
		strings.Repeat("1", 513),
		"9223372036854775808 1", "60 2147483648",
		"18446744073709551615 18446744073709551615",
		"18446744073709551616 1", "1 18446744073709551616",
	}
	for _, schedule := range invalid {
		input := validOperatorAttestationInput()
		input.values.SaveSchedule = schedule
		if _, err := NewOperatorAttestation(input); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
			t.Fatal("noncanonical save schedule was not rejected")
		}
	}
}

// TestOperatorAttestationPrivacyIsContentFreeAndSerializationRejected protects policy values.
func TestOperatorAttestationPrivacyIsContentFreeAndSerializationRejected(t *testing.T) {
	input := validOperatorAttestationInput()
	input.values.SaveSchedule = "123 456"
	attestation, err := NewOperatorAttestation(input)
	if err != nil {
		t.Fatal("valid operator attestation was rejected")
	}
	for _, format := range []string{"%v", testFormatDetailed, testFormatGoSyntax, "%s", "%q"} {
		formatted := fmt.Sprintf(format, attestation)
		if strings.Contains(formatted, input.values.SaveSchedule) ||
			strings.Contains(formatted, "rdb") ||
			strings.Contains(formatted, "asynchronous") {
			t.Fatal("operator attestation exposed retained policy")
		}
	}
	if encoded, marshalErr := json.Marshal(attestation); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("operator attestation unexpectedly marshaled as JSON")
	}
	if encoded, marshalErr := attestation.MarshalText(); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("operator attestation unexpectedly marshaled as text")
	}
}

// TestOperatorAttestationInputRejectsUnboundedAndAmbiguousAssertionSets freezes construction.
func TestOperatorAttestationInputRejectsUnboundedAndAmbiguousAssertionSets(t *testing.T) {
	base := []OperatorAssertion{
		AssertNoGlobalExactlyOnceClaim,
		AssertDedicatedDeployment,
		AssertDedicatedDatabaseZero,
		AssertDirectIPAuthority,
		AssertNoEndpointSubstitution,
		AssertStandaloneAuthority,
		AssertSharedDraft,
		AssertSharedAlgorithm,
		AssertSharedNamespace,
		AssertSharedEpoch,
		AssertSharedSecretSet,
		AssertSharedRetention,
	}
	construct := func(assertions []OperatorAssertion) OperatorAttestationInput {
		return NewOperatorAttestationInput(
			PersistenceModeRDB,
			AppendFsyncInactive,
			syntheticSaveSchedule,
			0,
			30,
			LossWindowAsynchronousAcknowledged,
			RotationUnchanged,
			assertions...,
		)
	}
	if construct(base).values == nil {
		t.Fatal("complete named assertion set was rejected")
	}
	for _, assertions := range [][]OperatorAssertion{
		base[:len(base)-1],
		append(append([]OperatorAssertion(nil), base[:len(base)-1]...), base[0]),
		append(append([]OperatorAssertion(nil), base[:len(base)-1]...), OperatorAssertion(255)),
		make([]OperatorAssertion, 1<<20),
	} {
		if construct(assertions).values != nil {
			t.Fatal("incomplete, duplicate, unknown, or unbounded assertions were retained")
		}
	}
	huge := make([]OperatorAssertion, 1<<20)
	if allocations := testing.AllocsPerRun(100, func() {
		_ = construct(huge)
	}); allocations != 0 {
		t.Fatal("unbounded assertion rejection allocated provider state")
	}
}

// TestOperatorAttestationCopiesShareImmutableOpaqueState freezes value-copy identity.
func TestOperatorAttestationCopiesShareImmutableOpaqueState(t *testing.T) {
	input := validOperatorAttestationInput()
	inputCopy := input
	if input.values == nil || inputCopy.values != input.values {
		t.Fatal("operator input copy split immutable state")
	}
	attestation, err := NewOperatorAttestation(input)
	if err != nil {
		t.Fatal(err)
	}
	attestationCopy := attestation
	if attestation.values == nil || attestationCopy.values != attestation.values ||
		!attestationCopy.valid() {
		t.Fatal("operator attestation copy split immutable state")
	}
	if (OperatorAttestationInput{}).values != nil ||
		(OperatorAttestation{}).valid() {
		t.Fatal("zero opaque authority value did not fail closed")
	}
}

// validOperatorAttestationInput constructs the complete required trusted assertion set.
func validOperatorAttestationInput() OperatorAttestationInput {
	return NewOperatorAttestationInput(
		PersistenceModeRDB,
		AppendFsyncInactive,
		syntheticSaveSchedule,
		0,
		30,
		LossWindowAsynchronousAcknowledged,
		RotationUnchanged,
		AssertNoGlobalExactlyOnceClaim,
		AssertDedicatedDeployment,
		AssertDedicatedDatabaseZero,
		AssertDirectIPAuthority,
		AssertNoEndpointSubstitution,
		AssertStandaloneAuthority,
		AssertSharedDraft,
		AssertSharedAlgorithm,
		AssertSharedNamespace,
		AssertSharedEpoch,
		AssertSharedSecretSet,
		AssertSharedRetention,
	)
}
