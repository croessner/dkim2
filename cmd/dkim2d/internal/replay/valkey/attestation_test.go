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
			input.PersistenceMode = test.mode
			input.AppendFsyncPolicy = test.fsync
			input.SaveSchedule = test.save
			input.RotationState = test.rotation
			input.MinReplicasToWrite = test.minReplica
			input.MinReplicasMaxLagSeconds = test.maxLag
			attestation, err := NewOperatorAttestation(input)
			if err != nil {
				t.Fatal("valid operator attestation was rejected")
			}
			if attestation.persistenceMode != test.mode ||
				attestation.appendFsyncPolicy != test.fsync ||
				attestation.saveSchedule != test.save ||
				attestation.rotationState != test.rotation ||
				attestation.minReplicasToWrite != test.minReplica ||
				attestation.minReplicasMaxLagSeconds != test.maxLag {
				t.Fatal("operator attestation did not retain exact closed policy")
			}
		})
	}
}

// TestOperatorAttestationRejectsEveryInvalidEnumCombinationAndAssertion proves fail-closed input.
func TestOperatorAttestationRejectsEveryInvalidEnumCombinationAndAssertion(t *testing.T) {
	inputType := reflect.TypeOf(OperatorAttestationInput{})
	expectedFields := []string{
		"PersistenceMode", "AppendFsyncPolicy", "SaveSchedule",
		"MinReplicasToWrite", "MinReplicasMaxLagSeconds",
		"LossWindowAcceptance", "RotationState", "NoGlobalExactlyOnceClaim",
		"DedicatedDeployment", "DedicatedDatabaseZero", "DirectIPAuthority",
		"NoEndpointSubstitution", "StandaloneAuthority", "SharedDraft",
		"SharedAlgorithm", "SharedNamespace", "SharedEpoch", "SharedSecretSet",
		"SharedRetention",
	}
	if inputType.NumField() != len(expectedFields) {
		t.Fatal("operator attestation input field set drifted")
	}
	for index, name := range expectedFields {
		if inputType.Field(index).Name != name {
			t.Fatal("operator attestation input field order drifted")
		}
	}
	tests := []struct {
		name   string
		mutate func(*OperatorAttestationInput)
	}{
		{name: "zero persistence", mutate: func(i *OperatorAttestationInput) { i.PersistenceMode = 0 }},
		{name: "unknown persistence", mutate: func(i *OperatorAttestationInput) { i.PersistenceMode = 255 }},
		{name: "zero fsync", mutate: func(i *OperatorAttestationInput) { i.AppendFsyncPolicy = 0 }},
		{name: "unknown fsync", mutate: func(i *OperatorAttestationInput) { i.AppendFsyncPolicy = 255 }},
		{name: "rdb active fsync", mutate: func(i *OperatorAttestationInput) { i.AppendFsyncPolicy = AppendFsyncAlways }},
		{name: "aof inactive fsync", mutate: func(i *OperatorAttestationInput) {
			i.PersistenceMode = PersistenceModeAOF
			i.AppendFsyncPolicy = AppendFsyncInactive
			i.SaveSchedule = ""
		}},
		{name: "both inactive fsync", mutate: func(i *OperatorAttestationInput) {
			i.PersistenceMode = PersistenceModeRDBAOF
			i.AppendFsyncPolicy = AppendFsyncInactive
		}},
		{name: "rdb empty save", mutate: func(i *OperatorAttestationInput) { i.SaveSchedule = "" }},
		{name: "aof nonempty save", mutate: func(i *OperatorAttestationInput) {
			i.PersistenceMode = PersistenceModeAOF
			i.AppendFsyncPolicy = AppendFsyncAlways
		}},
		{name: "both empty save", mutate: func(i *OperatorAttestationInput) {
			i.PersistenceMode = PersistenceModeRDBAOF
			i.AppendFsyncPolicy = AppendFsyncAlways
			i.SaveSchedule = ""
		}},
		{name: "too many replicas", mutate: func(i *OperatorAttestationInput) { i.MinReplicasToWrite = 4 }},
		{name: "zero max lag", mutate: func(i *OperatorAttestationInput) { i.MinReplicasMaxLagSeconds = 0 }},
		{name: "excess max lag", mutate: func(i *OperatorAttestationInput) { i.MinReplicasMaxLagSeconds = 3601 }},
		{name: "zero loss acceptance", mutate: func(i *OperatorAttestationInput) { i.LossWindowAcceptance = 0 }},
		{name: "unknown loss acceptance", mutate: func(i *OperatorAttestationInput) { i.LossWindowAcceptance = 255 }},
		{name: "zero rotation", mutate: func(i *OperatorAttestationInput) { i.RotationState = 0 }},
		{name: "unknown rotation", mutate: func(i *OperatorAttestationInput) { i.RotationState = 255 }},
		{name: "global claim", mutate: func(i *OperatorAttestationInput) { i.NoGlobalExactlyOnceClaim = false }},
	}
	requiredAssertions := []struct {
		name  string
		clear func(*OperatorAttestationInput)
	}{
		{name: "dedicated deployment", clear: func(i *OperatorAttestationInput) { i.DedicatedDeployment = false }},
		{name: "dedicated database", clear: func(i *OperatorAttestationInput) { i.DedicatedDatabaseZero = false }},
		{name: "direct authority", clear: func(i *OperatorAttestationInput) { i.DirectIPAuthority = false }},
		{name: "no substitution", clear: func(i *OperatorAttestationInput) { i.NoEndpointSubstitution = false }},
		{name: "standalone", clear: func(i *OperatorAttestationInput) { i.StandaloneAuthority = false }},
		{name: "shared draft", clear: func(i *OperatorAttestationInput) { i.SharedDraft = false }},
		{name: "shared algorithm", clear: func(i *OperatorAttestationInput) { i.SharedAlgorithm = false }},
		{name: "shared namespace", clear: func(i *OperatorAttestationInput) { i.SharedNamespace = false }},
		{name: "shared epoch", clear: func(i *OperatorAttestationInput) { i.SharedEpoch = false }},
		{name: "shared secret", clear: func(i *OperatorAttestationInput) { i.SharedSecretSet = false }},
		{name: "shared retention", clear: func(i *OperatorAttestationInput) { i.SharedRetention = false }},
	}
	for _, assertion := range requiredAssertions {
		assertion := assertion
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
		input.SaveSchedule = schedule
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
		input.SaveSchedule = schedule
		if _, err := NewOperatorAttestation(input); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
			t.Fatal("noncanonical save schedule was not rejected")
		}
	}
}

// TestOperatorAttestationPrivacyIsContentFreeAndSerializationRejected protects policy values.
func TestOperatorAttestationPrivacyIsContentFreeAndSerializationRejected(t *testing.T) {
	input := validOperatorAttestationInput()
	input.SaveSchedule = "123 456"
	attestation, err := NewOperatorAttestation(input)
	if err != nil {
		t.Fatal("valid operator attestation was rejected")
	}
	for _, format := range []string{"%v", testFormatDetailed, testFormatGoSyntax, "%s", "%q"} {
		formatted := fmt.Sprintf(format, attestation)
		if strings.Contains(formatted, input.SaveSchedule) ||
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

// validOperatorAttestationInput constructs the complete required trusted assertion set.
func validOperatorAttestationInput() OperatorAttestationInput {
	return OperatorAttestationInput{
		PersistenceMode:          PersistenceModeRDB,
		AppendFsyncPolicy:        AppendFsyncInactive,
		SaveSchedule:             syntheticSaveSchedule,
		MinReplicasToWrite:       0,
		MinReplicasMaxLagSeconds: 30,
		LossWindowAcceptance:     LossWindowAsynchronousAcknowledged,
		RotationState:            RotationUnchanged,
		NoGlobalExactlyOnceClaim: true,
		DedicatedDeployment:      true,
		DedicatedDatabaseZero:    true,
		DirectIPAuthority:        true,
		NoEndpointSubstitution:   true,
		StandaloneAuthority:      true,
		SharedDraft:              true,
		SharedAlgorithm:          true,
		SharedNamespace:          true,
		SharedEpoch:              true,
		SharedSecretSet:          true,
		SharedRetention:          true,
	}
}
