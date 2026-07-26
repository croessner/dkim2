package valkey

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	dkim2 "github.com/croessner/dkim2"
)

const operatorAttestationRedactedText = "valkey_operator_attestation"

// PersistenceMode identifies one closed persistence posture.
type PersistenceMode uint8

const (
	// PersistenceModeRDB requires snapshot persistence.
	PersistenceModeRDB PersistenceMode = iota + 1
	// PersistenceModeAOF requires append-only persistence.
	PersistenceModeAOF
	// PersistenceModeRDBAOF requires both persistence mechanisms.
	PersistenceModeRDBAOF
)

// AppendFsyncPolicy identifies one closed append-only synchronization posture.
type AppendFsyncPolicy uint8

const (
	// AppendFsyncInactive is legal only when AOF is disabled.
	AppendFsyncInactive AppendFsyncPolicy = iota + 1
	// AppendFsyncAlways requires every-write synchronization.
	AppendFsyncAlways
	// AppendFsyncEverySecond requires once-per-second synchronization.
	AppendFsyncEverySecond
)

// LossWindowAcceptance identifies explicit asynchronous-loss acknowledgment.
type LossWindowAcceptance uint8

const (
	// LossWindowAsynchronousAcknowledged accepts the documented failover window.
	LossWindowAsynchronousAcknowledged LossWindowAcceptance = iota + 1
)

// RotationState identifies one complete secret/epoch rotation posture.
type RotationState uint8

const (
	// RotationUnchanged means replay traffic uses an unchanged secret set.
	RotationUnchanged RotationState = iota + 1
	// RotationDrainCompleted proves the complete drain-only rotation contract.
	RotationDrainCompleted
)

// OperatorAssertion identifies one explicit trusted deployment assertion.
type OperatorAssertion uint8

const (
	// AssertNoGlobalExactlyOnceClaim rejects a global delivery guarantee.
	AssertNoGlobalExactlyOnceClaim OperatorAssertion = iota + 1
	// AssertDedicatedDeployment requires a replay-dedicated deployment.
	AssertDedicatedDeployment
	// AssertDedicatedDatabaseZero requires exclusive database zero.
	AssertDedicatedDatabaseZero
	// AssertDirectIPAuthority requires direct IP endpoint authority.
	AssertDirectIPAuthority
	// AssertNoEndpointSubstitution forbids endpoint substitution.
	AssertNoEndpointSubstitution
	// AssertStandaloneAuthority requires a standalone primary.
	AssertStandaloneAuthority
	// AssertSharedDraft requires one draft across participants.
	AssertSharedDraft
	// AssertSharedAlgorithm requires one replay-key algorithm.
	AssertSharedAlgorithm
	// AssertSharedNamespace requires one replay namespace.
	AssertSharedNamespace
	// AssertSharedEpoch requires one secret epoch.
	AssertSharedEpoch
	// AssertSharedSecretSet requires one replay secret set.
	AssertSharedSecretSet
	// AssertSharedRetention requires one retention policy.
	AssertSharedRetention
)

// operatorAttestationInputValues owns closed trusted deployment assertions.
type operatorAttestationInputValues struct {
	PersistenceMode          PersistenceMode
	AppendFsyncPolicy        AppendFsyncPolicy
	SaveSchedule             string
	MinReplicasToWrite       uint8
	MinReplicasMaxLagSeconds uint16
	LossWindowAcceptance     LossWindowAcceptance
	RotationState            RotationState
	NoGlobalExactlyOnceClaim bool
	DedicatedDeployment      bool
	DedicatedDatabaseZero    bool
	DirectIPAuthority        bool
	NoEndpointSubstitution   bool
	StandaloneAuthority      bool
	SharedDraft              bool
	SharedAlgorithm          bool
	SharedNamespace          bool
	SharedEpoch              bool
	SharedSecretSet          bool
	SharedRetention          bool
}

// OperatorAttestationInput is an opaque, copy-safe trusted assertion input.
type OperatorAttestationInput struct {
	values *operatorAttestationInputValues
}

// String returns one content-free operator-attestation input representation.
func (OperatorAttestationInput) String() string { return operatorAttestationRedactedText }

// GoString returns one content-free operator-attestation input representation.
func (OperatorAttestationInput) GoString() string { return operatorAttestationRedactedText }

// Format prevents formatting verbs from exposing unvalidated operator assertions.
func (OperatorAttestationInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, operatorAttestationRedactedText)
}

// MarshalJSON rejects serialization of unvalidated operator assertions.
func (OperatorAttestationInput) MarshalJSON() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// MarshalText rejects serialization of unvalidated operator assertions.
func (OperatorAttestationInput) MarshalText() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// operatorAttestationValues owns one immutable validated trusted deployment proof.
type operatorAttestationValues struct {
	persistenceMode          PersistenceMode
	appendFsyncPolicy        AppendFsyncPolicy
	saveSchedule             string
	minReplicasToWrite       uint8
	minReplicasMaxLagSeconds uint16
	lossWindowAcceptance     LossWindowAcceptance
	rotationState            RotationState
}

// OperatorAttestation is one opaque immutable validated trusted deployment proof.
type OperatorAttestation struct {
	values *operatorAttestationValues
}

// NewOperatorAttestationInput constructs one opaque trusted assertion input.
func NewOperatorAttestationInput(
	persistenceMode PersistenceMode,
	appendFsyncPolicy AppendFsyncPolicy,
	saveSchedule string,
	minReplicasToWrite uint8,
	minReplicasMaxLagSeconds uint16,
	lossWindowAcceptance LossWindowAcceptance,
	rotationState RotationState,
	assertions ...OperatorAssertion,
) OperatorAttestationInput {
	if len(assertions) != int(AssertSharedRetention) {
		return OperatorAttestationInput{}
	}
	values := &operatorAttestationInputValues{
		PersistenceMode:          persistenceMode,
		AppendFsyncPolicy:        appendFsyncPolicy,
		SaveSchedule:             saveSchedule,
		MinReplicasToWrite:       minReplicasToWrite,
		MinReplicasMaxLagSeconds: minReplicasMaxLagSeconds,
		LossWindowAcceptance:     lossWindowAcceptance,
		RotationState:            rotationState,
	}
	var seen uint16
	for _, assertion := range assertions {
		if assertion < AssertNoGlobalExactlyOnceClaim || assertion > AssertSharedRetention {
			return OperatorAttestationInput{}
		}
		bit := uint16(1) << (assertion - 1)
		if seen&bit != 0 || !applyOperatorAssertion(values, assertion) {
			return OperatorAttestationInput{}
		}
		seen |= bit
	}
	return OperatorAttestationInput{values: values}
}

// applyOperatorAssertion names and records one closed deployment assertion.
func applyOperatorAssertion(values *operatorAttestationInputValues, assertion OperatorAssertion) bool {
	switch assertion {
	case AssertNoGlobalExactlyOnceClaim:
		values.NoGlobalExactlyOnceClaim = true
	case AssertDedicatedDeployment:
		values.DedicatedDeployment = true
	case AssertDedicatedDatabaseZero:
		values.DedicatedDatabaseZero = true
	case AssertDirectIPAuthority:
		values.DirectIPAuthority = true
	case AssertNoEndpointSubstitution:
		values.NoEndpointSubstitution = true
	case AssertStandaloneAuthority:
		values.StandaloneAuthority = true
	case AssertSharedDraft:
		values.SharedDraft = true
	case AssertSharedAlgorithm:
		values.SharedAlgorithm = true
	case AssertSharedNamespace:
		values.SharedNamespace = true
	case AssertSharedEpoch:
		values.SharedEpoch = true
	case AssertSharedSecretSet:
		values.SharedSecretSet = true
	case AssertSharedRetention:
		values.SharedRetention = true
	default:
		return false
	}
	return true
}

// NewOperatorAttestation validates and constructs one immutable assertion set.
func NewOperatorAttestation(input OperatorAttestationInput) (OperatorAttestation, error) {
	if input.values == nil ||
		!validAttestationEnums(input.values) ||
		!validOperatorAssertions(input.values) ||
		!validAttestedPersistence(input.values) {
		return OperatorAttestation{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	return OperatorAttestation{values: &operatorAttestationValues{
		persistenceMode:          input.values.PersistenceMode,
		appendFsyncPolicy:        input.values.AppendFsyncPolicy,
		saveSchedule:             input.values.SaveSchedule,
		minReplicasToWrite:       input.values.MinReplicasToWrite,
		minReplicasMaxLagSeconds: input.values.MinReplicasMaxLagSeconds,
		lossWindowAcceptance:     input.values.LossWindowAcceptance,
		rotationState:            input.values.RotationState,
	}}, nil
}

// validAttestationEnums proves every closed scalar and bounded replica policy.
func validAttestationEnums(input *operatorAttestationInputValues) bool {
	return input.PersistenceMode >= PersistenceModeRDB &&
		input.PersistenceMode <= PersistenceModeRDBAOF &&
		input.AppendFsyncPolicy >= AppendFsyncInactive &&
		input.AppendFsyncPolicy <= AppendFsyncEverySecond &&
		input.MinReplicasToWrite <= 3 &&
		input.MinReplicasMaxLagSeconds >= 1 &&
		input.MinReplicasMaxLagSeconds <= 3600 &&
		input.LossWindowAcceptance == LossWindowAsynchronousAcknowledged &&
		input.RotationState >= RotationUnchanged &&
		input.RotationState <= RotationDrainCompleted
}

// validOperatorAssertions proves every required deployment assertion is explicit.
func validOperatorAssertions(input *operatorAttestationInputValues) bool {
	return input.NoGlobalExactlyOnceClaim &&
		input.DedicatedDeployment &&
		input.DedicatedDatabaseZero &&
		input.DirectIPAuthority &&
		input.NoEndpointSubstitution &&
		input.StandaloneAuthority &&
		input.SharedDraft &&
		input.SharedAlgorithm &&
		input.SharedNamespace &&
		input.SharedEpoch &&
		input.SharedSecretSet &&
		input.SharedRetention
}

// validAttestedPersistence proves the selected mode has one coherent save policy.
func validAttestedPersistence(input *operatorAttestationInputValues) bool {
	switch input.PersistenceMode {
	case PersistenceModeRDB:
		return input.AppendFsyncPolicy == AppendFsyncInactive &&
			validSaveSchedule(input.SaveSchedule)
	case PersistenceModeAOF:
		return input.AppendFsyncPolicy != AppendFsyncInactive &&
			input.SaveSchedule == ""
	case PersistenceModeRDBAOF:
		return input.AppendFsyncPolicy != AppendFsyncInactive &&
			validSaveSchedule(input.SaveSchedule)
	default:
		return false
	}
}

// valid reports whether one value could only have come from the constructor.
func (a OperatorAttestation) valid() bool {
	if a.values == nil {
		return false
	}
	values := a.values
	if values.persistenceMode < PersistenceModeRDB || values.persistenceMode > PersistenceModeRDBAOF ||
		values.appendFsyncPolicy < AppendFsyncInactive || values.appendFsyncPolicy > AppendFsyncEverySecond ||
		values.minReplicasToWrite > 3 ||
		values.minReplicasMaxLagSeconds < 1 || values.minReplicasMaxLagSeconds > 3600 ||
		values.lossWindowAcceptance != LossWindowAsynchronousAcknowledged ||
		values.rotationState < RotationUnchanged || values.rotationState > RotationDrainCompleted {
		return false
	}
	switch values.persistenceMode {
	case PersistenceModeRDB:
		return values.appendFsyncPolicy == AppendFsyncInactive && validSaveSchedule(values.saveSchedule)
	case PersistenceModeAOF:
		return values.appendFsyncPolicy != AppendFsyncInactive && values.saveSchedule == ""
	case PersistenceModeRDBAOF:
		return values.appendFsyncPolicy != AppendFsyncInactive && validSaveSchedule(values.saveSchedule)
	default:
		return false
	}
}

// validSaveSchedule proves exact canonical bounded CONFIG grammar.
func validSaveSchedule(schedule string) bool {
	if len(schedule) < 1 || len(schedule) > 512 ||
		schedule[0] == ' ' || schedule[len(schedule)-1] == ' ' ||
		strings.Contains(schedule, "  ") {
		return false
	}
	fields := strings.Split(schedule, " ")
	if len(fields)%2 != 0 {
		return false
	}
	for index, field := range fields {
		bits := 63
		if index%2 == 1 {
			bits = 31
		}
		value, err := strconv.ParseUint(field, 10, bits)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != field {
			return false
		}
	}
	return true
}

// String returns one content-free operator-attestation representation.
func (OperatorAttestation) String() string { return operatorAttestationRedactedText }

// GoString returns one content-free operator-attestation representation.
func (OperatorAttestation) GoString() string { return operatorAttestationRedactedText }

// Format prevents formatting verbs from exposing operator assertions.
func (OperatorAttestation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, operatorAttestationRedactedText)
}

// MarshalJSON rejects serialization of operator assertions.
func (OperatorAttestation) MarshalJSON() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// MarshalText rejects serialization of operator assertions.
func (OperatorAttestation) MarshalText() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}
