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

// OperatorAttestationInput contains closed trusted deployment assertions.
type OperatorAttestationInput struct {
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

// OperatorAttestation is one immutable validated trusted deployment proof.
type OperatorAttestation struct {
	persistenceMode          PersistenceMode
	appendFsyncPolicy        AppendFsyncPolicy
	saveSchedule             string
	minReplicasToWrite       uint8
	minReplicasMaxLagSeconds uint16
	lossWindowAcceptance     LossWindowAcceptance
	rotationState            RotationState
}

// NewOperatorAttestation validates and constructs one immutable assertion set.
func NewOperatorAttestation(input OperatorAttestationInput) (OperatorAttestation, error) {
	if !validAttestationEnums(input) ||
		!validOperatorAssertions(input) ||
		!validAttestedPersistence(input) {
		return OperatorAttestation{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	return OperatorAttestation{
		persistenceMode:          input.PersistenceMode,
		appendFsyncPolicy:        input.AppendFsyncPolicy,
		saveSchedule:             input.SaveSchedule,
		minReplicasToWrite:       input.MinReplicasToWrite,
		minReplicasMaxLagSeconds: input.MinReplicasMaxLagSeconds,
		lossWindowAcceptance:     input.LossWindowAcceptance,
		rotationState:            input.RotationState,
	}, nil
}

// validAttestationEnums proves every closed scalar and bounded replica policy.
func validAttestationEnums(input OperatorAttestationInput) bool {
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
func validOperatorAssertions(input OperatorAttestationInput) bool {
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
func validAttestedPersistence(input OperatorAttestationInput) bool {
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
	if a.persistenceMode < PersistenceModeRDB || a.persistenceMode > PersistenceModeRDBAOF ||
		a.appendFsyncPolicy < AppendFsyncInactive || a.appendFsyncPolicy > AppendFsyncEverySecond ||
		a.minReplicasToWrite > 3 ||
		a.minReplicasMaxLagSeconds < 1 || a.minReplicasMaxLagSeconds > 3600 ||
		a.lossWindowAcceptance != LossWindowAsynchronousAcknowledged ||
		a.rotationState < RotationUnchanged || a.rotationState > RotationDrainCompleted {
		return false
	}
	switch a.persistenceMode {
	case PersistenceModeRDB:
		return a.appendFsyncPolicy == AppendFsyncInactive && validSaveSchedule(a.saveSchedule)
	case PersistenceModeAOF:
		return a.appendFsyncPolicy != AppendFsyncInactive && a.saveSchedule == ""
	case PersistenceModeRDBAOF:
		return a.appendFsyncPolicy != AppendFsyncInactive && validSaveSchedule(a.saveSchedule)
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
