package rotationadmin

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/admincontract"
)

// State is the public closed campaign state vocabulary.
type State = admincontract.State

// State values expose the closed campaign-state vocabulary.
const (
	StatePlanned           = admincontract.StatePlanned
	StatePreparing         = admincontract.StatePreparing
	StatePrepared          = admincontract.StatePrepared
	StateStaged            = admincontract.StateStaged
	StateDNSInProgress     = admincontract.StateDNSInProgress
	StateDNSComplete       = admincontract.StateDNSComplete
	StateActivating        = admincontract.StateActivating
	StateActivated         = admincontract.StateActivated
	StateConflict          = admincontract.StateConflict
	StateFailed            = admincontract.StateFailed
	StateAborted           = admincontract.StateAborted
	StateReconcileRequired = admincontract.StateReconcileRequired
)

// Report contains only bounded identity-free campaign facts.
type Report struct {
	State       State
	Mode        admincontract.Mode
	WorkCount   uint32
	RecordCount uint32
	BatchCount  uint32
	ResultClass string
}

// String returns a constant bounded report class without protected identities.
func (r Report) String() string {
	return fmt.Sprintf("campaign state=%s mode=%s work=%d records=%d batches=%d result=%s", r.State, r.Mode, r.WorkCount, r.RecordCount, r.BatchCount, r.ResultClass)
}

// GoString returns the same bounded identity-free report.
func (r Report) GoString() string { return r.String() }

// Format emits only the bounded identity-free report.
func (r Report) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }
