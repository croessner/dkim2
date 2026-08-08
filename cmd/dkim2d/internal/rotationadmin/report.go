package rotationadmin

import (
	"encoding/json"
	"fmt"
)

// CommandReport is the sole identity-free result projection for offline campaign commands.
type CommandReport struct {
	Command         string
	Mode            string
	State           State
	Backend         string
	WorkCount       uint32
	RecordCount     uint32
	BatchCount      uint32
	RetainedCount   uint32
	UnresolvedCount uint32
	ResultClass     string
}

// EncodeCommandReport emits a bounded human line or a stable machine document.
func EncodeCommandReport(report CommandReport, machine bool) ([]byte, error) {
	if !validCommandReport(report) {
		return nil, errInvalid
	}
	if machine {
		encoded, err := json.Marshal(struct {
			Schema          string `json:"schema"`
			Command         string `json:"command"`
			Mode            string `json:"mode,omitempty"`
			State           State  `json:"state,omitempty"`
			Backend         string `json:"backend"`
			WorkCount       uint32 `json:"work_count"`
			RecordCount     uint32 `json:"record_count"`
			BatchCount      uint32 `json:"batch_count"`
			RetainedCount   uint32 `json:"retained_count"`
			UnresolvedCount uint32 `json:"unresolved_count"`
			ResultClass     string `json:"result"`
		}{"dkim2-rotation-report-v1", report.Command, report.Mode, report.State, report.Backend, report.WorkCount, report.RecordCount, report.BatchCount, report.RetainedCount, report.UnresolvedCount, report.ResultClass})
		if err != nil {
			return nil, errInvalid
		}
		return append(encoded, '\n'), nil
	}
	return []byte(fmt.Sprintf("schema=dkim2-rotation-report-v1 command=%s mode=%s state=%s backend=%s work_count=%d record_count=%d batch_count=%d retained_count=%d unresolved_count=%d result=%s\n", report.Command, report.Mode, report.State, report.Backend, report.WorkCount, report.RecordCount, report.BatchCount, report.RetainedCount, report.UnresolvedCount, report.ResultClass)), nil
}

// validCommandReport enforces the closed identity-free report vocabulary.
func validCommandReport(report CommandReport) bool {
	if report.Command == "" || report.Backend == "" || report.ResultClass == "" || len(report.Command) > 32 || len(report.Backend) > 16 || len(report.ResultClass) > 32 {
		return false
	}
	for _, value := range []string{report.Command, report.Backend, report.ResultClass} {
		for _, character := range value {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
				continue
			}
			return false
		}
	}
	if report.Mode != "" && report.Mode != string(adminModeNormal) && report.Mode != string(adminModeEmergency) {
		return false
	}
	return report.State == "" || report.State == StatePlanned || report.State == StatePreparing || report.State == StatePrepared || report.State == StateStaged || report.State == StateDNSInProgress || report.State == StateDNSComplete || report.State == StateActivating || report.State == StateActivated || report.State == StateConflict || report.State == StateFailed || report.State == StateAborted || report.State == StateReconcileRequired
}

const (
	adminModeNormal    = "normal"
	adminModeEmergency = "emergency"
)
