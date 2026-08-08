package rotationadmin

import "github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"

// TerminalBackend composes an existing datasource reader/publisher with the
// distinct closure authority so Coordinator discovers real terminal persistence.
type TerminalBackend struct {
	datasourceadmin.SnapshotReader
	datasourceadmin.GenerationPublisher
	datasourceadmin.TerminalRecorder
}

// NewTerminalBackend rejects incomplete provider composition before campaign use.
func NewTerminalBackend(reader datasourceadmin.SnapshotReader, publisher datasourceadmin.GenerationPublisher, recorder datasourceadmin.TerminalRecorder) (*TerminalBackend, error) {
	if reader == nil || publisher == nil || recorder == nil {
		return nil, errInvalid
	}
	return &TerminalBackend{SnapshotReader: reader, GenerationPublisher: publisher, TerminalRecorder: recorder}, nil
}
