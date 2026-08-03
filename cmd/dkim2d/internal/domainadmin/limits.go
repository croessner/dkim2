package domainadmin

import "time"

// Limits bounds every offline administrative operation.
type Limits struct {
	MaxDocumentBytes         uint32
	MaxSnapshotRows          uint32
	MaxSnapshotBytes         uint32
	MaxGenerations           uint32
	MaxOutstandingCandidates uint32
	MaxAllocationAttempts    uint32
	MaxDNSRecords            uint32
	MaxDNSExportBytes        uint32
	BackendDeadline          time.Duration
	DNSProofLifetime         time.Duration
}

// DefaultLimits returns restrictive finite administration limits.
func DefaultLimits() Limits {
	return Limits{
		MaxDocumentBytes: 64 << 10, MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20,
		MaxGenerations: 256, MaxOutstandingCandidates: 8, MaxAllocationAttempts: 32,
		MaxDNSRecords: 64, MaxDNSExportBytes: 256 << 10,
		BackendDeadline: 30 * time.Second, DNSProofLifetime: 5 * time.Minute,
	}
}

// Validate rejects zero, excessive, or unbounded administration limits.
func (l Limits) Validate() error {
	if l.MaxDocumentBytes == 0 || l.MaxDocumentBytes > 256<<10 ||
		l.MaxSnapshotRows == 0 || l.MaxSnapshotRows > 65536 ||
		l.MaxSnapshotBytes == 0 || l.MaxSnapshotBytes > 256<<20 ||
		l.MaxGenerations == 0 || l.MaxGenerations > 4096 ||
		l.MaxOutstandingCandidates == 0 || l.MaxOutstandingCandidates > 8 ||
		l.MaxAllocationAttempts == 0 || l.MaxAllocationAttempts > 128 ||
		l.MaxDNSRecords == 0 || l.MaxDNSRecords > 256 ||
		l.MaxDNSExportBytes == 0 || l.MaxDNSExportBytes > 1<<20 ||
		l.BackendDeadline <= 0 || l.BackendDeadline > 30*time.Second ||
		l.DNSProofLifetime <= 0 || l.DNSProofLifetime > 15*time.Minute {
		return newError(CodeInvalidLimits)
	}
	return nil
}

// GenerationState identifies backend-durable generation lifecycle evidence.
type GenerationState string

const (
	// GenerationStateStaging is one writable inactive candidate.
	GenerationStateStaging GenerationState = "staging"
	// GenerationStateCommitted is one sealed generation.
	GenerationStateCommitted GenerationState = "committed"
)

// GenerationEvidence is the backend-authoritative retention projection.
type GenerationEvidence struct {
	State     GenerationState
	Current   bool
	WasActive bool
}

// Outstanding conservatively classifies retained noncurrent candidate material.
func (e GenerationEvidence) Outstanding() bool {
	if e.Current {
		return false
	}
	return e.State != GenerationStateCommitted || !e.WasActive
}
