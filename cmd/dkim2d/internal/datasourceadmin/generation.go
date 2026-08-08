package datasourceadmin

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// GenerationState identifies backend-durable publication state.
type GenerationState string

const (
	// StateStaging identifies one writable inactive generation.
	StateStaging GenerationState = "staging"
	// StateCommitted identifies one sealed generation.
	StateCommitted GenerationState = "committed"
)

// GenerationInfo contains bounded backend-authoritative allocation evidence.
type GenerationInfo struct {
	Generation uint64
	Current    bool
	State      GenerationState
	WasActive  bool
	Operation  OperationBinding
	// SourceGeneration is the immutable current generation frozen for a v3 campaign.
	SourceGeneration uint64
	Schema           string
	ContentDigest    CandidateContentDigest
}

// Inventory contains one stable current pointer and every bounded generation.
type Inventory struct {
	Current     uint64
	Generations []GenerationInfo
}

// Outstanding reports whether this exact noncurrent generation retains candidate material.
func (g GenerationInfo) Outstanding() bool {
	return !g.Current && (g.State != StateCommitted || !g.WasActive)
}

// Equivalent reports whether two bounded inventories contain identical ordered evidence.
func (i Inventory) Equivalent(other Inventory) bool {
	if i.Current != other.Current || len(i.Generations) != len(other.Generations) {
		return false
	}
	for index := range i.Generations {
		left, right := i.Generations[index], other.Generations[index]
		if left.Generation != right.Generation || left.Current != right.Current ||
			left.State != right.State || left.WasActive != right.WasActive ||
			left.SourceGeneration != right.SourceGeneration ||
			left.Operation.Initialized() != right.Operation.Initialized() ||
			left.Operation.Initialized() && !left.Operation.Equal(right.Operation) {
			return false
		}
	}
	return true
}

// Canonicalize sorts one detached inventory by generation for stable comparison.
func (i Inventory) Canonicalize() Inventory {
	result := Inventory{Current: i.Current, Generations: append([]GenerationInfo(nil), i.Generations...)}
	slices.SortFunc(result.Generations, func(left, right GenerationInfo) int {
		return compareUint64(left.Generation, right.Generation)
	})
	return result
}

// compareUint64 orders generation values without arithmetic overflow.
func compareUint64(left, right uint64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

// String returns a constant protected generation-info representation.
func (GenerationInfo) String() string { return redacted }

// GoString returns a constant protected generation-info representation.
func (GenerationInfo) GoString() string { return redacted }

// Format prevents generation metadata from reaching formatting sinks.
func (GenerationInfo) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected generation-info serialization.
func (GenerationInfo) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected inventory representation.
func (Inventory) String() string { return redacted }

// GoString returns a constant protected inventory representation.
func (Inventory) GoString() string { return redacted }

// Format prevents inventory metadata from reaching formatting sinks.
func (Inventory) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected inventory serialization.
func (Inventory) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// GenerationLimits bounds one stable inventory and allocation decision.
type GenerationLimits struct {
	MaxGenerations           uint32
	MaxOutstandingCandidates uint32
	MaxSnapshotRows          uint32
	MaxSnapshotBytes         uint32
	BackendDeadline          time.Duration
}

// Validate rejects zero, excessive, or unbounded generation limits.
func (l GenerationLimits) Validate() error {
	if l.MaxGenerations == 0 || l.MaxGenerations > 4096 ||
		l.MaxOutstandingCandidates == 0 || l.MaxOutstandingCandidates > 8 ||
		l.MaxSnapshotRows == 0 || l.MaxSnapshotRows > 1<<20 ||
		l.MaxSnapshotBytes == 0 || l.MaxSnapshotBytes > 1<<30 ||
		l.BackendDeadline <= 0 || l.BackendDeadline > 2*time.Minute {
		return newError(CodeLimitExceeded)
	}
	return nil
}

// AllocateGeneration chooses the first free value above every observed generation.
func AllocateGeneration(inventory Inventory, limits GenerationLimits) (uint64, error) {
	maximum, outstanding, err := validateInventory(inventory, limits)
	if err != nil {
		return 0, err
	}
	if outstanding >= limits.MaxOutstandingCandidates {
		return 0, newError(CodeLimitExceeded)
	}
	if inventory.Current == 0 && len(inventory.Generations) != 0 {
		return 0, newError(CodeConflict)
	}
	if maximum == math.MaxUint64 {
		return 0, newError(CodeConflict)
	}
	return maximum + 1, nil
}

// ValidateInventory proves one complete bounded authority view without
// reserving capacity for another candidate.
func ValidateInventory(inventory Inventory, limits GenerationLimits) error {
	_, _, err := validateInventory(inventory, limits)
	return err
}

// validateInventory owns the common current, duplicate, lifecycle, and
// retained-candidate invariants used by read and allocation paths.
func validateInventory(inventory Inventory, limits GenerationLimits) (uint64, uint32, error) {
	if limits.Validate() != nil || len(inventory.Generations) > int(limits.MaxGenerations) {
		return 0, 0, newError(CodeLimitExceeded)
	}
	seen := make(map[uint64]struct{}, len(inventory.Generations))
	maxGeneration := uint64(0)
	currentMatches := 0
	outstanding := uint32(0)
	for _, generation := range inventory.Generations {
		if generation.Generation == 0 || (generation.State != StateStaging && generation.State != StateCommitted) ||
			generation.State == StateStaging && generation.WasActive {
			return 0, 0, newError(CodeConflict)
		}
		if _, duplicate := seen[generation.Generation]; duplicate {
			return 0, 0, newError(CodeConflict)
		}
		seen[generation.Generation] = struct{}{}
		if generation.Generation > maxGeneration {
			maxGeneration = generation.Generation
		}
		if generation.Current {
			currentMatches++
			if generation.Generation != inventory.Current || generation.State != StateCommitted {
				return 0, 0, newError(CodeConflict)
			}
		} else if generation.State == StateStaging || !generation.WasActive {
			outstanding++
		}
	}
	if inventory.Current == 0 {
		if currentMatches != 0 {
			return 0, 0, newError(CodeConflict)
		}
	} else if currentMatches != 1 {
		return 0, 0, newError(CodeConflict)
	}
	if outstanding > limits.MaxOutstandingCandidates {
		return 0, 0, newError(CodeLimitExceeded)
	}
	return maxGeneration, outstanding, nil
}
