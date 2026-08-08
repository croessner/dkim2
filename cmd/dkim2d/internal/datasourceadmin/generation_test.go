package datasourceadmin

import (
	"math"
	"testing"
	"time"
)

// TestAllocateGenerationInventoriesAllObservedValues freezes higher allocation.
func TestAllocateGenerationInventoriesAllObservedValues(t *testing.T) {
	inventory := Inventory{Current: 7, Generations: []GenerationInfo{
		{Generation: 7, Current: true, State: StateCommitted, WasActive: true},
		{Generation: 12, State: StateCommitted, WasActive: true},
	}}
	generation, err := AllocateGeneration(inventory, testGenerationLimits())
	if err != nil || generation != 13 {
		t.Fatal("allocator ignored inactive higher generation")
	}
}

// TestAllocateGenerationRetainsLegacyHistory proves deployed v1/v2 history
// neither blocks a global campaign nor becomes an outstanding v3 candidate.
func TestAllocateGenerationRetainsLegacyHistory(t *testing.T) {
	inventory := Inventory{Current: 36}
	for generation := uint64(1); generation <= 36; generation++ {
		schema := SchemaVersionV2
		if generation == 1 {
			schema = SchemaVersionV1
		}
		inventory.Generations = append(inventory.Generations, GenerationInfo{
			Generation: generation,
			Current:    generation == inventory.Current,
			State:      StateCommitted,
			Schema:     schema,
		})
	}
	allocated, err := AllocateGeneration(inventory, testGenerationLimits())
	if err != nil || allocated != 37 {
		t.Fatal("legacy committed history blocked the next global generation")
	}
}

// TestAllocateGenerationFailsClosedOnCeilingAndOverflow freezes resource limits.
func TestAllocateGenerationFailsClosedOnCeilingAndOverflow(t *testing.T) {
	limits := testGenerationLimits()
	inventory := Inventory{Current: 1, Generations: []GenerationInfo{{Generation: 1, Current: true, State: StateCommitted}}}
	for generation := uint64(2); generation <= uint64(limits.MaxOutstandingCandidates)+1; generation++ {
		inventory.Generations = append(inventory.Generations, GenerationInfo{Generation: generation, State: StateCommitted})
	}
	if _, err := AllocateGeneration(inventory, limits); CodeOf(err) != CodeLimitExceeded {
		t.Fatal("outstanding candidate ceiling bypassed")
	}
	inventory = Inventory{Current: math.MaxUint64, Generations: []GenerationInfo{{Generation: math.MaxUint64, Current: true, State: StateCommitted}}}
	if _, err := AllocateGeneration(inventory, limits); CodeOf(err) != CodeConflict {
		t.Fatal("generation exhaustion accepted")
	}
}

// testGenerationLimits returns one fully bounded administrative inventory policy.
func testGenerationLimits() GenerationLimits {
	return GenerationLimits{
		MaxGenerations: 256, MaxOutstandingCandidates: 8,
		MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20,
		BackendDeadline: 30 * time.Second,
	}
}
