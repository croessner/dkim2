package datasourceadmin

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestCollisionInventoryConsumesCompleteCurrentAndOutstandingSnapshots freezes identity scope.
func TestCollisionInventoryConsumesCompleteCurrentAndOutstandingSnapshots(t *testing.T) {
	operation, _ := NewOperationBinding(digestTestID)
	lock, _ := NewAdministrationLock(operation, 11)
	current, err := NewSnapshot(SchemaVersionV2, 7, deterministicRows(t))
	if err != nil {
		t.Fatal("current snapshot rejected")
	}
	outstanding, err := NewSnapshot(SchemaVersionV3, 9, validRows(t, 9))
	if err != nil {
		t.Fatal("outstanding snapshot rejected")
	}
	inventory := Inventory{Current: 7, Generations: []GenerationInfo{
		{Generation: 9, State: StateStaging, Operation: operation},
		{Generation: 7, Current: true, State: StateCommitted, WasActive: true},
	}}
	view, err := NewCollisionInventory(t.Context(), lock, inventory, []CollisionSnapshot{
		{Info: inventory.Generations[1], Snapshot: current},
		{Info: inventory.Generations[0], Snapshot: outstanding},
	}, testGenerationLimits())
	if err != nil {
		t.Fatal("complete collision inventory rejected")
	}
	defer view.Close() //nolint:errcheck // Test cleanup has no recovery.
	if current.Generation() != 0 || outstanding.Generation() != 0 {
		t.Fatal("collision inventory retained complete key snapshots")
	}
	if !view.ProfileIDUsed(testProfileID) || !view.HandleIDUsed(testHandleEd) ||
		!view.SelectorUsed(testSelector) || !view.OperationUsed(operation) || view.CandidateGeneration() != 10 {
		t.Fatal("collision inventory omitted current or outstanding identities")
	}
	if !view.ValidFor(lock) {
		t.Fatal("collision inventory lost its exact lock binding")
	}
	wrongRevision, _ := NewAdministrationLock(operation, lock.Revision()+1)
	if source, err := view.TakePlanSource(wrongRevision); err == nil || source != nil {
		t.Fatal("different lock revision transferred the plan source")
	}
	source, err := view.TakePlanSource(lock)
	if err != nil || source == nil || source.Generation() != 7 {
		t.Fatal("exact lock did not transfer the current plan source")
	}
	defer source.Close() //nolint:errcheck // Test cleanup has no recovery.
	if err := source.WithRows(t.Context(), func(rows Rows) error {
		for _, key := range rows.KeyMaterial {
			if len(key.PrivatePKCS8) != 0 {
				t.Fatal("plan source retained private-key bytes")
			}
		}
		return nil
	}); err != nil {
		t.Fatal("transferred plan source was not readable")
	}
	if repeated, err := view.TakePlanSource(lock); err == nil || repeated != nil {
		t.Fatal("current plan source was transferred more than once")
	}
}

// TestCollisionInventoryRejectsIncompleteConcurrentView freezes insertion drift handling.
func TestCollisionInventoryRejectsIncompleteConcurrentView(t *testing.T) {
	operation, _ := NewOperationBinding(digestTestID)
	lock, _ := NewAdministrationLock(operation, 12)
	current, err := NewSnapshot(SchemaVersionV2, 7, validRows(t, 7))
	if err != nil {
		t.Fatal("current snapshot rejected")
	}
	inventory := Inventory{Current: 7, Generations: []GenerationInfo{
		{Generation: 7, Current: true, State: StateCommitted, WasActive: true},
		{Generation: 9, State: StateStaging},
	}}
	if view, err := NewCollisionInventory(t.Context(), lock, inventory, []CollisionSnapshot{{Info: inventory.Generations[0], Snapshot: current}}, testGenerationLimits()); err == nil || view != nil {
		t.Fatal("incomplete concurrent collision view accepted")
	}
	if current.Generation() != 0 {
		t.Fatal("rejected collision view retained transferred snapshot")
	}
}

// TestCollisionInventoryRejectsGenericSinks freezes protected-view privacy.
func TestCollisionInventoryRejectsGenericSinks(t *testing.T) {
	operation, _ := NewOperationBinding(digestTestID)
	lock, _ := NewAdministrationLock(operation, 13)
	view, err := NewCollisionInventory(t.Context(), lock, Inventory{}, nil, testGenerationLimits())
	if err != nil {
		t.Fatal("empty collision inventory rejected")
	}
	defer view.Close() //nolint:errcheck // Test cleanup has no recovery.
	values := []any{view, CollisionSnapshot{}, Inventory{}, GenerationInfo{}}
	for _, value := range values {
		rendered := fmt.Sprintf("%+v", value)
		if !strings.Contains(rendered, redacted) {
			t.Fatal("collision evidence reached formatting sink")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("collision evidence reached JSON sink")
		}
	}
}

// TestCollisionInventoryTransfersEmptyPlanSourceExactlyOnce freezes empty-backend ownership.
func TestCollisionInventoryTransfersEmptyPlanSourceExactlyOnce(t *testing.T) {
	operation, _ := NewOperationBinding(digestTestID)
	lock, _ := NewAdministrationLock(operation, 14)
	view, err := NewCollisionInventory(t.Context(), lock, Inventory{}, nil, testGenerationLimits())
	if err != nil {
		t.Fatal("empty collision inventory rejected")
	}
	defer view.Close() //nolint:errcheck // Test cleanup has no recovery.
	if source, err := view.TakePlanSource(lock); err != nil || source != nil {
		t.Fatal("first empty plan-source transfer rejected")
	}
	if source, err := view.TakePlanSource(lock); err == nil || source != nil {
		t.Fatal("empty plan source was transferred more than once")
	}
}
