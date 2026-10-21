package datasourceadmin

import (
	"bytes"
	"context"
	"testing"

	"github.com/croessner/dkim2/admincontract"
)

// purgeTestDigest returns one valid digest filled with the given byte.
func purgeTestDigest(t *testing.T, fill byte) admincontract.Digest {
	t.Helper()
	digest, err := admincontract.ParseDigest(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	return digest
}

// TestPurgeCommandZeroValueRefusesTargets proves an unverified command never
// reaches a provider callback.
func TestPurgeCommandZeroValueRefusesTargets(t *testing.T) {
	called := false
	err := PurgeCommand{}.WithTargets(context.Background(), func([]admincontract.PurgeTarget) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("zero command must refuse provider callbacks: err=%v called=%v", err, called)
	}
}

// TestVerifiedPurgeCommandDetachesAndClearsTargets proves the command owns a
// private target copy that callers cannot mutate and Clear zeroes.
func TestVerifiedPurgeCommandDetachesAndClearsTargets(t *testing.T) {
	targets := []admincontract.PurgeTarget{{Generation: 2, Schema: "v3", Lifecycle: "retired", ContentDigest: purgeTestDigest(t, 3)}}
	command := NewVerifiedPurgeCommand(5, purgeTestDigest(t, 1), purgeTestDigest(t, 2), "retention-v1", targets)
	targets[0].Generation = 9

	for range 2 {
		if err := command.WithTargets(context.Background(), func(view []admincontract.PurgeTarget) error {
			if len(view) != 1 || view[0].Generation != 2 {
				t.Fatalf("command target was not detached: %+v", view)
			}
			view[0].Generation = 7
			return nil
		}); err != nil {
			t.Fatalf("WithTargets: %v", err)
		}
	}
	if command.CurrentGeneration() != 5 || command.PolicyVersion() != "retention-v1" {
		t.Fatal("unexpected command projection")
	}

	command.Clear()
	if err := command.WithTargets(context.Background(), func(view []admincontract.PurgeTarget) error {
		if view[0].Generation != 0 {
			t.Fatalf("Clear left target generation %d", view[0].Generation)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithTargets after Clear: %v", err)
	}
}
