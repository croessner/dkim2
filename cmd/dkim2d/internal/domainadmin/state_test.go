package domainadmin

import "testing"

// TestOperationVocabularyHasNoVerifiedState freezes the recovery boundary.
func TestOperationVocabularyHasNoVerifiedState(t *testing.T) {
	for _, state := range OperationStates() {
		if state == OperationState("verified") || !state.Known() {
			t.Fatal("operation state vocabulary widened")
		}
	}
	if OperationState("verified").Known() {
		t.Fatal("verified state accepted")
	}
	if CommandStatus.MutatesJournal() || !CommandReconcile.MutatesJournal() {
		t.Fatal("status/reconcile ownership drifted")
	}
}
