package outcome

import "testing"

// TestClosedOutcomeVocabulariesRejectUnknownValues proves both domain enums remain exact.
func TestClosedOutcomeVocabulariesRejectUnknownValues(t *testing.T) {
	t.Parallel()
	for value := ReplayClass(0); value <= ReplayClass(6); value++ {
		want := value >= ReplayNotChecked && value <= ReplayIndeterminate
		if value.Known() != want {
			t.Fatalf("ReplayClass(%d).Known() = %t, want %t", value, value.Known(), want)
		}
	}
	for value := FinalDisposition(0); value <= FinalDisposition(5); value++ {
		want := value >= DispositionAccept && value <= DispositionContinue
		if value.Known() != want {
			t.Fatalf("FinalDisposition(%d).Known() = %t, want %t", value, value.Known(), want)
		}
	}
}
