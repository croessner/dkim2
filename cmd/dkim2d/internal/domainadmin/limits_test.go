package domainadmin

import "testing"

// TestLimitsBoundOutstandingCandidates freezes finite administrative work.
func TestLimitsBoundOutstandingCandidates(t *testing.T) {
	limits := DefaultLimits()
	if err := limits.Validate(); err != nil || limits.MaxOutstandingCandidates == 0 || limits.MaxOutstandingCandidates > 8 {
		t.Fatal("default administrative limits are not restrictive")
	}
	limits.MaxOutstandingCandidates = 0
	if CodeOf(limits.Validate()) != CodeInvalidLimits {
		t.Fatal("unbounded candidate retention accepted")
	}
}

// TestClassifyOutstandingUsesBackendEvidence freezes journal-independent retention.
func TestClassifyOutstandingUsesBackendEvidence(t *testing.T) {
	cases := []struct {
		evidence GenerationEvidence
		want     bool
	}{
		{GenerationEvidence{State: GenerationStateStaging}, true},
		{GenerationEvidence{State: GenerationStateCommitted}, true},
		{GenerationEvidence{State: GenerationStateCommitted, WasActive: true}, false},
		{GenerationEvidence{State: GenerationStateCommitted, Current: true}, false},
		{GenerationEvidence{State: GenerationState("unknown")}, true},
	}
	for _, test := range cases {
		if got := test.evidence.Outstanding(); got != test.want {
			t.Fatal("backend retention classification drifted")
		}
	}
}
