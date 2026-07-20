package recipe

import (
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestApplyHistoricalContinuesHeadersAcrossUnavailableBodyCopy locks explicit b:null proof semantics.
func TestApplyHistoricalContinuesHeadersAcrossUnavailableBodyCopy(t *testing.T) {
	parser := mustParser(t, Limits{})
	applier := mustApplier(t, Limits{})
	message, err := rawmsg.Parse([]byte("Subject:current\r\n\r\ncurrent\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	state, err := NewState(message)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	nullRecipe, _, err := parser.Parse([]byte(`{"h":{"Subject":[{"d":["middle"]}]},"b":null}`))
	if err != nil {
		t.Fatalf("Parse(null) error = %v", err)
	}
	unavailable, _, err := applier.Apply(state, nullRecipe)
	if err != nil || unavailable.BodyState() != BodyAvailabilityUnavailable {
		t.Fatalf("Apply(null) state/error = %q/%v", unavailable.BodyState(), err)
	}
	copyRecipe, _, err := parser.Parse([]byte(`{"h":{"Subject":[{"d":["origin"]}]},"b":[{"c":[1,1]}]}`))
	if err != nil {
		t.Fatalf("Parse(copy) error = %v", err)
	}
	if _, _, err := applier.Apply(unavailable, copyRecipe); !IsErrorCode(err, ErrorCodeSourceUnavailable) {
		t.Fatalf("ordinary Apply() error = %v, want source_unavailable", err)
	}
	origin, _, err := applier.ApplyHistorical(unavailable, copyRecipe)
	if err != nil || origin.BodyState() != BodyAvailabilityUnavailable || string(origin.Headers().OriginalBytes()) != "Subject:origin\r\n" {
		t.Fatalf("ApplyHistorical() header/body/error = %q/%q/%v", origin.Headers().OriginalBytes(), origin.BodyState(), err)
	}
	restoreRecipe, _, err := parser.Parse([]byte(`{"b":[{"d":["restored"]}]}`))
	if err != nil {
		t.Fatalf("Parse(restore) error = %v", err)
	}
	restored, _, err := applier.ApplyHistorical(unavailable, restoreRecipe)
	body, known := restored.Body()
	if err != nil || !known || string(body.Bytes()) != "restored\r\n" {
		t.Fatalf("d-only restore known/body/error = %t/%q/%v", known, body.Bytes(), err)
	}
}
