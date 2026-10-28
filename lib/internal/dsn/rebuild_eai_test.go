package dsn

import (
	"context"
	"testing"
)

// TestRebuildPropagatesToSMTPUTF8PreviousHop proves that a DSN can be
// propagated to a previous hop whose recorded mf= carries an RFC 6531 UTF-8
// local part (Draft-08 Sections 16.3 and 18): the next-hop recipient keeps the
// exact recorded path and the rebuilt report requires an SMTPUTF8
// re-injection. Recorded domains are always A-labels, so the domain part needs
// no separate case here.
func TestRebuildPropagatesToSMTPUTF8PreviousHop(t *testing.T) {
	for _, sender := range []string{"<jörg@remote.example>"} {
		original := defaultPropagationOriginal(rebuildFullRecipe)
		original.Hops[0].MailFrom = sender
		evaluator := mustRebuildEvaluator(t, "")
		evaluation := mustEvaluate(t, evaluator, propagationSpec{original: original})
		if evaluation.Propagation() != PropagationEligible {
			t.Fatalf("%s: propagation=%q embedded=%q", sender, evaluation.Propagation(), evaluation.Embedded())
		}
		report, err := evaluator.Rebuild(context.Background(), rebuildRequest(evaluation))
		if err != nil || report.Outcome() != RebuildRebuilt || !report.Valid() ||
			string(report.NextHopRecipient()) != sender || !report.SMTPUTF8Required() {
			t.Fatalf("%s: Rebuild() outcome=%q failure=%q smtputf8=%t error=%v", sender, report.Outcome(), report.Failure(), report.SMTPUTF8Required(), err)
		}
	}
}
