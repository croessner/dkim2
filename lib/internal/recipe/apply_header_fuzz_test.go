package recipe

import (
	"bytes"
	"errors"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// FuzzApplyHeader exercises deterministic immutable header reconstruction under bounded input.
func FuzzApplyHeader(f *testing.F) {
	f.Add([]byte("Subject: top\r\nSubject: bottom\r\n\r\nbody\r\n"), []byte(`{"h":{"Subject":[{"c":[1,1]},{"d":["restored"]}]}}`))
	f.Add([]byte("Folded: one\r\n two\r\n\r\n"), []byte(`{"h":{"Folded":[{"c":[1,1]}]}}`))
	f.Add([]byte("A:TOXIC_HEADER_MARKER\r\n\r\n"), []byte(`{"h":{"A":[{"c":[2,2]}]}}`))
	f.Fuzz(func(t *testing.T, message, encodedRecipe []byte) {
		if len(message) > 4096 || len(encodedRecipe) > 4096 {
			t.Skip()
		}
		parsed, rawErr := rawmsg.Parse(message)
		if rawErr != nil {
			return
		}
		current, stateErr := NewState(parsed)
		if stateErr != nil {
			t.Fatal("rawmsg produced an unusable recipe state")
		}
		plan, _, parseErr := mustParser(t, Limits{}).Parse(encodedRecipe)
		if parseErr != nil {
			return
		}
		before := parsed.RawBytes()
		applier := mustApplier(t, Limits{})
		first, firstUsage, firstErr := applier.applyHeaders(current, plan)
		second, secondUsage, secondErr := applier.applyHeaders(current, plan)
		assertHeaderFuzzContract(t, first, firstUsage, firstErr)
		assertHeaderFuzzContract(t, second, secondUsage, secondErr)
		if recipeTestErrorCode(firstErr) != recipeTestErrorCode(secondErr) || firstUsage != secondUsage || first.Valid() != second.Valid() {
			t.Fatal("header application is not deterministic")
		}
		if first.Valid() {
			if !bytes.Equal(first.Headers().OriginalBytes(), second.Headers().OriginalBytes()) {
				t.Fatal("header output bytes are not deterministic")
			}
			exposed := first.Headers().OriginalBytes()
			if len(exposed) > 0 {
				exposed[0] ^= 0xff
			}
			if !bytes.Equal(first.Headers().OriginalBytes(), second.Headers().OriginalBytes()) {
				t.Fatal("header result accessor exposed owned storage")
			}
		}
		if !bytes.Equal(parsed.RawBytes(), before) {
			t.Fatal("header application mutated its source message")
		}
	})
}

// assertHeaderFuzzContract verifies the disjoint transactional header-apply contract.
func assertHeaderFuzzContract(t *testing.T, state State, usage Usage, err error) {
	t.Helper()
	if !usage.Valid() {
		t.Fatal("header apply returned invalid Usage")
	}
	if err == nil {
		if !state.Valid() {
			t.Fatal("successful header apply returned zero State")
		}
		return
	}
	var recipeErr *Error
	if state.Valid() || !errors.As(err, &recipeErr) || !recipeErr.Code().Known() || len(err.Error()) > 512 {
		t.Fatal("failed header apply violated typed bounded zero-State contract")
	}
}
