package recipe

import (
	"bytes"
	"errors"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// FuzzApplyBody exercises bounded deterministic body application over parsed recipes.
func FuzzApplyBody(f *testing.F) {
	f.Add("one\r\ntwo\r\n", `{"b":[{"c":[1,1]},{"d":["x"]}]}`)
	f.Add("tail", `{"b":[{"c":[1,1]}]}`)
	f.Fuzz(func(t *testing.T, body, encodedRecipe string) {
		if len(body) > 2048 || len(encodedRecipe) > 2048 {
			t.Skip()
		}
		message := append([]byte("A:x\r\n\r\n"), []byte(body)...)
		current, rawErr := rawStateForBodyFuzz(message)
		if rawErr != nil {
			return
		}
		plan, _, parseErr := mustParser(t, Limits{}).Parse([]byte(encodedRecipe))
		if parseErr != nil {
			return
		}
		applier := mustApplier(t, Limits{})
		before := current.body.Bytes()
		first, firstUsage, firstErr := applier.applyBody(current, plan)
		second, secondUsage, secondErr := applier.applyBody(current, plan)
		assertBodyFuzzContract(t, first, firstUsage, firstErr)
		assertBodyFuzzContract(t, second, secondUsage, secondErr)
		if recipeTestErrorCode(firstErr) != recipeTestErrorCode(secondErr) || first.Valid() != second.Valid() || firstUsage != secondUsage {
			t.Fatal("body application is not deterministic")
		}
		if first.Valid() {
			firstBody, _ := first.Body()
			secondBody, _ := second.Body()
			if !bytes.Equal(firstBody.Bytes(), secondBody.Bytes()) {
				t.Fatal("body bytes are not deterministic")
			}
			exposed := firstBody.Bytes()
			if len(exposed) > 0 {
				exposed[0] ^= 0xff
			}
			if !bytes.Equal(firstBody.Bytes(), secondBody.Bytes()) {
				t.Fatal("body result accessor exposed owned storage")
			}
		}
		if !bytes.Equal(current.body.Bytes(), before) {
			t.Fatal("body application mutated its source state")
		}
		integrated, integratedUsage, integratedErr := applier.Apply(current, plan)
		assertBodyFuzzContract(t, integrated, integratedUsage, integratedErr)
	})
}

// assertBodyFuzzContract verifies the disjoint transactional apply contract.
func assertBodyFuzzContract(t *testing.T, state State, usage Usage, err error) {
	t.Helper()
	if !usage.Valid() {
		t.Fatal("apply returned invalid Usage")
	}
	if err == nil {
		if !state.Valid() {
			t.Fatal("successful apply returned zero State")
		}
		return
	}
	var recipeErr *Error
	if state.Valid() || !errors.As(err, &recipeErr) || !recipeErr.Code().Known() || len(err.Error()) > 512 {
		t.Fatal("failed apply violated typed zero-State contract")
	}
}

// rawStateForBodyFuzz constructs a controlled state without failing the fuzz case.
func rawStateForBodyFuzz(message []byte) (State, error) {
	parsed, err := rawmsg.Parse(message)
	if err != nil {
		return State{}, err
	}
	return NewState(parsed)
}
