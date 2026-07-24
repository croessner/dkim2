package valkey

import (
	"errors"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
)

// FuzzValkeyResultMapping verifies bounded authoritative, null, unexpected, and error classifications.
func FuzzValkeyResultMapping(f *testing.F) {
	f.Add([]byte("synthetic"), uint8(0), uint8(0))
	f.Add([]byte("synthetic"), uint8(1), uint8(0))
	f.Add([]byte("synthetic"), uint8(2), uint8(0))
	f.Add([]byte("synthetic"), uint8(3), uint8(0))
	f.Add([]byte("synthetic"), uint8(4), uint8(0))
	f.Add([]byte("synthetic"), uint8(4), uint8(16))
	f.Add(make([]byte, maximumReplyBytes), uint8(6), uint8(0))
	f.Add(make([]byte, maximumReplyBytes+1), uint8(7), uint8(0))

	f.Fuzz(func(t *testing.T, payload []byte, shapeSeed, kindSeed uint8) {
		exerciseValkeyResultMapping(t, payload, shapeSeed, kindSeed)
	})
}

type fuzzMappingExpectation struct {
	check    dkim2.ReplayCheck
	code     dkim2.ReplayErrorCode
	recovery recoveryClass
}

// exerciseValkeyResultMapping bounds reply bytes before constructing and checking a synthetic provider result.
func exerciseValkeyResultMapping(t *testing.T, payload []byte, shapeSeed, kindSeed uint8) {
	t.Helper()
	const maximumFuzzReplyBytes = maximumReplyBytes + 1
	if len(payload) > maximumFuzzReplyBytes {
		return
	}

	shape := shapeSeed % 10
	result, want := newFuzzMappingResult(t, payload, shape, kindSeed)
	assertFuzzMappingOutcome(t, result, want, payload, shape, kindSeed)
}

// newFuzzMappingResult constructs one closed authoritative, contradictory, or transport result class.
func newFuzzMappingResult(
	t *testing.T,
	payload []byte,
	shape, kindSeed uint8,
) (*fakeResult, fuzzMappingExpectation) {
	t.Helper()
	switch shape {
	case 0:
		return resultFromMessage(t, cachedMessage(t, '+', "OK")),
			fuzzMappingExpectation{check: dkim2.ReplayCheckFirstSeen}
	case 1:
		return resultFromMessage(t, cachedMessage(t, '$', "OK")),
			fuzzMappingExpectation{code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart}
	case 2:
		return resultFromMessage(t, cachedMessage(t, '_', "")),
			fuzzMappingExpectation{check: dkim2.ReplayCheckReplayed}
	case 3:
		result := resultFromMessage(t, cachedMessage(t, '_', ""))
		result.raw = "SYNTHETIC-CONTRADICTION"
		return result,
			fuzzMappingExpectation{code: dkim2.ReplayErrorInternalInvariant, recovery: recoveryRestart}
	case 4:
		return newFuzzServerErrorResult(t, payload, kindSeed)
	case 5:
		return &fakeResult{nonValkeyErr: errors.New("synthetic-transport")},
			fuzzMappingExpectation{code: dkim2.ReplayErrorIndeterminate, recovery: recoveryTransient}
	case 6:
		return &fakeResult{raw: string(payload)},
			fuzzMappingExpectation{code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart}
	case 7:
		return &fakeResult{
			raw: string(payload) + strings.Repeat("X", maximumReplyBytes+1-len(payload)),
		}, fuzzMappingExpectation{code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart}
	case 8:
		return wrappedServerResult(t, serverKindBUSY+" synthetic"),
			fuzzMappingExpectation{code: dkim2.ReplayErrorInternalInvariant, recovery: recoveryRestart}
	default:
		return &fakeResult{
			raw:        "OK",
			messageErr: errors.New("synthetic-message"),
		}, fuzzMappingExpectation{code: dkim2.ReplayErrorInternalInvariant, recovery: recoveryRestart}
	}
}

// newFuzzServerErrorResult constructs one direct typed server error with an arbitrary bounded suffix.
func newFuzzServerErrorResult(
	t *testing.T,
	payload []byte,
	kindSeed uint8,
) (*fakeResult, fuzzMappingExpectation) {
	t.Helper()
	kinds := [...]struct {
		name     string
		code     dkim2.ReplayErrorCode
		recovery recoveryClass
	}{
		{name: serverKindOOM, code: dkim2.ReplayErrorLimitExceeded, recovery: recoveryRevalidation},
		{name: serverKindNOAUTH, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRestart},
		{name: serverKindWRONGPASS, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRestart},
		{name: serverKindNOPERM, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindREADONLY, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindMISCONF, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindNOREPLICAS, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindMASTERDOWN, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindCLUSTERDOWN, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindLOADING, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindMOVED, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindASK, code: dkim2.ReplayErrorUnavailable, recovery: recoveryRevalidation},
		{name: serverKindTRYAGAIN, code: dkim2.ReplayErrorUnavailable, recovery: recoveryTransient},
		{name: serverKindBUSY, code: dkim2.ReplayErrorUnavailable, recovery: recoveryTransient},
		{name: "FUTURE_KIND", code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: serverKindERR, code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
		{name: "OOM_SUFFIX", code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart},
	}
	selected := kinds[int(kindSeed)%len(kinds)]
	raw := selected.name + " " + string(payload)
	result := resultFromMessage(t, cachedMessage(t, '-', raw))
	if len(raw) > maximumReplyBytes {
		return result,
			fuzzMappingExpectation{code: dkim2.ReplayErrorInconsistent, recovery: recoveryRestart}
	}
	return result, fuzzMappingExpectation{code: selected.code, recovery: selected.recovery}
}

// assertFuzzMappingOutcome verifies exact mapping, closed pair coherence, call bounds, and error privacy.
func assertFuzzMappingOutcome(
	t *testing.T,
	result *fakeResult,
	want fuzzMappingExpectation,
	payload []byte,
	shape, kindSeed uint8,
) {
	t.Helper()
	outcome := mapResult(result)
	gotCode := dkim2.ReplayErrorCode("")
	if outcome.err != nil {
		gotCode = dkim2.ReplayErrorCodeOf(outcome.err)
	}
	if outcome.check != want.check || gotCode != want.code ||
		outcome.recovery != want.recovery {
		t.Fatalf("shape=%d kind=%d result=%s code=%q recovery=%d want=%s/%q/%d",
			shape, kindSeed, outcome.check, gotCode, outcome.recovery,
			want.check, want.code, want.recovery)
	}
	if outcome.err == nil {
		if !outcome.check.Known() || outcome.recovery != recoveryNone {
			t.Fatalf("shape=%d produced incoherent success", shape)
		}
	} else if outcome.check != 0 || !dkim2.IsReplayError(outcome.err) ||
		!dkim2.ReplayErrorCodeOf(outcome.err).Known() {
		t.Fatalf("shape=%d produced incoherent failure", shape)
	}
	if result.nonValkeyCalls != 1 {
		t.Fatalf("shape=%d non-Valkey calls=%d", shape, result.nonValkeyCalls)
	}
	wantStringCalls := 1
	if shape == 5 {
		wantStringCalls = 0
	}
	if result.stringCalls != wantStringCalls {
		t.Fatalf("shape=%d string calls=%d want=%d", shape, result.stringCalls, wantStringCalls)
	}
	wantMessageCalls := 0
	if shape == 0 || shape == 1 || shape == 9 || (shape == 6 && string(payload) == "OK") {
		wantMessageCalls = 1
	}
	if result.messageCalls != wantMessageCalls {
		t.Fatalf("shape=%d message calls=%d want=%d", shape, result.messageCalls, wantMessageCalls)
	}
	if outcome.err != nil && outcome.err.Error() != string(want.code) {
		t.Fatalf("shape=%d emitted non-canonical bounded error", shape)
	}
}
