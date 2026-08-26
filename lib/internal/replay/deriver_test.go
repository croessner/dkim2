package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const privacyDeriverMapKey = "deriver"

// TestDeriverProducesExactPublishedStorageKey verifies byte framing, HMAC, epoch formatting, and base64url.
func TestDeriverProducesExactPublishedStorageKey(t *testing.T) {
	secret := sequenceBytes(0xa0)
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		message: sequenceDigest(0x00), messagePresent: true,
		signature: sequenceDigest(0x20), signaturePresent: true,
		recipients: [][32]byte{sequenceDigest(0x40)},
	}
	set, err := NewIdentitySet(source)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	deriver, err := NewDeriver(secret, 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	for index := range secret {
		secret[index] = 0
	}
	key, err := deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	const want = "dkim2:replay:v1:01020304:HI_5l6s7L6xrPIUOMgXV1sgoMf1Nmc_J_KYh0c_aiYk"
	calls := 0
	if err := UseStorageKey(key, func(storageKey string) error {
		calls++
		if storageKey != want || len(storageKey) != 68 {
			t.Fatalf("storage key = %q, want %q", storageKey, want)
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("UseStorageKey() calls=%d error=%v", calls, err)
	}
}

// TestDraft05IdentitySeparatesEpoch proves the DraftIdentifier rotates otherwise identical replay facts.
func TestDraft05IdentitySeparatesEpoch(t *testing.T) {
	if DraftIdentifier != "draft-ietf-dkim-dkim2-spec-05" {
		t.Fatalf("DraftIdentifier = %q", DraftIdentifier)
	}
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		message: sequenceDigest(0x00), messagePresent: true,
		signature: sequenceDigest(0x20), signaturePresent: true,
		recipients: [][32]byte{sequenceDigest(0x40)},
	}
	const draft04Key = "dkim2:replay:v1:01020304:ZY5FUs9tgID9qTmf5RMx0klaDUM7YNLc__lWkDX8RnE"
	if got := mustDerivedStorageKey(t, sequenceBytes(0xa0), 0x01020304, source); got == draft04Key {
		t.Fatal("Draft-05 replay identity reused the Draft-04 HMAC epoch")
	}
}

// TestDeriverProducesExactAllZeroPresentDigestKey verifies digest presence is independent of value.
func TestDeriverProducesExactAllZeroPresentDigestKey(t *testing.T) {
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		messagePresent: true, signaturePresent: true,
		recipients: [][32]byte{sequenceDigest(0x40)},
	}
	const want = "dkim2:replay:v1:01020304:ZDWmi2XZcYnMZlpGWEHxBxw0STMmc6b7h06LanyC2i0"
	if got := mustDerivedStorageKey(t, sequenceBytes(0xa0), 0x01020304, source); got != want {
		t.Fatalf("all-zero present digest storage key = %q, want %q", got, want)
	}
}

// TestDeriverIsDeterministicAcrossIndependentInstances verifies identical facts yield one key.
func TestDeriverIsDeterministicAcrossIndependentInstances(t *testing.T) {
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		message: sequenceDigest(0x00), messagePresent: true,
		signature: sequenceDigest(0x20), signaturePresent: true,
		recipients: [][32]byte{sequenceDigest(0x40)},
	}
	secret := sequenceBytes(0xa0)
	first := mustDerivedStorageKey(t, secret, 0x01020304, source)
	second := mustDerivedStorageKey(t, secret, 0x01020304, source)
	if first != second {
		t.Fatal("independent derivers produced different keys for identical facts")
	}
}

// TestDeriverChangesEveryBoundFact verifies separation across key, versioned identity, epoch, and recipient facts.
func TestDeriverChangesEveryBoundFact(t *testing.T) {
	baseSource := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		message: sequenceDigest(0x00), messagePresent: true,
		signature: sequenceDigest(0x20), signaturePresent: true,
		recipients: [][32]byte{sequenceDigest(0x40)},
	}
	base := mustDerivedStorageKey(t, sequenceBytes(0xa0), 1, baseSource)
	variants := []struct {
		secret []byte
		epoch  uint32
		source syntheticIdentitySource
	}{
		{sequenceBytes(0xa1), 1, baseSource},
		{sequenceBytes(0xa0), 2, baseSource},
		{sequenceBytes(0xa0), 1, func() syntheticIdentitySource { value := baseSource; value.message[0]++; return value }()},
		{sequenceBytes(0xa0), 1, func() syntheticIdentitySource { value := baseSource; value.signature[0]++; return value }()},
		{sequenceBytes(0xa0), 1, func() syntheticIdentitySource {
			value := baseSource
			value.recipients = [][32]byte{sequenceDigest(0x41)}
			return value
		}()},
	}
	for index, variant := range variants {
		if got := mustDerivedStorageKey(t, variant.secret, variant.epoch, variant.source); got == base {
			t.Fatalf("variant %d did not change storage key", index)
		}
	}

	notExploded := baseSource
	exploded := baseSource
	exploded.exploded = true
	if left, right := mustDerivedStorageKey(t, sequenceBytes(0xa0), 1, notExploded),
		mustDerivedStorageKey(t, sequenceBytes(0xa0), 1, exploded); left != right {
		t.Fatal("authenticated exploded policy fact changed storage identity")
	}
}

// TestDeriverRejectsInvalidSecretsEpochIdentityAndContext verifies exact pre-admission failures.
func TestDeriverRejectsInvalidSecretsEpochIdentityAndContext(t *testing.T) {
	for _, secret := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33)} {
		if deriver, err := NewDeriver(secret, 1); deriver != nil || ErrorCodeOf(err) != ErrorCodeMisconfigured {
			t.Fatalf("NewDeriver(len=%d) = %v, %v", len(secret), deriver, err)
		}
	}
	if deriver, err := NewDeriver(sequenceBytes(1), 0); deriver != nil || ErrorCodeOf(err) != ErrorCodeMisconfigured {
		t.Fatalf("NewDeriver(epoch zero) = %v, %v", deriver, err)
	}
	deriver, err := NewDeriver(sequenceBytes(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deriver.Derive(nil, Identity{}); ErrorCodeOf(err) != ErrorCodeInvalidRequest { //nolint:staticcheck // Nil is the contract case.
		t.Fatalf("Derive(nil) error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := deriver.Derive(cancelled, Identity{}); ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("Derive(cancelled) error = %v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	if _, err := deriver.Derive(deadline, Identity{}); ErrorCodeOf(err) != ErrorCodeDeadlineExceeded {
		t.Fatalf("Derive(deadline) error = %v", err)
	}
	if _, err := deriver.Derive(context.Background(), Identity{}); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("Derive(zero identity) error = %v", err)
	}
}

// TestUseStorageKeyContainsCallbackFailuresAndRunsExactlyOnce verifies the protected capability boundary.
func TestUseStorageKeyContainsCallbackFailuresAndRunsExactlyOnce(t *testing.T) {
	key := mustTestKey(t)
	if !key.Valid() {
		t.Fatal("derived replay key reported invalid")
	}
	neverCalled := func(string) error { t.Fatal("invalid callback invoked"); return nil }
	if err := UseStorageKey(Key{}, neverCalled); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("UseStorageKey(zero) error = %v", err)
	}
	var forged Key
	forged.state = &keyState{}
	copy(forged.state.storage[:], []byte("TOXIC-NONZERO-BUT-INVALID-STORAGE-CAPABILITY"))
	if err := UseStorageKey(forged, neverCalled); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("UseStorageKey(forged) error = %v", err)
	}
	nonCanonical := key
	nonCanonical.state = &keyState{storage: key.state.storage}
	const rawURLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := len(nonCanonical.state.storage) - 1
	index := strings.IndexByte(rawURLAlphabet, nonCanonical.state.storage[last])
	if index < 0 || index&3 != 0 {
		t.Fatal("canonical key ended in an unexpected base64url symbol")
	}
	nonCanonical.state.storage[last] = rawURLAlphabet[index|1]
	if err := UseStorageKey(nonCanonical, neverCalled); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("UseStorageKey(noncanonical base64url) error = %v", err)
	}
	if err := UseStorageKey(key, nil); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("UseStorageKey(nil) error = %v", err)
	}
	typed := NewError(ErrorCodeUnavailable)
	calls := 0
	if err := UseStorageKey(key, func(string) error { calls++; return typed }); err != typed || calls != 1 {
		t.Fatalf("typed callback error was not passed through: %v", err)
	}
	var typedNil *Error
	for _, callbackErr := range []error{
		errors.New("TOXIC-RAW-CALLBACK"),
		fmt.Errorf("TOXIC-WRAPPED: %w", NewError(ErrorCodeUnavailable)),
		typedNil,
		hostileCallbackError{},
	} {
		calls = 0
		err := UseStorageKey(key, func(string) error { calls++; return callbackErr })
		if ErrorCodeOf(err) != ErrorCodeInternalInvariant || calls != 1 ||
			strings.Contains(err.Error(), "TOXIC") {
			t.Fatalf("callback error %T mapped to %v after %d calls", callbackErr, err, calls)
		}
	}
	calls = 0
	if err := UseStorageKey(key, func(string) error { calls++; panic("TOXIC-PANIC") }); ErrorCodeOf(err) != ErrorCodeInternalInvariant ||
		calls != 1 || strings.Contains(err.Error(), "TOXIC") {
		t.Fatalf("callback panic = %v", err)
	}
}

// TestDeriverCloseDrainsConcurrentAdmissionAndClearsOwnedSecret verifies close linearization.
func TestDeriverCloseDrainsConcurrentAdmissionAndClearsOwnedSecret(t *testing.T) {
	deriver, err := NewDeriver(sequenceBytes(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	identity := mustTestIdentity(t)
	deriver.state.beforeHMAC = make(chan struct{})
	deriver.state.continueHMAC = make(chan struct{})

	deriveDone := make(chan error, 1)
	go func() {
		_, deriveErr := deriver.Derive(context.Background(), identity)
		deriveDone <- deriveErr
	}()
	<-deriver.state.beforeHMAC

	closeContext, cancel := context.WithCancel(context.Background())
	closeDone := make(chan error, 1)
	go func() { closeDone <- deriver.Close(closeContext) }()
	for deriver.state.gate.State() != StoreClosing {
		runtime.Gosched()
	}
	cancel()
	if err := <-closeDone; ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("Close(cancelled drain) error = %v", err)
	}
	if _, err := deriver.Derive(context.Background(), identity); ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("derive during closing error = %v", err)
	}
	close(deriver.state.continueHMAC)
	if err := <-deriveDone; err != nil {
		t.Fatalf("admitted derive error = %v", err)
	}
	if err := deriver.Close(context.Background()); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if deriver.state.secret != ([32]byte{}) {
		t.Fatal("owned secret was not cleared")
	}
	if _, err := deriver.Derive(context.Background(), identity); ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("post-close derive error = %v", err)
	}
	if _, err := deriver.Derive(context.Background(), Identity{}); ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("post-close invalid derive precedence error = %v", err)
	}
}

// TestDeriverCloseContainsHostileContextState verifies no context panic or contradictory wake escapes.
func TestDeriverCloseContainsHostileContextState(t *testing.T) {
	for _, ctx := range []context.Context{
		hostileCloseContext{panicOnDone: true},
		hostileCloseContext{done: closedSignal()},
	} {
		deriver, err := NewDeriver(sequenceBytes(1), 1)
		if err != nil {
			t.Fatal(err)
		}
		deriver.state.beforeHMAC = make(chan struct{})
		deriver.state.continueHMAC = make(chan struct{})
		identity := mustTestIdentity(t)
		deriveDone := make(chan error, 1)
		go func() {
			_, deriveErr := deriver.Derive(context.Background(), identity)
			deriveDone <- deriveErr
		}()
		<-deriver.state.beforeHMAC
		if err := deriver.Close(ctx); ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("Close(%T) error = %v", ctx, err)
		}
		close(deriver.state.continueHMAC)
		if err := <-deriveDone; err != nil {
			t.Fatalf("Derive() cleanup error = %v", err)
		}
		if err := deriver.Close(context.Background()); err != nil {
			t.Fatalf("Close() cleanup error = %v", err)
		}
	}
}

// TestDeriverFormattingAndSerializationRemainContentFree verifies every reachable owner surface.
func TestDeriverFormattingAndSerializationRemainContentFree(t *testing.T) {
	secret := []byte("TOXIC-DERIVER-SECRET-1234567890!")
	deriver, err := NewDeriver(secret, 0x544f5849)
	if err != nil {
		t.Fatal(err)
	}
	value := *deriver
	surfaces := []any{
		deriver, value, any(deriver), any(value),
		[]*Deriver{deriver}, []Deriver{value},
		map[string]*Deriver{privacyDeriverMapKey: deriver},
		map[string]Deriver{privacyDeriverMapKey: value},
	}
	for _, surface := range surfaces {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%p", surface, surface, surface, surface, surface, surface, surface)
		if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "544f584943") ||
			strings.Contains(formatted, "84 79 88 73 67") {
			t.Fatal("deriver formatting exposed protected state")
		}
		encoded, marshalErr := json.Marshal(surface)
		if strings.Contains(string(encoded), "TOXIC") ||
			marshalErr != nil && strings.Contains(marshalErr.Error(), "TOXIC") {
			t.Fatal("deriver serialization exposed protected state")
		}
	}
}

// TestDeriverConcurrentDeriveAndCloseIsRaceSafe verifies concurrent admission has no panic or disclosure.
func TestDeriverConcurrentDeriveAndCloseIsRaceSafe(t *testing.T) {
	deriver, err := NewDeriver(sequenceBytes(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	identity := mustTestIdentity(t)
	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			_, deriveErr := deriver.Derive(context.Background(), identity)
			if deriveErr != nil && ErrorCodeOf(deriveErr) != ErrorCodeClosed {
				t.Errorf("Derive() error = %v", deriveErr)
			}
		})
	}
	if err := deriver.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wait.Wait()
}

// TestKeyAndDeriverFormattingNeverExposeProtectedMaterial verifies privacy matrices.
func TestKeyAndDeriverFormattingNeverExposeProtectedMaterial(t *testing.T) {
	secret := bytesWithText("TOXIC-DERIVER-SECRET-MARKER")
	deriver, err := NewDeriver(secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	key := mustTestKey(t)
	for _, value := range []any{
		key, &key, deriver, []*Deriver{deriver},
		map[string]*Deriver{privacyDeriverMapKey: deriver},
	} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", value, value, value, value, value, value)
		if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "544f584943") || strings.Contains(formatted, "84 79 88 73 67") {
			t.Fatalf("%T formatting exposed protected material: %q", value, formatted)
		}
		encoded, marshalErr := json.Marshal(value)
		if strings.Contains(string(encoded), "TOXIC") || strings.Contains(string(encoded), "VE9YSUM") {
			t.Fatalf("json.Marshal(%T) exposed protected material: %s, %v", value, encoded, marshalErr)
		}
	}
}

// TestKeyConstantsMatchFrozenAlgorithmAndStoredMarker verifies later providers consume one exact definition.
func TestKeyConstantsMatchFrozenAlgorithmAndStoredMarker(t *testing.T) {
	if KeyAlgorithm != "dkim2-replay-hmac-sha256-v1" {
		t.Fatalf("KeyAlgorithm = %q", KeyAlgorithm)
	}
	if StoredValue != "v1" || len(StoredValue) != 2 {
		t.Fatalf("StoredValue = %q (%d bytes)", StoredValue, len(StoredValue))
	}
}

type hostileCallbackError struct{}

// Error returns a synthetic raw marker that must not cross the callback boundary.
func (hostileCallbackError) Error() string { return "TOXIC-HOSTILE-CALLBACK" }

// As panics if classification traverses hostile error chains.
func (hostileCallbackError) As(any) bool { panic("TOXIC-HOSTILE-AS") }

type hostileCloseContext struct {
	done        <-chan struct{}
	panicOnDone bool
}

// Deadline reports no deadline.
func (hostileCloseContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done returns hostile channel state or panics at the wait boundary.
func (c hostileCloseContext) Done() <-chan struct{} {
	if c.panicOnDone {
		panic("TOXIC-HOSTILE-DONE")
	}
	return c.done
}

// Err contradictorily reports a live context.
func (hostileCloseContext) Err() error { return nil }

// Value reports no associated value.
func (hostileCloseContext) Value(any) any { return nil }

// closedSignal returns one already-closed context signal.
func closedSignal() <-chan struct{} {
	signal := make(chan struct{})
	close(signal)
	return signal
}

// sequenceBytes returns a deterministic 32-byte synthetic secret.
func sequenceBytes(start byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = start + byte(index)
	}
	return value
}

// sequenceDigest returns a deterministic 32-byte synthetic digest.
func sequenceDigest(start byte) [32]byte {
	var value [32]byte
	copy(value[:], sequenceBytes(start))
	return value
}

// bytesWithText returns one 32-byte buffer containing synthetic marker text.
func bytesWithText(text string) []byte {
	value := make([]byte, 32)
	copy(value, text)
	return value
}

// mustTestIdentity constructs one valid synthetic identity.
func mustTestIdentity(t *testing.T) Identity {
	t.Helper()
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		message: sequenceDigest(0), messagePresent: true,
		signature: sequenceDigest(32), signaturePresent: true,
		recipients: [][32]byte{sequenceDigest(64)},
	}
	set, err := NewIdentitySet(source)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// mustTestKey derives one valid protected storage key.
func mustTestKey(t *testing.T) Key {
	t.Helper()
	deriver, err := NewDeriver(sequenceBytes(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriver.Derive(context.Background(), mustTestIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// mustDerivedStorageKey derives and exposes one key only inside a synthetic test callback.
func mustDerivedStorageKey(t *testing.T, secret []byte, epoch uint32, source syntheticIdentitySource) string {
	t.Helper()
	set, err := NewIdentitySet(source)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	deriver, err := NewDeriver(secret, epoch)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	var storage string
	if err := UseStorageKey(key, func(value string) error {
		storage = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return storage
}
