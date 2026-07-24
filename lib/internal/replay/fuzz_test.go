package replay

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// FuzzReplayIdentityAndKey verifies complete identity construction and deterministic protected key derivation.
func FuzzReplayIdentityAndKey(f *testing.F) {
	f.Add([]byte("synthetic-identity"), uint8(1), uint8(0), uint32(1), false, false)
	f.Add([]byte("synthetic-duplicate"), uint8(2), uint8(4), uint32(1), false, true)
	f.Add([]byte("synthetic-order"), uint8(2), uint8(5), uint32(math.MaxUint32), false, false)
	f.Add([]byte("synthetic-empty"), uint8(0), uint8(6), uint32(1), false, false)
	f.Add([]byte("synthetic-secret"), uint8(8), uint8(0), uint32(0), false, true)
	f.Add([]byte("synthetic-zero"), uint8(8), uint8(0), uint32(1), true, true)

	f.Fuzz(func(t *testing.T, material []byte, countSeed, modeSeed uint8, epoch uint32, zeroSecret, exploded bool) {
		exerciseReplayIdentityAndKey(t, material, countSeed, modeSeed, epoch, zeroSecret, exploded)
	})
}

// exerciseReplayIdentityAndKey bounds material before constructing and checking one synthetic identity projection.
func exerciseReplayIdentityAndKey(
	t *testing.T,
	material []byte,
	countSeed, modeSeed uint8,
	epoch uint32,
	zeroSecret, exploded bool,
) {
	t.Helper()
	const maximumSyntheticMaterial = 256
	if len(material) > maximumSyntheticMaterial {
		return
	}

	source, count, mode := newFuzzIdentitySource(material, countSeed, modeSeed, exploded)
	set, err := NewIdentitySet(source)
	if mode != 0 {
		if set.Valid() || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
			t.Fatalf("identity contradiction mode=%d accepted with code=%q", mode, ErrorCodeOf(err))
		}
		return
	}
	if err != nil || !set.Valid() || set.Len() != count || set.Exploded() != exploded {
		t.Fatalf("valid identity set mode=%d count=%d code=%q", mode, count, ErrorCodeOf(err))
	}

	var secret [32]byte
	if !zeroSecret {
		secret = source.signature
		secret[0] |= 1
	}
	deriver, err := NewDeriver(secret[:], epoch)
	if zeroSecret || epoch == 0 {
		if deriver != nil || ErrorCodeOf(err) != ErrorCodeMisconfigured {
			t.Fatalf("invalid deriver configuration accepted with code=%q", ErrorCodeOf(err))
		}
		return
	}
	if err != nil || deriver == nil {
		t.Fatalf("valid deriver construction failed with code=%q", ErrorCodeOf(err))
	}
	assertFuzzDerivedKeys(t, deriver, set, count)
}

// newFuzzIdentitySource constructs one allocation-bounded valid or deliberately contradictory projection.
func newFuzzIdentitySource(
	material []byte,
	countSeed, modeSeed uint8,
	exploded bool,
) (syntheticIdentitySource, int, uint8) {
	mode := modeSeed % 7
	count := int(countSeed%8) + 1
	if mode == 6 {
		count = 0
	}
	if (mode == 4 || mode == 5) && count < 2 {
		count = 2
	}

	var message [32]byte
	var signature [32]byte
	for index := range message {
		if len(material) > 0 {
			message[index] = material[index%len(material)] ^ byte(index)
		} else {
			message[index] = byte(index)
		}
		signature[index] = message[index] ^ 0xa5
	}
	var recipients [8][32]byte
	for index := range count {
		recipients[index][0] = byte(index + 1)
		for offset := 1; offset < len(recipients[index]); offset++ {
			recipients[index][offset] = message[offset] ^ byte(index)
		}
	}
	if mode == 4 {
		recipients[1] = recipients[0]
	}
	if mode == 5 {
		recipients[0], recipients[1] = recipients[1], recipients[0]
	}

	source := syntheticIdentitySource{
		valid:            mode != 1,
		draft:            DraftIdentifier,
		message:          message,
		messagePresent:   mode != 2,
		signature:        signature,
		signaturePresent: mode != 3,
		recipients:       recipients[:count],
		exploded:         exploded,
	}
	if mode == 6 {
		source.recipients = nil
	}
	return source, count, mode
}

// assertFuzzDerivedKeys verifies deterministic, recipient-distinct keys and terminal deriver behavior.
func assertFuzzDerivedKeys(t *testing.T, deriver *Deriver, set IdentitySet, count int) {
	t.Helper()
	var previousStorage string
	for index := range count {
		identity, identityErr := set.Identity(index)
		if identityErr != nil || !identity.Valid() {
			t.Fatalf("identity index=%d unavailable with code=%q", index, ErrorCodeOf(identityErr))
		}
		key, deriveErr := deriver.Derive(context.Background(), identity)
		if deriveErr != nil {
			t.Fatalf("derive index=%d failed with code=%q", index, ErrorCodeOf(deriveErr))
		}
		repeated, repeatErr := deriver.Derive(context.Background(), identity)
		if repeatErr != nil || repeated != key {
			t.Fatalf("derive index=%d was nondeterministic with code=%q", index, ErrorCodeOf(repeatErr))
		}

		var storage string
		calls := 0
		if useErr := UseStorageKey(key, func(value string) error {
			calls++
			storage = value
			return nil
		}); useErr != nil || calls != 1 {
			t.Fatalf("protected key callback index=%d calls=%d code=%q", index, calls, ErrorCodeOf(useErr))
		}
		if len(storage) != storageKeyByteLength || !strings.HasPrefix(storage, keyNamespacePrefix) {
			t.Fatalf("derived key index=%d violated fixed grammar", index)
		}
		if index > 0 && storage == previousStorage {
			t.Fatalf("distinct recipient index=%d produced duplicate key", index)
		}
		previousStorage = storage
	}
	if key, deriveErr := deriver.Derive(context.Background(), Identity{}); key != (Key{}) ||
		ErrorCodeOf(deriveErr) != ErrorCodeInvalidRequest {
		t.Fatalf("invalid identity derive returned code=%q", ErrorCodeOf(deriveErr))
	}
	if closeErr := deriver.Close(context.Background()); closeErr != nil {
		t.Fatalf("deriver close failed with code=%q", ErrorCodeOf(closeErr))
	}
	if _, deriveErr := deriver.Derive(context.Background(), set.identities[0]); ErrorCodeOf(deriveErr) != ErrorCodeClosed {
		t.Fatalf("closed deriver returned code=%q", ErrorCodeOf(deriveErr))
	}
}

// FuzzReplayResultPair verifies that only coherent closed result and direct typed-error pairs are accepted.
func FuzzReplayResultPair(f *testing.F) {
	f.Add(uint8(CheckFirstSeen), uint8(0))
	f.Add(uint8(CheckReplayed), uint8(0))
	f.Add(uint8(CheckDisabled), uint8(0))
	f.Add(uint8(0), uint8(1))
	f.Add(uint8(CheckFirstSeen), uint8(1))
	f.Add(uint8(0), uint8(12))
	f.Add(uint8(255), uint8(13))

	f.Fuzz(func(t *testing.T, rawCheck, errorSeed uint8) {
		check := Check(rawCheck)
		var err error
		switch errorSeed % 14 {
		case 0:
		case 1:
			err = NewError(ErrorCodeInvalidRequest)
		case 2:
			err = NewError(ErrorCodeMisconfigured)
		case 3:
			err = NewError(ErrorCodeLimitExceeded)
		case 4:
			err = NewError(ErrorCodeUnavailable)
		case 5:
			err = NewError(ErrorCodeIndeterminate)
		case 6:
			err = NewError(ErrorCodeInconsistent)
		case 7:
			err = NewError(ErrorCodeCancelled)
		case 8:
			err = NewError(ErrorCodeDeadlineExceeded)
		case 9:
			err = NewError(ErrorCodeClosed)
		case 10:
			err = NewError(ErrorCodeInternalInvariant)
		case 11:
			err = errors.New("synthetic-untyped")
		case 12:
			err = fmt.Errorf("synthetic-wrapped: %w", NewError(ErrorCodeUnavailable))
		case 13:
			var typedNil *Error
			err = typedNil
		}

		expectedValid := err == nil && check.Known() ||
			err != nil && check == 0 && IsTypedError(err)
		validationErr := ValidateCheckOutcome(check, err)
		if expectedValid {
			if validationErr != nil {
				t.Fatalf("coherent pair check=%s error_kind=%d rejected", check, errorSeed%14)
			}
			return
		}
		if ErrorCodeOf(validationErr) != ErrorCodeInternalInvariant {
			t.Fatalf("contradictory pair check=%s error_kind=%d returned code=%q",
				check, errorSeed%14, ErrorCodeOf(validationErr))
		}
	})
}

// FuzzMemoryStateSequence verifies bounded sequential replay, expiry, validation, and close transitions.
func FuzzMemoryStateSequence(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0x60, 0})
	f.Add([]byte{0, 0x7c, 0})
	f.Add([]byte{0, 0x80, 0, 0xc0, 0})
	f.Add([]byte{0xa0, 0, 0xe0, 0xc0})

	f.Fuzz(func(t *testing.T, operations []byte) {
		exerciseMemoryStateSequence(t, operations)
	})
}

// exerciseMemoryStateSequence bounds an operation stream before constructing and checking one memory provider.
func exerciseMemoryStateSequence(t *testing.T, operations []byte) {
	t.Helper()
	const maximumOperations = 64
	if len(operations) > maximumOperations {
		return
	}

	now := time.Unix(1_700_000_000, 0)
	clock := newTestClock(now)
	store := newTestMemoryStore(t, Limits{MaxEntries: 4, MaxWaiters: 1, PruneBudget: 4}, clock)
	var expiries [4]time.Time
	closed := false

	for step, operation := range operations {
		kind := operation >> 5
		keyIndex := int(operation & 3)
		retentionDuration := time.Duration(((operation>>2)&7)+1) * time.Second
		retention := mustRetention(t, retentionDuration)

		switch kind {
		case 3:
			now = now.Add(time.Duration((operation>>2)&7) * time.Second)
			clock.Set(now)
		case 4:
			assertFuzzMemoryInvalidCheck(t, store, Key{}, retention, closed, step)
		case 5:
			assertFuzzMemoryInvalidCheck(t, store, testReplayKey(byte(keyIndex)), Retention{}, closed, step)
		case 6:
			if err := store.Close(context.Background()); err != nil {
				t.Fatalf("step=%d close code=%q", step, ErrorCodeOf(err))
			}
			closed = true
			expiries = [4]time.Time{}
		default:
			assertFuzzMemoryCheck(
				t,
				store,
				now,
				&expiries,
				keyIndex,
				retention,
				retentionDuration,
				closed,
				step,
			)
		}
		assertFuzzMemoryModel(t, store, expiries, closed, step)
	}

	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("final close code=%q", ErrorCodeOf(err))
	}
	if store.State() != StoreClosed {
		t.Fatalf("final state=%s", store.State())
	}
	if entries, nodes := store.testCounts(); entries != 0 || nodes != 0 {
		t.Fatalf("final ownership=%d/%d", entries, nodes)
	}
}

// assertFuzzMemoryInvalidCheck verifies validation precedence without mutating the model.
func assertFuzzMemoryInvalidCheck(
	t *testing.T,
	store *MemoryStore,
	key Key,
	retention Retention,
	closed bool,
	step int,
) {
	t.Helper()
	check, err := store.CheckAndRemember(context.Background(), key, retention)
	want := ErrorCodeInvalidRequest
	if closed {
		want = ErrorCodeClosed
	}
	if check != 0 || ErrorCodeOf(err) != want {
		t.Fatalf("step=%d invalid request result=%s code=%q want=%q", step, check, ErrorCodeOf(err), want)
	}
}

// assertFuzzMemoryCheck applies one valid request and verifies replay, expiry, and no-extension behavior.
func assertFuzzMemoryCheck(
	t *testing.T,
	store *MemoryStore,
	now time.Time,
	expiries *[4]time.Time,
	keyIndex int,
	retention Retention,
	retentionDuration time.Duration,
	closed bool,
	step int,
) {
	t.Helper()
	check, err := store.CheckAndRemember(
		context.Background(),
		testReplayKey(byte(keyIndex)),
		retention,
	)
	if validationErr := ValidateCheckOutcome(check, err); validationErr != nil {
		t.Fatalf("step=%d incoherent memory pair code=%q", step, ErrorCodeOf(validationErr))
	}
	if closed {
		if check != 0 || ErrorCodeOf(err) != ErrorCodeClosed {
			t.Fatalf("step=%d post-close result=%s code=%q", step, check, ErrorCodeOf(err))
		}
		return
	}

	for index, expiry := range expiries {
		if !expiry.IsZero() && !expiry.After(now) {
			expiries[index] = time.Time{}
		}
	}
	want := CheckReplayed
	if expiries[keyIndex].IsZero() {
		want = CheckFirstSeen
		expiries[keyIndex] = now.Add(retentionDuration)
	}
	if err != nil || check != want {
		t.Fatalf("step=%d key=%d result=%s code=%q want=%s",
			step, keyIndex, check, ErrorCodeOf(err), want)
	}
	if expiry := store.testExpiry(testReplayKey(byte(keyIndex))); !expiry.Equal(expiries[keyIndex]) {
		t.Fatalf("step=%d key=%d expiry changed unexpectedly", step, keyIndex)
	}
}

// assertFuzzMemoryModel verifies lifecycle and one-to-one heap ownership after each operation.
func assertFuzzMemoryModel(
	t *testing.T,
	store *MemoryStore,
	expiries [4]time.Time,
	closed bool,
	step int,
) {
	t.Helper()
	if closed {
		if store.State() != StoreClosed {
			t.Fatalf("step=%d terminal state=%s", step, store.State())
		}
	} else if store.State() != StoreReady {
		t.Fatalf("step=%d operational state=%s", step, store.State())
	}
	assertMemoryInvariant(t, store)
	entries, nodes := store.testCounts()
	wantEntries := 0
	for _, expiry := range expiries {
		if !expiry.IsZero() {
			wantEntries++
		}
	}
	if entries != wantEntries || nodes != wantEntries {
		t.Fatalf("step=%d ownership=%d/%d want=%d", step, entries, nodes, wantEntries)
	}
}

// FuzzReplayRetention verifies exact millisecond conversion and bounded expiry overflow classification.
func FuzzReplayRetention(f *testing.F) {
	f.Add(int64(time.Second), int64(1_700_000_000), uint32(0))
	f.Add(int64(time.Second-time.Nanosecond), int64(1_700_000_000), uint32(0))
	f.Add(int64(maximumRetentionDuration), int64(1_700_000_000), uint32(999_999_999))
	f.Add(int64(maximumRetentionDuration+time.Millisecond), int64(1_700_000_000), uint32(0))
	f.Add(int64(time.Second), int64(math.MaxInt64), uint32(999_999_999))
	f.Add(int64(time.Second), int64(-62_135_596_800), uint32(0))

	f.Fuzz(func(t *testing.T, rawDuration, nowSeconds int64, rawNanoseconds uint32) {
		duration := time.Duration(rawDuration)
		retention, err := NewRetention(duration)
		validDuration := duration >= minimumRetentionDuration &&
			duration <= maximumRetentionDuration &&
			duration%time.Millisecond == 0
		if !validDuration {
			if retention != (Retention{}) || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
				t.Fatalf("invalid duration class returned code=%q", ErrorCodeOf(err))
			}
			return
		}
		if err != nil || !retention.Valid() || retention.Duration() != duration ||
			retention.Milliseconds() != int64(duration/time.Millisecond) {
			t.Fatalf("valid duration class returned code=%q", ErrorCodeOf(err))
		}

		nanoseconds := int64(rawNanoseconds % uint32(time.Second))
		now := time.Unix(nowSeconds, nanoseconds)
		expiry, addErr := retention.AddTo(now)
		addSeconds := int64(duration / time.Second)
		if int64(now.Nanosecond())+int64(duration%time.Second) >= int64(time.Second) {
			addSeconds++
		}
		overflow := now.Unix() > math.MaxInt64-addSeconds
		if now.IsZero() || overflow {
			if !expiry.IsZero() || ErrorCodeOf(addErr) != ErrorCodeInternalInvariant {
				t.Fatalf("overflow class returned code=%q", ErrorCodeOf(addErr))
			}
			return
		}
		if addErr != nil || !expiry.After(now) || expiry.Sub(now) != duration {
			t.Fatalf("exact addition returned code=%q", ErrorCodeOf(addErr))
		}
	})
}
