package dkim2

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/service"
)

const (
	replayMethodCheckAndRemember = "CheckAndRemember"
	replayMethodClose            = "Close"
	replayMethodFormat           = "Format"
	replayMethodGoString         = "GoString"
	replayMethodKnown            = "Known"
	replayMethodMarshalJSON      = "MarshalJSON"
	replayMethodMarshalText      = "MarshalText"
	replayMethodNow              = "Now"
	replayMethodState            = "State"
	replayMethodString           = "String"
	replayMethodValid            = "Valid"
	replayDisabledText           = "disabled"
	replayPrivacyDeriverMapKey   = "deriver"
)

// TestReplayFacadeTransfersOnlyAuthenticCurrentPass verifies the sealed service-to-root bridge.
func TestReplayFacadeTransfersOnlyAuthenticCurrentPass(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicReplayMessage(t, timestamp, [][]byte{[]byte("<rcpt@example.test>")})
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	coordinator := serviceVerifierForTest(t, verifier)
	serviceResult, err := coordinator.Verify(
		context.Background(),
		service.NewRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
	)
	if err != nil {
		t.Fatalf("service Verify() error = %v", err)
	}
	policySeamResult := adaptServiceResultWithProjection(serviceResult, serviceResult.PolicyProjection())
	if set, replayErr := ReplayIdentities(policySeamResult); set.Valid() ||
		ReplayErrorCodeOf(replayErr) != ReplayErrorInvalidRequest {
		t.Fatalf("policy-only adapter transferred replay provenance: valid=%t error=%v", set.Valid(), replayErr)
	}
	if set, replayErr := ReplayIdentities(adaptServiceResult(serviceResult)); replayErr != nil || !set.Valid() {
		t.Fatalf("authoritative adapter lost replay provenance: valid=%t error=%v", set.Valid(), replayErr)
	}

	result, err := verifier.Verify(
		context.Background(),
		NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
	)
	if err != nil || result.State() != ResultStatePASS {
		t.Fatalf("Verify() state=%q error=%v", result.State(), err)
	}

	assertReplayIdentitySet(t, result, 1)
	copied := result
	assertReplayIdentitySet(t, copied, 1)

	for name, mutate := range map[string]func(*VerifyResult){
		"fail": func(candidate *VerifyResult) {
			candidate.state = candidate.cloneState()
			candidate.state.resultState = ResultStateFAIL
		},
		"permerror": func(candidate *VerifyResult) {
			candidate.state = candidate.cloneState()
			candidate.state.resultState = ResultStatePERMERROR
		},
		"wrong scope": func(candidate *VerifyResult) {
			candidate.state = candidate.cloneState()
			candidate.state.scope = ""
		},
		"historical content": func(candidate *VerifyResult) {
			candidate.state = candidate.cloneState()
			candidate.state.historicalContent = ""
		},
		"missing projection": func(candidate *VerifyResult) {
			candidate.state = candidate.cloneState()
			candidate.state.hasReplayProjection = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := result
			mutate(&candidate)
			set, replayErr := ReplayIdentities(candidate)
			if set.Valid() || ReplayErrorCodeOf(replayErr) != ReplayErrorInvalidRequest {
				t.Fatalf("ReplayIdentities(mutated) valid=%t error=%v", set.Valid(), replayErr)
			}
		})
	}
}

// TestReplayFacadeRejectsZeroAndCallerComposedPass verifies public facts cannot forge provenance.
func TestReplayFacadeRejectsZeroAndCallerComposedPass(t *testing.T) {
	for _, result := range []VerifyResult{
		{},
		newVerifyResult(verifyResultData{
			state: ResultStatePASS, scope: VerificationScopeCurrent,
			historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
			custodyStructure: CustodyStructureNotPresent, target: newVerificationTarget(1, 1),
			primaryReason: ReasonNone,
			checks:        []CheckFact{newCheckFact(CheckClassSignature, ReasonNone)},
			signatures:    []SignatureSetFact{newSignatureSetFact(AlgorithmRSASHA256, SignatureStatusPASS, ReasonNone)},
		}),
		internalContractResult(newVerificationTarget(1, 1)),
	} {
		set, err := ReplayIdentities(result)
		if set.Valid() || set.Len() != 0 || set.Exploded() ||
			ReplayErrorCodeOf(err) != ReplayErrorInvalidRequest {
			t.Fatalf("ReplayIdentities(%q) valid=%t len=%d exploded=%t error=%v",
				result.State(), set.Valid(), set.Len(), set.Exploded(), err)
		}
		if identity, identityErr := set.Identity(0); identity.Valid() ||
			ReplayErrorCodeOf(identityErr) != ReplayErrorInvalidRequest {
			t.Fatalf("zero set Identity(0) valid=%t error=%v", identity.Valid(), identityErr)
		}
	}
}

// TestReplayFacadePreservesExplodedAndEveryRecipient verifies exact root set facts.
func TestReplayFacadePreservesExplodedAndEveryRecipient(t *testing.T) {
	const timestamp = int64(1700000000)
	flaggedRaw, flaggedKey := signedPublicFlaggedPolicyMessage(t, timestamp)
	flagged := verifyReplayFixture(
		t,
		flaggedRaw,
		flaggedKey,
		timestamp,
		[][]byte{[]byte("<rcpt@example.test>")},
	)
	flaggedSet, err := ReplayIdentities(flagged)
	if err != nil || !flaggedSet.Valid() || flaggedSet.Len() != 1 || !flaggedSet.Exploded() {
		t.Fatalf("flagged set valid=%t len=%d exploded=%t error=%v",
			flaggedSet.Valid(), flaggedSet.Len(), flaggedSet.Exploded(), err)
	}

	recipients := [][]byte{
		[]byte("<first@example.test>"),
		[]byte("<second@example.test>"),
	}
	raw, key := signedPublicReplayMessage(t, timestamp, recipients)
	result := verifyReplayFixture(t, raw, key, timestamp, recipients)
	set, err := ReplayIdentities(result)
	if err != nil || !set.Valid() || set.Len() != 2 || set.Exploded() {
		t.Fatalf("two-recipient set valid=%t len=%d exploded=%t error=%v",
			set.Valid(), set.Len(), set.Exploded(), err)
	}
	first, firstErr := set.Identity(0)
	second, secondErr := set.Identity(1)
	if firstErr != nil || secondErr != nil || !first.Valid() || !second.Valid() || first == second {
		t.Fatalf("two-recipient identities valid=%t/%t equal=%t errors=%v/%v",
			first.Valid(), second.Valid(), first == second, firstErr, secondErr)
	}
}

// TestReplayFacadeContractSurfaceIsExact verifies aliases expose no extra behavior.
func TestReplayFacadeContractSurfaceIsExact(t *testing.T) {
	storeType := reflect.TypeFor[ReplayStore]()
	managedType := reflect.TypeFor[ManagedReplayStore]()
	assertExactReplayMethods(t, storeType, []string{replayMethodCheckAndRemember})
	assertExactReplayMethods(t, managedType, []string{replayMethodCheckAndRemember, replayMethodClose, replayMethodState})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayCheck](), []string{
		replayMethodFormat, replayMethodGoString, replayMethodKnown, replayMethodMarshalJSON, replayMethodMarshalText, replayMethodString,
	})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayStoreState](), []string{
		replayMethodFormat, replayMethodGoString, replayMethodKnown, replayMethodMarshalJSON, replayMethodMarshalText, replayMethodString,
	})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayErrorCode](), []string{
		replayMethodFormat, replayMethodGoString, replayMethodKnown, replayMethodMarshalJSON, replayMethodMarshalText, replayMethodString,
	})
	assertExactReplayMethods(t, reflect.TypeFor[*ReplayError](), []string{
		"Code", "Error", replayMethodFormat, replayMethodGoString,
		replayMethodMarshalJSON, replayMethodMarshalText, "Unwrap",
	})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayRetention](), []string{
		"AddTo", "Duration", "Milliseconds", replayMethodValid,
	})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayLimits](), []string{"Validate"})
	clockType := reflect.TypeFor[ReplayClock]()
	assertExactReplayMethods(t, clockType, []string{replayMethodNow})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayClockFunc](), []string{replayMethodNow})
	assertExactReplayMethodSignature(
		t,
		storeType,
		replayMethodCheckAndRemember,
		reflect.TypeFor[func(context.Context, ReplayKey, ReplayRetention) (ReplayCheck, error)](),
	)
	assertExactReplayMethodSignature(
		t,
		managedType,
		replayMethodClose,
		reflect.TypeFor[func(context.Context) error](),
	)
	assertExactReplayMethodSignature(
		t,
		managedType,
		replayMethodState,
		reflect.TypeFor[func() ReplayStoreState](),
	)
	assertExactReplayMethodSignature(
		t,
		clockType,
		replayMethodNow,
		reflect.TypeFor[func() time.Time](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(result VerifyResult) (ReplayIdentitySet, error)](),
		reflect.TypeFor[func(VerifyResult) (ReplayIdentitySet, error)](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(code ReplayErrorCode) error](),
		reflect.TypeFor[func(ReplayErrorCode) error](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(err error) ReplayErrorCode](),
		reflect.TypeFor[func(error) ReplayErrorCode](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(err error) bool](),
		reflect.TypeFor[func(error) bool](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(duration time.Duration) (ReplayRetention, error)](),
		reflect.TypeFor[func(time.Duration) (ReplayRetention, error)](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func() ReplayRetention](),
		reflect.TypeFor[func() ReplayRetention](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(secret []byte, epoch uint32) (*ReplayDeriver, error)](),
		reflect.TypeFor[func([]byte, uint32) (*ReplayDeriver, error)](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(config ReplayMemoryConfig) (*ReplayMemoryStore, error)](),
		reflect.TypeFor[func(ReplayMemoryConfig) (*ReplayMemoryStore, error)](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func() *ReplayDisabledStore](),
		reflect.TypeFor[func() *ReplayDisabledStore](),
	)
	assertExactReplayFunction(
		t,
		reflect.TypeFor[func(key ReplayKey, use func(storageKey string) error) error](),
		reflect.TypeFor[func(ReplayKey, func(string) error) error](),
	)
	assertExactReplayMethods(t, reflect.TypeFor[ReplayIdentity](), []string{
		replayMethodFormat, replayMethodGoString, replayMethodString, replayMethodValid,
	})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayIdentitySet](), []string{
		"Exploded", replayMethodFormat, replayMethodGoString, "Identity", "Len", replayMethodString, replayMethodValid,
	})
	assertExactReplayMethods(t, reflect.TypeFor[ReplayKey](), []string{
		replayMethodFormat, replayMethodGoString, replayMethodMarshalJSON, replayMethodMarshalText,
		replayMethodString, replayMethodValid,
	})
	assertExactReplayMethods(t, reflect.TypeFor[*ReplayDeriver](), []string{
		replayMethodClose, "Derive", replayMethodFormat, replayMethodGoString, replayMethodString,
	})
	assertExactReplayMethods(t, reflect.TypeFor[*ReplayMemoryStore](), []string{
		replayMethodCheckAndRemember, replayMethodClose, replayMethodFormat, replayMethodGoString,
		replayMethodMarshalJSON, replayMethodMarshalText, replayMethodState, replayMethodString,
	})
	assertExactReplayMethods(t, reflect.TypeFor[*ReplayDisabledStore](), []string{
		replayMethodCheckAndRemember, replayMethodClose, replayMethodFormat, replayMethodGoString,
		replayMethodMarshalJSON, replayMethodMarshalText, replayMethodState, replayMethodString,
	})
	configType := reflect.TypeFor[ReplayMemoryConfig]()
	if configType.NumMethod() != 0 || reflect.PointerTo(configType).NumMethod() != 0 {
		t.Fatal("ReplayMemoryConfig exposes methods")
	}
	assertExactReplayFields(t, configType, []replayFieldExpectation{
		{name: "Limits", fieldType: reflect.TypeFor[ReplayLimits]()},
		{name: "Clock", fieldType: reflect.TypeFor[ReplayClock]()},
	})
	assertExactReplayFields(t, reflect.TypeFor[ReplayLimits](), []replayFieldExpectation{
		{name: "MaxEntries", fieldType: reflect.TypeFor[int]()},
		{name: "MaxWaiters", fieldType: reflect.TypeFor[int]()},
		{name: "PruneBudget", fieldType: reflect.TypeFor[int]()},
		{name: "MaxInFlight", fieldType: reflect.TypeFor[int]()},
		{name: "MaxAdmissionWaiters", fieldType: reflect.TypeFor[int]()},
	})
	for _, protected := range []reflect.Type{
		reflect.TypeFor[ReplayKey](),
		reflect.TypeFor[ReplayError](),
		reflect.TypeFor[ReplayRetention](),
		reflect.TypeFor[ReplayIdentity](),
		reflect.TypeFor[ReplayIdentitySet](),
		reflect.TypeFor[ReplayDeriver](),
		reflect.TypeFor[ReplayMemoryStore](),
		reflect.TypeFor[ReplayDisabledStore](),
	} {
		assertNoExportedReplayFields(t, protected)
	}
	if ReplayCheckFirstSeen.String() != "first_seen" ||
		ReplayCheckReplayed.String() != "replayed" ||
		ReplayCheckDisabled.String() != replayDisabledText {
		t.Fatal("root replay checks diverged from the closed core vocabulary")
	}
	if ReplayStoreReady.String() != "ready" || ReplayStoreDegraded.String() != "degraded" ||
		ReplayStoreDisabled.String() != replayDisabledText || ReplayStoreClosing.String() != "closing" ||
		ReplayStoreClosed.String() != "closed" {
		t.Fatal("root replay states diverged from the closed core vocabulary")
	}
	if ReplayKeyAlgorithm != "dkim2-replay-hmac-sha256-v1" || ReplayStoredValue != "v1" {
		t.Fatalf("root replay constants = %q/%q", ReplayKeyAlgorithm, ReplayStoredValue)
	}
}

// TestReplayFacadeConstructorsDelegateClosedCoreBehavior verifies exact wrappers.
func TestReplayFacadeConstructorsDelegateClosedCoreBehavior(t *testing.T) {
	if got := ReplayErrorCodeOf(NewReplayError(ReplayErrorUnavailable)); got != ReplayErrorUnavailable {
		t.Fatalf("NewReplayError() code = %q", got)
	}
	if retention, err := NewReplayRetention(time.Second); err != nil || !retention.Valid() {
		t.Fatalf("NewReplayRetention() = %#v, %v", retention, err)
	}
	if !DefaultReplayRetention().Valid() {
		t.Fatal("DefaultReplayRetention() is invalid")
	}
	if _, err := NewReplayDeriver(make([]byte, 32), 1); ReplayErrorCodeOf(err) != ReplayErrorMisconfigured {
		t.Fatalf("NewReplayDeriver(all-zero) error = %v", err)
	}

	var clock *typedNilReplayClock
	if store, err := NewReplayMemoryStore(ReplayMemoryConfig{Clock: clock}); store != nil ||
		ReplayErrorCodeOf(err) != ReplayErrorMisconfigured {
		t.Fatalf("NewReplayMemoryStore(typed nil) = %v, %v", store, err)
	}
	disabled := NewReplayDisabledStore()
	var _ ReplayStore = disabled
	var _ ManagedReplayStore = disabled
	if check, err := disabled.CheckAndRemember(context.Background(), ReplayKey{}, ReplayRetention{}); err != nil || check != ReplayCheckDisabled {
		t.Fatalf("disabled CheckAndRemember() = %q, %v", check, err)
	}

	set := authenticReplayIdentitySet(t)
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	secret := syntheticReplaySecret()
	deriver, err := NewReplayDeriver(secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := deriver.Close(context.Background()); closeErr != nil {
			t.Error("replay deriver cleanup failed")
		}
	})
	key, err := deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Valid() || (ReplayKey{}).Valid() {
		t.Fatal("public replay key validity diverged from protected grammar")
	}
	store, err := NewReplayMemoryStore(ReplayMemoryConfig{
		Clock: ReplayClockFunc(func() time.Time { return time.Unix(1, 0) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	retention := DefaultReplayRetention()
	if check, checkErr := store.CheckAndRemember(context.Background(), key, retention); checkErr != nil || check != ReplayCheckFirstSeen {
		t.Fatalf("memory first check=%q error=%v", check, checkErr)
	}
	if check, checkErr := store.CheckAndRemember(context.Background(), key, retention); checkErr != nil || check != ReplayCheckReplayed {
		t.Fatalf("memory replay check=%q error=%v", check, checkErr)
	}
	if err := store.Close(context.Background()); err != nil || store.State() != ReplayStoreClosed {
		t.Fatalf("memory close state=%q error=%v", store.State(), err)
	}
}

// TestUseReplayStorageKeyContainsCallbackFailures verifies the protected exact-once seam.
func TestUseReplayStorageKeyContainsCallbackFailures(t *testing.T) {
	set := authenticReplayIdentitySet(t)
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	secret := syntheticReplaySecret()
	deriver, err := NewReplayDeriver(secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	if err := UseReplayStorageKey(key, func(storageKey string) error {
		calls++
		if len(storageKey) != 68 {
			t.Fatal("protected storage key has the wrong fixed length")
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("UseReplayStorageKey() calls=%d error=%v", calls, err)
	}
	if code := ReplayErrorCodeOf(UseReplayStorageKey(ReplayKey{}, func(string) error {
		t.Fatal("invalid key callback ran")
		return nil
	})); code != ReplayErrorInvalidRequest {
		t.Fatalf("zero key code = %q", code)
	}
	if code := ReplayErrorCodeOf(UseReplayStorageKey(key, nil)); code != ReplayErrorInvalidRequest {
		t.Fatalf("nil callback code = %q", code)
	}

	var typedNil *ReplayError
	for name, callback := range map[string]func(string) error{
		"panic": func(string) error { panic("protected callback panic") },
		"plain error": func(string) error {
			return errors.New("protected callback failure marker")
		},
		"wrapped": func(string) error {
			return fmt.Errorf("protected wrapped callback marker: %w", NewReplayError(ReplayErrorUnavailable))
		},
		"typed nil": func(string) error { return typedNil },
	} {
		t.Run(name, func(t *testing.T) {
			if code := ReplayErrorCodeOf(UseReplayStorageKey(key, callback)); code != ReplayErrorInternalInvariant {
				t.Fatalf("UseReplayStorageKey(%s) code = %q", name, code)
			}
		})
	}
	typed := NewReplayError(ReplayErrorUnavailable)
	if got := UseReplayStorageKey(key, func(string) error { return typed }); got != typed {
		t.Fatalf("typed callback error identity changed: got=%v want=%v", got, typed)
	}
}

// TestReplayFacadePrivacyCoversNestedAndContainerSurfaces verifies no protected facts are traversed.
func TestReplayFacadePrivacyCoversNestedAndContainerSurfaces(t *testing.T) {
	result := authenticReplayResult(t)
	resultFormatted := fmt.Sprintf("%v|%+v|%#v", result, result, result)
	if strings.Count(resultFormatted, verifyResultRedactedText) != 3 {
		t.Fatalf("VerifyResult formatting=%q", resultFormatted)
	}
	set, err := ReplayIdentities(result)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	secret := syntheticReplaySecret()
	deriver, err := NewReplayDeriver(secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := deriver.Close(context.Background()); closeErr != nil {
			t.Error("replay deriver cleanup failed")
		}
	})
	key, err := deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := NewReplayMemoryStore(ReplayMemoryConfig{
		Clock: ReplayClockFunc(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := memory.Close(context.Background()); closeErr != nil {
			t.Error("replay memory cleanup failed")
		}
	})
	if check, checkErr := memory.CheckAndRemember(
		context.Background(),
		key,
		DefaultReplayRetention(),
	); checkErr != nil || check != ReplayCheckFirstSeen {
		t.Fatal("memory store did not retain the protected replay key")
	}
	disabled := NewReplayDisabledStore()
	t.Cleanup(func() {
		if closeErr := disabled.Close(context.Background()); closeErr != nil {
			t.Error("replay disabled cleanup failed")
		}
	})
	deriverValue := *deriver
	memoryValue := *memory
	disabledValue := *disabled
	var storage string
	if err := UseReplayStorageKey(key, func(value string) error {
		storage = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	values := []any{
		result, &result, []VerifyResult{result}, map[string]VerifyResult{"result": result},
		set, &set, []ReplayIdentitySet{set}, map[string]ReplayIdentitySet{"set": set},
		identity, &identity, []ReplayIdentity{identity},
		key, &key, []ReplayKey{key}, map[ReplayKey]struct{}{key: {}},
		deriver, deriverValue, any(deriverValue), []ReplayDeriver{deriverValue},
		map[string]ReplayDeriver{replayPrivacyDeriverMapKey: deriverValue},
		memory, memoryValue, any(memoryValue), []ReplayMemoryStore{memoryValue},
		map[string]ReplayMemoryStore{"memory": memoryValue},
		disabled, disabledValue, any(disabledValue), []ReplayDisabledStore{disabledValue},
		map[string]ReplayDisabledStore{replayDisabledText: disabledValue},
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%X|%p", value, value, value, value, value, value, value, value)
		for _, forbidden := range []string{
			"draft-ietf-dkim-dkim2-spec-04", "rcpt@example.test",
			"dkim2:replay:v1:", storage, fmt.Sprintf("%x", storage),
			fmt.Sprintf("%x", secret), "01020304", "protected callback failure marker",
		} {
			if forbidden != "" && strings.Contains(formatted, forbidden) {
				t.Fatal("public replay formatting exposed protected material")
			}
		}
		encoded, marshalErr := json.Marshal(value)
		if strings.Contains(string(encoded), storage) ||
			marshalErr != nil && strings.Contains(marshalErr.Error(), storage) {
			t.Fatal("public replay JSON serialization exposed protected material")
		}
		if textMarshaler, ok := value.(encoding.TextMarshaler); ok {
			text, textErr := textMarshaler.MarshalText()
			if strings.Contains(string(text), storage) ||
				textErr != nil && strings.Contains(textErr.Error(), storage) {
				t.Fatal("public replay text serialization exposed protected material")
			}
		}
	}
}

// assertReplayIdentitySet verifies the exact immutable public set behavior.
func assertReplayIdentitySet(t *testing.T, result VerifyResult, want int) {
	t.Helper()
	set, err := ReplayIdentities(result)
	if err != nil || !set.Valid() || set.Len() != want {
		t.Fatalf("ReplayIdentities() valid=%t len=%d error=%v", set.Valid(), set.Len(), err)
	}
	for index := range want {
		identity, identityErr := set.Identity(index)
		if identityErr != nil || !identity.Valid() {
			t.Fatalf("Identity(%d) valid=%t error=%v", index, identity.Valid(), identityErr)
		}
	}
	if identity, identityErr := set.Identity(want); identity.Valid() ||
		ReplayErrorCodeOf(identityErr) != ReplayErrorInvalidRequest {
		t.Fatalf("Identity(out of range) valid=%t error=%v", identity.Valid(), identityErr)
	}
}

// authenticReplayResult verifies one signed fixture through the complete public facade.
func authenticReplayResult(t *testing.T) VerifyResult {
	t.Helper()
	const timestamp = int64(1700000000)
	raw, key := signedPublicReplayMessage(t, timestamp, [][]byte{[]byte("<rcpt@example.test>")})
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(
		context.Background(),
		NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
	)
	if err != nil || result.State() != ResultStatePASS {
		t.Fatalf("Verify() state=%q error=%v", result.State(), err)
	}
	return result
}

// verifyReplayFixture verifies one signed synthetic fixture through the root facade.
func verifyReplayFixture(
	t *testing.T,
	raw []byte,
	key *rsa.PublicKey,
	timestamp int64,
	recipients [][]byte,
) VerifyResult {
	t.Helper()
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(
		context.Background(),
		NewVerifyRequest(raw, []byte("<>"), recipients),
	)
	if err != nil || result.State() != ResultStatePASS {
		t.Fatalf("Verify() state=%q error=%v", result.State(), err)
	}
	return result
}

// signedPublicReplayMessage creates one passing synthetic fixture with exact recipients.
func signedPublicReplayMessage(
	t testing.TB,
	timestamp int64,
	recipients [][]byte,
) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: replay facade\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	encodedRecipients := make([]string, len(recipients))
	for index, recipient := range recipients {
		encodedRecipients[index] = base64.StdEncoding.EncodeToString(recipient)
	}
	build := func(signature string) string {
		return "From: sender@example.test\r\nSubject: replay facade\r\n" +
			"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n" +
			"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatInt(timestamp, 10) +
			"; mf=PD4=; rt=" + strings.Join(encodedRecipients, ",") +
			"; d=example.test; s=selector.test:rsa-sha256:" + signature + ";\r\n\r\nbody line\r\n"
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsigned, err := rawmsg.Parse([]byte(build(placeholder)))
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers: unsigned.Headers(), TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	sealed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return []byte(build(base64.StdEncoding.EncodeToString(sealed))), &key.PublicKey
}

// authenticReplayIdentitySet constructs one public set only from an authentic PASS result.
func authenticReplayIdentitySet(t *testing.T) ReplayIdentitySet {
	t.Helper()
	set, err := ReplayIdentities(authenticReplayResult(t))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// typedNilReplayClock supplies a practical typed-nil constructor dependency.
type typedNilReplayClock struct{}

// Now returns a deterministic value when called on a non-nil clock.
func (*typedNilReplayClock) Now() time.Time { return time.Unix(1, 0) }

// syntheticReplaySecret returns one published non-production fixed secret.
func syntheticReplaySecret() []byte {
	secret := make([]byte, 32)
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	return secret
}

// assertExactReplayMethods proves one public alias exposes no additional behavior.
func assertExactReplayMethods(t *testing.T, value reflect.Type, want []string) {
	t.Helper()
	if value.NumMethod() != len(want) {
		t.Fatalf("%s methods=%d, want %d", value, value.NumMethod(), len(want))
	}
	for index, name := range want {
		method := value.Method(index)
		if method.Name != name {
			t.Fatalf("%s method[%d]=%q, want %q", value, index, method.Name, name)
		}
	}
}

// assertExactReplayMethodSignature proves one interface method has no widening.
func assertExactReplayMethodSignature(t *testing.T, owner reflect.Type, name string, want reflect.Type) {
	t.Helper()
	method, present := owner.MethodByName(name)
	if !present || method.Type != want {
		t.Fatalf("%s.%s signature=%v, want %v", owner, name, method.Type, want)
	}
}

// assertExactReplayFunction proves one facade function has no widening.
func assertExactReplayFunction(t *testing.T, got, want reflect.Type) {
	t.Helper()
	if got != want || got.IsVariadic() {
		t.Fatalf("replay function signature=%v variadic=%t, want %v", got, got.IsVariadic(), want)
	}
}

type replayFieldExpectation struct {
	name      string
	fieldType reflect.Type
}

// assertExactReplayFields proves one public struct exposes only exact ordered fields.
func assertExactReplayFields(t *testing.T, value reflect.Type, want []replayFieldExpectation) {
	t.Helper()
	if value.Kind() != reflect.Struct || value.NumField() != len(want) {
		t.Fatalf("%s fields=%d, want %d", value, value.NumField(), len(want))
	}
	for index, expected := range want {
		field := value.Field(index)
		if field.Name != expected.name || field.Type != expected.fieldType ||
			!field.IsExported() || field.Anonymous || field.Tag != "" {
			t.Fatalf("%s field[%d]=%s %s anonymous=%t tag=%q", value, index,
				field.Name, field.Type, field.Anonymous, field.Tag)
		}
	}
}

// assertNoExportedReplayFields proves protected public values expose no data fields.
func assertNoExportedReplayFields(t *testing.T, value reflect.Type) {
	t.Helper()
	for field := range value.Fields() {
		if field.IsExported() {
			t.Fatalf("%s exposes field %s", value, field.Name)
		}
	}
}
