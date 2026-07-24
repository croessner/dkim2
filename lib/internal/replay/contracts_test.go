package replay

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestCheckVocabularyIsClosed verifies the exact three nonzero successes.
func TestCheckVocabularyIsClosed(t *testing.T) {
	tests := []struct {
		check Check
		text  string
	}{
		{CheckFirstSeen, "first_seen"},
		{CheckReplayed, "replayed"},
		{CheckDisabled, disabledValueText},
	}
	for _, test := range tests {
		if !test.check.Known() || test.check.String() != test.text {
			t.Fatalf("Check(%d) = %q known=%t", test.check, test.check, test.check.Known())
		}
		assertClosedValueEncoding(t, test.check, test.text)
	}
	for _, unknown := range []Check{0, 255} {
		if unknown.Known() || unknown.String() != unknownValueText {
			t.Fatalf("unknown Check(%d) = %q known=%t", unknown, unknown, unknown.Known())
		}
		if text, err := unknown.MarshalText(); text != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("Check(%d).MarshalText() = %q, %v", unknown, text, err)
		}
		if encoded, err := json.Marshal(unknown); encoded != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("json.Marshal(Check(%d)) = %s, %v", unknown, encoded, err)
		}
	}
}

// TestStoreStateVocabularyIsClosed verifies the exact five nonzero lifecycle states.
func TestStoreStateVocabularyIsClosed(t *testing.T) {
	tests := []struct {
		state StoreState
		text  string
	}{
		{StoreReady, "ready"},
		{StoreDegraded, "degraded"},
		{StoreDisabled, disabledValueText},
		{StoreClosing, "closing"},
		{StoreClosed, "closed"},
	}
	for _, test := range tests {
		if !test.state.Known() || test.state.String() != test.text {
			t.Fatalf("StoreState(%d) = %q known=%t", test.state, test.state, test.state.Known())
		}
		assertClosedValueEncoding(t, test.state, test.text)
	}
	for _, unknown := range []StoreState{0, 255} {
		if unknown.Known() || unknown.String() != unknownValueText {
			t.Fatalf("unknown StoreState(%d) = %q known=%t", unknown, unknown, unknown.Known())
		}
		if text, err := unknown.MarshalText(); text != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("StoreState(%d).MarshalText() = %q, %v", unknown, text, err)
		}
		if encoded, err := json.Marshal(unknown); encoded != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("json.Marshal(StoreState(%d)) = %s, %v", unknown, encoded, err)
		}
	}
}

// TestValidateCheckOutcomeRejectsEveryContradictoryPair verifies fail-closed pair reconciliation.
func TestValidateCheckOutcomeRejectsEveryContradictoryPair(t *testing.T) {
	for _, check := range []Check{CheckFirstSeen, CheckReplayed, CheckDisabled} {
		if err := ValidateCheckOutcome(check, nil); err != nil {
			t.Fatalf("ValidateCheckOutcome(%q, nil) = %v", check, err)
		}
	}
	for _, code := range allErrorCodes() {
		if err := ValidateCheckOutcome(0, NewError(code)); err != nil {
			t.Fatalf("ValidateCheckOutcome(zero, %q) = %v", code, err)
		}
	}

	var typedNil *Error
	invalidErrors := []error{
		errors.New("raw-marker"),
		fmt.Errorf("wrapped-marker: %w", NewError(ErrorCodeUnavailable)),
		typedNil,
	}
	for _, test := range []struct {
		check Check
		err   error
	}{
		{0, nil},
		{Check(255), nil},
		{CheckFirstSeen, NewError(ErrorCodeUnavailable)},
		{Check(255), NewError(ErrorCodeUnavailable)},
	} {
		if code := ErrorCodeOf(ValidateCheckOutcome(test.check, test.err)); code != ErrorCodeInternalInvariant {
			t.Fatalf("ValidateCheckOutcome(%q, %v) code = %q", test.check, test.err, code)
		}
	}
	for _, invalidErr := range invalidErrors {
		if code := ErrorCodeOf(ValidateCheckOutcome(0, invalidErr)); code != ErrorCodeInternalInvariant {
			t.Fatalf("ValidateCheckOutcome(zero, %T) code = %q", invalidErr, code)
		}
	}
}

// TestStoreContractsRemainStorageNeutral verifies the interfaces expose no backend vocabulary.
func TestStoreContractsRemainStorageNeutral(t *testing.T) {
	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	if storeType.NumMethod() != 1 {
		t.Fatalf("Store methods = %d", storeType.NumMethod())
	}
	method, ok := storeType.MethodByName("CheckAndRemember")
	if !ok || method.Type.NumIn() != 3 || method.Type.NumOut() != 2 {
		t.Fatalf("CheckAndRemember signature = %#v", method)
	}
	managedType := reflect.TypeOf((*ManagedStore)(nil)).Elem()
	if managedType.NumMethod() != 3 {
		t.Fatalf("ManagedStore methods = %d", managedType.NumMethod())
	}
	for _, forbidden := range []string{"SET", "NX", "PX", "Valkey", "Redis", "Usage"} {
		if strings.Contains(storeType.String()+managedType.String(), forbidden) {
			t.Fatalf("store contract exposed backend vocabulary %q", forbidden)
		}
	}
}

// TestKeyFormattingAndSerializationNeverExposeStorageBytes verifies the opaque contract is protected.
func TestKeyFormattingAndSerializationNeverExposeStorageBytes(t *testing.T) {
	var key Key
	copy(key.storage[:], []byte("TOXIC-PROTECTED-REPLAY-KEY"))
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%X", key, key, key, key, key, key, key)
	if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "544f584943") ||
		strings.Count(formatted, replayKeyRedactedText) != 7 {
		t.Fatalf("Key formatting was not constant: %q", formatted)
	}
	if pointerFormatted := fmt.Sprintf("%p", &key); containsKeyMaterial(pointerFormatted) {
		t.Fatalf("Key pointer formatting exposed protected bytes: %q", pointerFormatted)
	}
	if text, err := key.MarshalText(); text != nil || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("Key.MarshalText() = %q, %v", text, err)
	}
	if encoded, err := json.Marshal(key); encoded != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
		t.Fatalf("json.Marshal(Key) = %s, %v", encoded, err)
	}
}

// TestKeyContainerAndPointerSurfacesNeverExposeStorageBytes verifies recursive diagnostics.
func TestKeyContainerAndPointerSurfacesNeverExposeStorageBytes(t *testing.T) {
	var key Key
	copy(key.storage[:], []byte("TOXIC-PROTECTED-REPLAY-KEY"))
	slice := []Key{key}
	structure := struct{ Key Key }{Key: key}
	stringMap := map[string]Key{"key": key}
	keyMap := map[Key]struct{}{key: {}}
	surfaces := []struct {
		value   any
		pointer any
	}{
		{&key, &key},
		{slice, &slice},
		{structure, &structure},
		{stringMap, &stringMap},
		{keyMap, &keyMap},
	}
	for _, surface := range surfaces {
		formatted := fmt.Sprintf("%v|%+v|%#v|%x", surface.value, surface.value, surface.value, surface.value)
		formatted += "|" + fmt.Sprintf("%p", surface.pointer)
		if containsKeyMaterial(formatted) {
			t.Fatalf("%T formatting exposed protected bytes: %q", surface.value, formatted)
		}
		encoded, err := json.Marshal(surface.value)
		if err == nil || encoded != nil {
			t.Fatalf("json.Marshal(%T) = %s, %v", surface.value, encoded, err)
		}
		if containsKeyMaterial(err.Error()) {
			t.Fatalf("json.Marshal(%T) error exposed protected bytes", surface.value)
		}
	}
}

// containsKeyMaterial reports whether diagnostics contain the synthetic protected marker.
func containsKeyMaterial(value string) bool {
	return strings.Contains(value, "TOXIC") ||
		strings.Contains(value, "544f584943") ||
		strings.Contains(value, "84 79 88 73 67")
}

// assertClosedValueEncoding verifies stable formatting and text/JSON encoding.
func assertClosedValueEncoding(t *testing.T, value interface {
	fmt.Stringer
	encoding.TextMarshaler
}, want string) {
	t.Helper()
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", value, value, value, value, value, value)
	if strings.Count(formatted, want) != 6 {
		t.Fatalf("%T formatting = %q", value, formatted)
	}
	text, err := value.MarshalText()
	if err != nil || string(text) != want {
		t.Fatalf("%T.MarshalText() = %q, %v", value, text, err)
	}
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != `"`+want+`"` {
		t.Fatalf("json.Marshal(%T) = %s, %v", value, encoded, err)
	}
}

// compile-time assertions keep the intended context-aware interface shape.
var (
	_ interface {
		CheckAndRemember(context.Context, Key, Retention) (Check, error)
	} = (Store)(nil)
)
