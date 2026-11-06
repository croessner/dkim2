package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestDisabledStoreBypassesKeyAndRetentionValidation verifies explicit disabled precedence.
func TestDisabledStoreBypassesKeyAndRetentionValidation(t *testing.T) {
	store := NewDisabledStore()
	for _, request := range []struct {
		key       Key
		retention Retention
	}{
		{},
		{key: testReplayKey(1)},
		{retention: mustRetention(t, time.Second)},
	} {
		check, err := store.CheckAndRemember(context.Background(), request.key, request.retention)
		if check != CheckDisabled || err != nil {
			t.Fatalf("disabled result = %s, %v", check, err)
		}
	}
	if store.State() != StoreDisabled {
		t.Fatalf("disabled state = %s", store.State())
	}
}

// TestDisabledStorePreservesContextAndClosedPrecedence verifies exact public ordering.
func TestDisabledStorePreservesContextAndClosedPrecedence(t *testing.T) {
	store := NewDisabledStore()
	if check, err := store.CheckAndRemember(nil, Key{}, Retention{}); check != 0 || ErrorCodeOf(err) != ErrorCodeInvalidRequest { //nolint:staticcheck // Nil is the contract case under test.
		t.Fatalf("nil context = %s, %v", check, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if check, err := store.CheckAndRemember(cancelled, Key{}, Retention{}); check != 0 ||
		ErrorCodeOf(err) != ErrorCodeCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal context = %s, %v", check, err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if check, err := store.CheckAndRemember(cancelled, Key{}, Retention{}); check != 0 || ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("terminal-over-closed result = %s, %v", check, err)
	}
	if check, err := store.CheckAndRemember(context.Background(), Key{}, Retention{}); check != 0 || ErrorCodeOf(err) != ErrorCodeClosed {
		t.Fatalf("closed result = %s, %v", check, err)
	}
	if err := store.Close(cancelled); ErrorCodeOf(err) != ErrorCodeCancelled {
		t.Fatalf("terminal closed Close() = %v", err)
	}
	if err := store.Close(nil); ErrorCodeOf(err) != ErrorCodeInvalidRequest { //nolint:staticcheck // Nil is the contract case under test.
		t.Fatalf("nil closed Close() = %v", err)
	}
}

// TestDisabledStoreCloseIsIdempotent verifies terminal lifecycle behavior.
func TestDisabledStoreCloseIsIdempotent(t *testing.T) {
	store := NewDisabledStore()
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.State() != StoreClosed {
		t.Fatalf("closed state = %s", store.State())
	}
}

// TestDisabledStoreContainsHostileContexts verifies no context panic escapes.
func TestDisabledStoreContainsHostileContexts(t *testing.T) {
	store := NewDisabledStore()
	for _, ctx := range []context.Context{
		hostileContext{panicOnErr: true},
		hostileContext{err: errors.New("TOXIC-DISABLED-CONTEXT")},
	} {
		check, err := store.CheckAndRemember(ctx, Key{}, Retention{})
		if check != 0 || ErrorCodeOf(err) != ErrorCodeInternalInvariant || strings.Contains(err.Error(), "TOXIC") {
			t.Fatalf("hostile disabled check = %s, %v", check, err)
		}
	}
}

// TestDisabledStoreFormattingIsContentFree verifies stable provider privacy.
func TestDisabledStoreFormattingIsContentFree(t *testing.T) {
	store := NewDisabledStore()
	value := *store
	for _, surface := range []any{
		store, value, any(store), any(value),
		[]*DisabledStore{store}, []DisabledStore{value},
		map[string]*DisabledStore{privacyStoreMapKey: store},
		map[string]DisabledStore{privacyStoreMapKey: value},
	} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%p", surface, surface, surface, surface, surface, surface, surface)
		if strings.Contains(formatted, "lifecycleGate") {
			t.Fatal("disabled formatting exposed retained provider state")
		}
		encoded, marshalErr := json.Marshal(surface)
		if encoded != nil || ErrorCodeOf(marshalErr) != ErrorCodeInternalInvariant {
			t.Fatal("disabled serialization did not fail closed")
		}
	}
	if text, err := store.MarshalText(); text != nil || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("disabled text = %q, %v", text, err)
	}
	if encoded, err := store.MarshalJSON(); encoded != nil || ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("disabled direct JSON = %s, %v", encoded, err)
	}
	if encoded, err := json.Marshal(store); encoded != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
		t.Fatalf("disabled JSON = %s, %v", encoded, err)
	}
}

var (
	_ ManagedStore = (*MemoryStore)(nil)
	_ ManagedStore = (*DisabledStore)(nil)
)
