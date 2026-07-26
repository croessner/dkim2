package replay

import (
	"context"
	"fmt"
	"io"
)

const replayKeyRedactedText = "replay_key"

// Key is an opaque replay-storage capability.
//
// Identity construction and key derivation own the nonzero representation.
// The zero value is intentionally invalid for enabled stores.
type Key struct {
	state *keyState
}

// keyState owns the protected immutable storage representation.
type keyState struct {
	storage [storageKeyByteLength]byte
}

// Valid reports whether the capability has the exact protected storage grammar.
func (k Key) Valid() bool { return validStorageKey(k) }

// String returns a constant representation without protected key bytes.
func (Key) String() string { return replayKeyRedactedText }

// GoString returns a constant representation without protected key bytes.
func (Key) GoString() string { return replayKeyRedactedText }

// Format prevents every formatting verb from exposing protected key bytes.
func (Key) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayKeyRedactedText)
}

// MarshalText rejects serialization of a protected replay key.
func (Key) MarshalText() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}

// MarshalJSON rejects serialization of a protected replay key.
func (Key) MarshalJSON() ([]byte, error) {
	return nil, NewError(ErrorCodeInvalidRequest)
}

// storageValue returns one protected storage representation by value.
func (k Key) storageValue() ([storageKeyByteLength]byte, bool) {
	if k.state == nil {
		return [storageKeyByteLength]byte{}, false
	}
	return k.state.storage, true
}

// Store atomically checks and retains one replay identity.
type Store interface {
	CheckAndRemember(context.Context, Key, Retention) (Check, error)
}

// ManagedStore adds bounded lifecycle control to a replay store.
type ManagedStore interface {
	Store
	State() StoreState
	Close(context.Context) error
}

// ValidateCheckOutcome verifies one result/error pair without traversing raw errors.
func ValidateCheckOutcome(check Check, err error) error {
	if err == nil {
		if check.Known() {
			return nil
		}
		return NewError(ErrorCodeInternalInvariant)
	}
	if check != 0 || !IsTypedError(err) {
		return NewError(ErrorCodeInternalInvariant)
	}
	return nil
}
