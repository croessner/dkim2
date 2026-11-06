package replay

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	unknownValueText  = "unknown"
	disabledValueText = "disabled"
)

// Check identifies one successful replay-store outcome.
type Check uint8

const (
	// CheckFirstSeen means the identity was atomically retained for the first time.
	CheckFirstSeen Check = iota + 1
	// CheckReplayed means the identity already existed without retention extension.
	CheckReplayed
	// CheckDisabled means explicit local policy selected no replay storage.
	CheckDisabled
)

// Known reports whether the check belongs to the closed success vocabulary.
func (c Check) Known() bool {
	return c == CheckFirstSeen || c == CheckReplayed || c == CheckDisabled
}

// String returns the stable check value or a constant unknown marker.
func (c Check) String() string {
	switch c {
	case CheckFirstSeen:
		return "first_seen"
	case CheckReplayed:
		return "replayed"
	case CheckDisabled:
		return disabledValueText
	default:
		return unknownValueText
	}
}

// GoString returns the stable check representation.
func (c Check) GoString() string { return c.String() }

// Format prevents unknown numeric values from reaching formatting output.
func (c Check) Format(state fmt.State, _ rune) { formatClosedValue(state, c.String()) }

// MarshalText emits only a known replay-check value.
func (c Check) MarshalText() ([]byte, error) {
	return marshalClosedText(c.Known(), c.String())
}

// MarshalJSON emits only a known replay-check value.
func (c Check) MarshalJSON() ([]byte, error) {
	return marshalClosedJSON(c.Known(), c.String())
}

// StoreState identifies one bounded replay-store lifecycle state.
type StoreState uint8

const (
	// StoreReady permits enabled storage operations.
	StoreReady StoreState = iota + 1
	// StoreDegraded reports a fail-closed enabled provider impairment.
	StoreDegraded
	// StoreDisabled reports an explicitly selected disabled provider.
	StoreDisabled
	// StoreClosing rejects new operations while admitted work drains.
	StoreClosing
	// StoreClosed rejects all later operations.
	StoreClosed
)

// Known reports whether the state belongs to the closed lifecycle vocabulary.
func (s StoreState) Known() bool {
	switch s {
	case StoreReady, StoreDegraded, StoreDisabled, StoreClosing, StoreClosed:
		return true
	default:
		return false
	}
}

// String returns the stable state value or a constant unknown marker.
func (s StoreState) String() string {
	switch s {
	case StoreReady:
		return "ready"
	case StoreDegraded:
		return "degraded"
	case StoreDisabled:
		return disabledValueText
	case StoreClosing:
		return "closing"
	case StoreClosed:
		return "closed"
	default:
		return unknownValueText
	}
}

// GoString returns the stable store-state representation.
func (s StoreState) GoString() string { return s.String() }

// Format prevents unknown numeric values from reaching formatting output.
func (s StoreState) Format(state fmt.State, _ rune) {
	formatClosedValue(state, s.String())
}

// MarshalText emits only a known replay-store state.
func (s StoreState) MarshalText() ([]byte, error) {
	return marshalClosedText(s.Known(), s.String())
}

// MarshalJSON emits only a known replay-store state.
func (s StoreState) MarshalJSON() ([]byte, error) {
	return marshalClosedJSON(s.Known(), s.String())
}

// marshalClosedText serializes a known closed value without normalizing input.
func marshalClosedText(known bool, value string) ([]byte, error) {
	if !known {
		return nil, NewError(ErrorCodeInternalInvariant)
	}
	return []byte(value), nil
}

// marshalClosedJSON serializes a known closed value as one JSON string.
func marshalClosedJSON(known bool, value string) ([]byte, error) {
	if !known {
		return nil, NewError(ErrorCodeInternalInvariant)
	}
	return json.Marshal(value)
}

// formatClosedValue writes one stable known value or the constant unknown marker.
func formatClosedValue(state fmt.State, value string) {
	_, _ = io.WriteString(state, value)
}
