package datasource

import (
	"fmt"
	"io"
)

const maxIdentifierBytes = 128

type identifier struct {
	value string
}

// valid reports whether the identifier satisfies the closed ASCII grammar.
func (i identifier) valid() bool {
	return validIdentifier(i.value)
}

// zero reports whether no identifier bytes are present.
func (i identifier) zero() bool { return i.value == "" }

// byteLen returns the canonical identifier length without exposing its value.
func (i identifier) byteLen() int { return len(i.value) }

// withinMaxBytes reports whether an initialized identifier fits a narrowed bound.
func (i identifier) withinMaxBytes(maximum int) bool {
	return i.valid() && maximum > 0 && i.byteLen() <= maximum && maximum <= maxIdentifierBytes
}

// validIdentifier validates the canonical provider identifier grammar.
func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maxIdentifierBytes || !identifierEdge(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		b := value[index]
		if !identifierEdge(b) && b != '.' && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

// identifierEdge reports whether one byte is a lowercase ASCII letter or digit.
func identifierEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// ProfileID identifies one exact signing profile.
type ProfileID struct{ identifier }

// NewProfileID validates one canonical profile identifier.
func NewProfileID(value string) (ProfileID, error) {
	if !validIdentifier(value) {
		return ProfileID{}, NewError(ErrorCodeInvalidRequest)
	}
	return ProfileID{identifier{value: value}}, nil
}

// Valid reports whether the profile identifier is initialized.
func (i ProfileID) Valid() bool { return i.valid() }

// ByteLen returns the canonical identifier byte length.
func (i ProfileID) ByteLen() int { return i.byteLen() }

// WithinMaxBytes reports whether the identifier fits a valid narrowed bound.
func (i ProfileID) WithinMaxBytes(maximum int) bool { return i.withinMaxBytes(maximum) }

// String returns a constant protected profile-identifier summary.
func (i ProfileID) String() string { return "datasource.ProfileID{redacted}" }

// GoString returns a constant protected profile-identifier representation.
func (i ProfileID) GoString() string { return i.String() }

// Format prevents formatting verbs from exposing the identifier.
func (i ProfileID) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, i.String()) }

// KeyHandleID identifies one provider-neutral private-key handle binding.
type KeyHandleID struct{ identifier }

// NewKeyHandleID validates one canonical key-handle identifier.
func NewKeyHandleID(value string) (KeyHandleID, error) {
	if !validIdentifier(value) {
		return KeyHandleID{}, NewError(ErrorCodeInvalidRequest)
	}
	return KeyHandleID{identifier{value: value}}, nil
}

// Valid reports whether the key-handle identifier is initialized.
func (i KeyHandleID) Valid() bool { return i.valid() }

// ByteLen returns the canonical identifier byte length.
func (i KeyHandleID) ByteLen() int { return i.byteLen() }

// WithinMaxBytes reports whether the identifier fits a valid narrowed bound.
func (i KeyHandleID) WithinMaxBytes(maximum int) bool {
	return i.withinMaxBytes(maximum)
}

// String returns a constant protected key-handle summary.
func (i KeyHandleID) String() string { return "datasource.KeyHandleID{redacted}" }

// GoString returns a constant protected key-handle representation.
func (i KeyHandleID) GoString() string { return i.String() }

// Format prevents formatting verbs from exposing the identifier.
func (i KeyHandleID) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, i.String()) }

// TenantID identifies one exact administrative tenant.
type TenantID struct{ identifier }

// NewTenantID validates one canonical tenant identifier.
func NewTenantID(value string) (TenantID, error) {
	if !validIdentifier(value) {
		return TenantID{}, NewError(ErrorCodeInvalidRequest)
	}
	return TenantID{identifier{value: value}}, nil
}

// Valid reports whether the tenant identifier is initialized.
func (i TenantID) Valid() bool { return i.valid() }

// ByteLen returns the canonical identifier byte length.
func (i TenantID) ByteLen() int { return i.byteLen() }

// WithinMaxBytes reports whether the identifier fits a valid narrowed bound.
func (i TenantID) WithinMaxBytes(maximum int) bool { return i.withinMaxBytes(maximum) }

// String returns a constant protected tenant summary.
func (i TenantID) String() string { return "datasource.TenantID{redacted}" }

// GoString returns a constant protected tenant representation.
func (i TenantID) GoString() string { return i.String() }

// Format prevents formatting verbs from exposing the identifier.
func (i TenantID) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, i.String()) }

// FeedbackRouteID identifies one opaque later-service feedback route.
type FeedbackRouteID struct{ identifier }

// NewFeedbackRouteID validates one canonical feedback-route identifier.
func NewFeedbackRouteID(value string) (FeedbackRouteID, error) {
	if !validIdentifier(value) {
		return FeedbackRouteID{}, NewError(ErrorCodeInvalidRequest)
	}
	return FeedbackRouteID{identifier{value: value}}, nil
}

// Valid reports whether the feedback-route identifier is initialized.
func (i FeedbackRouteID) Valid() bool { return i.valid() }

// ByteLen returns the canonical identifier byte length.
func (i FeedbackRouteID) ByteLen() int { return i.byteLen() }

// WithinMaxBytes reports whether the identifier fits a valid narrowed bound.
func (i FeedbackRouteID) WithinMaxBytes(maximum int) bool {
	return i.withinMaxBytes(maximum)
}

// String returns a constant protected feedback-route summary.
func (i FeedbackRouteID) String() string { return "datasource.FeedbackRouteID{redacted}" }

// GoString returns a constant protected feedback-route representation.
func (i FeedbackRouteID) GoString() string { return i.String() }

// Format prevents formatting verbs from exposing the identifier.
func (i FeedbackRouteID) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, i.String())
}
