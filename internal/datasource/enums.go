package datasource

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	profileUseOriginatorText        = "originator"
	profileUseOrdinaryTransitText   = "ordinary_transit"
	profileUseNextDomainTransitText = "next_domain_transit"
	profileUseDeliveryStatusText    = "delivery_status"
	recordStatusActiveText          = "active"
	recordStatusDisabledText        = "disabled"
	rolloutEnforceText              = "enforce"
	rolloutObserveText              = "observe"
	rolloutOffText                  = "off"
	compatibilityStrictText         = "strict"
	unknownEnumText                 = "unknown"
)

// ProfileUse identifies one administrative profile-selection purpose.
type ProfileUse uint8

const (
	// ProfileUseOriginator selects an administrative originator profile.
	ProfileUseOriginator ProfileUse = iota + 1
	// ProfileUseOrdinaryTransit selects an administrative ordinary-transit profile.
	ProfileUseOrdinaryTransit
	// ProfileUseNextDomainTransit selects an administrative next-domain profile.
	ProfileUseNextDomainTransit
	// ProfileUseDeliveryStatus selects an administrative delivery-status profile.
	ProfileUseDeliveryStatus
)

// ParseProfileUse parses one exact closed profile-use value.
func ParseProfileUse(value string) (ProfileUse, error) {
	switch value {
	case profileUseOriginatorText:
		return ProfileUseOriginator, nil
	case profileUseOrdinaryTransitText:
		return ProfileUseOrdinaryTransit, nil
	case profileUseNextDomainTransitText:
		return ProfileUseNextDomainTransit, nil
	case profileUseDeliveryStatusText:
		return ProfileUseDeliveryStatus, nil
	default:
		return 0, NewError(ErrorCodeMalformedData)
	}
}

// Known reports whether the use belongs to the closed vocabulary.
func (u ProfileUse) Known() bool {
	return u == ProfileUseOriginator || u == ProfileUseOrdinaryTransit ||
		u == ProfileUseNextDomainTransit || u == ProfileUseDeliveryStatus
}

// String returns the stable profile-use value or a constant unknown marker.
func (u ProfileUse) String() string {
	switch u {
	case ProfileUseOriginator:
		return profileUseOriginatorText
	case ProfileUseOrdinaryTransit:
		return profileUseOrdinaryTransitText
	case ProfileUseNextDomainTransit:
		return profileUseNextDomainTransitText
	case ProfileUseDeliveryStatus:
		return profileUseDeliveryStatusText
	default:
		return unknownEnumText
	}
}

// GoString returns the stable profile-use representation.
func (u ProfileUse) GoString() string { return u.String() }

// Format prevents formatting verbs from exposing unknown numeric values.
func (u ProfileUse) Format(state fmt.State, _ rune) { formatEnum(state, u.String()) }

// MarshalJSON emits only a known closed profile-use value.
func (u ProfileUse) MarshalJSON() ([]byte, error) { return marshalKnown(u.Known(), u.String()) }

// RecordStatus identifies one administrative record state.
type RecordStatus uint8

const (
	// RecordStatusActive permits an otherwise authorized record.
	RecordStatusActive RecordStatus = iota + 1
	// RecordStatusDisabled closes an administrative record.
	RecordStatusDisabled
)

// ParseRecordStatus parses one exact closed record status.
func ParseRecordStatus(value string) (RecordStatus, error) {
	switch value {
	case recordStatusActiveText:
		return RecordStatusActive, nil
	case recordStatusDisabledText:
		return RecordStatusDisabled, nil
	default:
		return 0, NewError(ErrorCodeMalformedData)
	}
}

// Known reports whether the status belongs to the closed vocabulary.
func (s RecordStatus) Known() bool { return s == RecordStatusActive || s == RecordStatusDisabled }

// String returns the stable record status or a constant unknown marker.
func (s RecordStatus) String() string {
	switch s {
	case RecordStatusActive:
		return recordStatusActiveText
	case RecordStatusDisabled:
		return recordStatusDisabledText
	default:
		return unknownEnumText
	}
}

// GoString returns the stable record-status representation.
func (s RecordStatus) GoString() string { return s.String() }

// Format prevents formatting verbs from exposing unknown numeric values.
func (s RecordStatus) Format(state fmt.State, _ rune) { formatEnum(state, s.String()) }

// MarshalJSON emits only a known closed record status.
func (s RecordStatus) MarshalJSON() ([]byte, error) { return marshalKnown(s.Known(), s.String()) }

// Rollout identifies one closed administrative rollout state.
type Rollout uint8

const (
	// RolloutEnforce permits signing after every other check succeeds.
	RolloutEnforce Rollout = iota + 1
	// RolloutObserve resolves data but does not permit signing.
	RolloutObserve
	// RolloutOff disables the administrative binding.
	RolloutOff
)

// ParseRollout parses one exact closed rollout value.
func ParseRollout(value string) (Rollout, error) {
	switch value {
	case rolloutEnforceText:
		return RolloutEnforce, nil
	case rolloutObserveText:
		return RolloutObserve, nil
	case rolloutOffText:
		return RolloutOff, nil
	default:
		return 0, NewError(ErrorCodeMalformedData)
	}
}

// Known reports whether the rollout belongs to the closed vocabulary.
func (r Rollout) Known() bool { return r == RolloutEnforce || r == RolloutObserve || r == RolloutOff }

// String returns the stable rollout value or a constant unknown marker.
func (r Rollout) String() string {
	switch r {
	case RolloutEnforce:
		return rolloutEnforceText
	case RolloutObserve:
		return rolloutObserveText
	case RolloutOff:
		return rolloutOffText
	default:
		return unknownEnumText
	}
}

// GoString returns the stable rollout representation.
func (r Rollout) GoString() string { return r.String() }

// Format prevents formatting verbs from exposing unknown numeric values.
func (r Rollout) Format(state fmt.State, _ rune) { formatEnum(state, r.String()) }

// MarshalJSON emits only a known closed rollout value.
func (r Rollout) MarshalJSON() ([]byte, error) { return marshalKnown(r.Known(), r.String()) }

// Compatibility identifies one closed compatibility policy.
type Compatibility uint8

const (
	// CompatibilityStrict preserves every restrictive DKIM2 rule.
	CompatibilityStrict Compatibility = iota + 1
)

// ParseCompatibility parses the one supported compatibility value.
func ParseCompatibility(value string) (Compatibility, error) {
	if value != compatibilityStrictText {
		return 0, NewError(ErrorCodeMalformedData)
	}
	return CompatibilityStrict, nil
}

// Known reports whether the compatibility value is supported.
func (c Compatibility) Known() bool { return c == CompatibilityStrict }

// String returns the stable compatibility value or a constant unknown marker.
func (c Compatibility) String() string {
	if c == CompatibilityStrict {
		return compatibilityStrictText
	}
	return unknownEnumText
}

// GoString returns the stable compatibility representation.
func (c Compatibility) GoString() string { return c.String() }

// Format prevents formatting verbs from exposing unknown numeric values.
func (c Compatibility) Format(state fmt.State, _ rune) { formatEnum(state, c.String()) }

// MarshalJSON emits only a known closed compatibility value.
func (c Compatibility) MarshalJSON() ([]byte, error) {
	return marshalKnown(c.Known(), c.String())
}

// ProviderState identifies the lifecycle of a concrete provider.
type ProviderState uint8

const (
	// ProviderStateReady permits lookups.
	ProviderStateReady ProviderState = iota + 1
	// ProviderStateDegraded rejects lookups until recovery.
	ProviderStateDegraded
	// ProviderStateClosed rejects all later work.
	ProviderStateClosed
)

// Known reports whether the provider state belongs to the closed vocabulary.
func (s ProviderState) Known() bool {
	return s == ProviderStateReady || s == ProviderStateDegraded || s == ProviderStateClosed
}

// String returns the stable provider state or a constant unknown marker.
func (s ProviderState) String() string {
	switch s {
	case ProviderStateReady:
		return "ready"
	case ProviderStateDegraded:
		return "degraded"
	case ProviderStateClosed:
		return "closed"
	default:
		return unknownEnumText
	}
}

// GoString returns the stable provider-state representation.
func (s ProviderState) GoString() string { return s.String() }

// Format prevents formatting verbs from exposing unknown numeric values.
func (s ProviderState) Format(state fmt.State, _ rune) { formatEnum(state, s.String()) }

// MarshalJSON emits only a known closed provider state.
func (s ProviderState) MarshalJSON() ([]byte, error) { return marshalKnown(s.Known(), s.String()) }

// marshalKnown serializes one closed known string without exposing unknown input.
func marshalKnown(known bool, value string) ([]byte, error) {
	if !known {
		return nil, NewError(ErrorCodeMalformedData)
	}
	return json.Marshal(value)
}

// formatEnum writes one stable known value or the constant unknown marker.
func formatEnum(state fmt.State, value string) { _, _ = io.WriteString(state, value) }
