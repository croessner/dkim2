package milter

import "bytes"

const (
	postfixDSNMacroStageHeader byte   = commandHeader
	postfixDSNMacroStageEOH    byte   = commandEOH
	postfixDSNMacroClassEOH    uint32 = 6
	postfixDSNMacroOrigin             = "{postfix_dsn_origin}"
	postfixDSNOriginInternal          = "internal"
	postfixDSNOriginExternal          = "external"
	postfixDSNEOHMacroList            = postfixDSNMacroOrigin
)

// postfixDSNMacroState retains the closed Postfix origin enum through EOH.
type postfixDSNMacroState struct {
	seen         bool
	confirmedEOH bool
	origin       string
}

// validPostfixDSNMacroPayload validates the normal opaque Milter grammar
// while keeping every macro value within the ordinary metadata bound.
func validPostfixDSNMacroPayload(payload []byte) bool {
	if len(payload) < 1 || len(payload) > maxMilterPayloadLength {
		return false
	}
	next := 1
	for next < len(payload) {
		name, afterName, ok := nextNULField(payload, next)
		if !ok || len(name) == 0 || len(name) > 255 {
			return false
		}
		value, afterValue, ok := nextNULField(payload, afterName)
		if !ok || len(value) > 4096 {
			return false
		}
		next = afterValue
	}
	return true
}

// accept validates one opaque Milter macro callback and retains only its DSN
// proof values. The returned size is newly retained memory for admission.
func (s *postfixDSNMacroState) accept(
	payload []byte,
	state callbackState,
	hasTransaction bool,
) (int64, bool) {
	if s == nil || len(payload) < 1 {
		return 0, false
	}
	stage := payload[0]
	next := 1
	originInPayload := false
	for next < len(payload) {
		name, afterName, ok := nextNULField(payload, next)
		if !ok || len(name) == 0 || len(name) > 255 {
			return 0, false
		}
		value, afterValue, ok := nextNULField(payload, afterName)
		if !ok || len(value) > 4096 {
			return 0, false
		}
		next = afterValue
		if !bytes.Equal(name, []byte(postfixDSNMacroOrigin)) {
			continue
		}
		if originInPayload {
			return 0, false
		}
		originInPayload = true
		if !hasTransaction || !validPostfixDSNMacroStage(stage, state) {
			return 0, false
		}
		origin := string(value)
		if origin != postfixDSNOriginInternal && origin != postfixDSNOriginExternal ||
			s.seen && s.origin != origin {
			return 0, false
		}
		s.seen = true
		s.origin = origin
	}
	if stage == postfixDSNMacroStageEOH && originInPayload {
		s.confirmedEOH = true
	}
	return 0, true
}

// validPostfixDSNMacroStage reflects Postfix milter8_message(): the EOH macro
// vector is emitted before every header callback and once more at EOH. The
// value must therefore tolerate identical header-stage replays, but take()
// still requires the origin macro itself in the final EOH-stage callback.
func validPostfixDSNMacroStage(stage byte, state callbackState) bool {
	return stage == postfixDSNMacroStageHeader &&
		(state == stateRecipients || state == stateHeaders) ||
		stage == postfixDSNMacroStageEOH && state == stateHeaders
}

// present reports whether this transaction supplied the trusted Postfix DSN
// origin macro. An entirely absent value is inapplicable; once present,
// take() must validate the EOH-confirmed enum.
func (s *postfixDSNMacroState) present() bool { return s != nil && s.seen }

// take treats exact external provenance as inapplicable regardless of ordinary
// envelope shape; only internal provenance requires the strict outer DSN shape.
func (s *postfixDSNMacroState) take(reverse []byte, recipients [][]byte) (PostfixDSNEvidence, bool, bool) {
	if s == nil || !s.seen || !s.confirmedEOH {
		return PostfixDSNEvidence{}, false, false
	}
	internal := s.origin == postfixDSNOriginInternal
	s.clear()
	if !internal {
		return PostfixDSNEvidence{}, false, true
	}
	if !bytes.Equal(reverse, []byte("<>")) || len(recipients) != 1 {
		return PostfixDSNEvidence{}, false, false
	}
	return PostfixDSNEvidence{internal: true}, true, true
}

// clear erases retained proof material when a transaction ends before EOM.
func (s *postfixDSNMacroState) clear() {
	if s == nil {
		return
	}
	s.seen = false
	s.confirmedEOH = false
	s.origin = ""
}
