package milter

import (
	"bytes"
	"encoding/base64"
)

const (
	postfixDSNMacroStageHeader byte   = commandHeader
	postfixDSNMacroStageEOH    byte   = commandEOH
	postfixDSNMacroClassEOH    uint32 = 6
	postfixDSNMarker                  = "postfix-dsn-evidence-v1"
	postfixDSNMacroMarker             = "{postfix_dsn_evidence}"
	postfixDSNMacroQueueID            = "{postfix_dsn_original_queue_id}"
	postfixDSNMacroEnvelope           = "{postfix_dsn_original_envelope}"
	postfixDSNEOHMacroList            = postfixDSNMacroMarker + " " +
		postfixDSNMacroQueueID + " " + postfixDSNMacroEnvelope
)

const (
	postfixDSNMacroSeenMarker uint8 = 1 << iota
	postfixDSNMacroSeenQueueID
	postfixDSNMacroSeenEnvelope
	postfixDSNMacroSeenAll = postfixDSNMacroSeenMarker |
		postfixDSNMacroSeenQueueID | postfixDSNMacroSeenEnvelope
)

// postfixDSNMacroState owns at most one complete Postfix-only EOH record.
type postfixDSNMacroState struct {
	seen         uint8
	confirmedEOH bool
	queueID      []byte
	envelope     postfixDSNOriginalEnvelope
}

// validPostfixDSNMacroPayload validates the normal opaque Milter grammar
// while making room only for the bounded DSN envelope macro at EOH.
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
		if !ok || !validPostfixDSNMacroValue(name, value) {
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
	retained := int64(0)
	for next < len(payload) {
		name, afterName, ok := nextNULField(payload, next)
		if !ok || len(name) == 0 || len(name) > 255 {
			return 0, false
		}
		value, afterValue, ok := nextNULField(payload, afterName)
		if !ok || !validPostfixDSNMacroValue(name, value) {
			return 0, false
		}
		next = afterValue
		if isPostfixDSNMacroNamespace(name) && !isPostfixDSNMacro(name) {
			return 0, false
		}
		if !isPostfixDSNMacro(name) {
			continue
		}
		if !hasTransaction || !validPostfixDSNMacroStage(stage, state) {
			return 0, false
		}
		added, accepted := s.acceptValue(name, value)
		if !accepted {
			return 0, false
		}
		retained += added
	}
	if stage == postfixDSNMacroStageEOH && s.seen == postfixDSNMacroSeenAll {
		s.confirmedEOH = true
	}
	return retained, true
}

// validPostfixDSNMacroStage reflects Postfix milter8_message(): the EOH macro
// vector is emitted before every header callback and once more at EOH. The
// complete record must therefore tolerate identical header-stage replays, but
// take() still requires the final EOH-stage confirmation.
func validPostfixDSNMacroStage(stage byte, state callbackState) bool {
	return stage == postfixDSNMacroStageHeader &&
		(state == stateRecipients || state == stateHeaders) ||
		stage == postfixDSNMacroStageEOH && state == stateHeaders
}

// validPostfixDSNMacroValue keeps ordinary metadata bounded while admitting
// the one deliberately large base64url envelope proof.
func validPostfixDSNMacroValue(name, value []byte) bool {
	if string(name) == postfixDSNMacroEnvelope {
		return len(value) > 0 &&
			len(value) <= base64.RawURLEncoding.EncodedLen(maxPostfixDSNEnvelopeBytes)
	}
	return len(value) <= 4096
}

// isPostfixDSNMacro identifies the closed macro namespace owned by this mode.
func isPostfixDSNMacro(name []byte) bool {
	return bytes.Equal(name, []byte(postfixDSNMacroMarker)) ||
		bytes.Equal(name, []byte(postfixDSNMacroQueueID)) ||
		bytes.Equal(name, []byte(postfixDSNMacroEnvelope))
}

// isPostfixDSNMacroNamespace prevents a partial or future local proof record
// from being silently discarded as ordinary Milter metadata.
func isPostfixDSNMacroNamespace(name []byte) bool {
	return bytes.HasPrefix(name, []byte("{postfix_dsn_"))
}

// acceptValue retains one exact, non-duplicated DSN proof component.
func (s *postfixDSNMacroState) acceptValue(name, value []byte) (int64, bool) {
	switch string(name) {
	case postfixDSNMacroMarker:
		if string(value) != postfixDSNMarker {
			return 0, false
		}
		if s.seen&postfixDSNMacroSeenMarker != 0 {
			return 0, true
		}
		s.seen |= postfixDSNMacroSeenMarker
		return 0, true
	case postfixDSNMacroQueueID:
		if !validPostfixDSNQueueID(value) {
			return 0, false
		}
		if s.seen&postfixDSNMacroSeenQueueID != 0 {
			return 0, bytes.Equal(s.queueID, value)
		}
		s.queueID = bytes.Clone(value)
		s.seen |= postfixDSNMacroSeenQueueID
		return int64(len(s.queueID)), true
	case postfixDSNMacroEnvelope:
		envelope, ok := decodePostfixDSNOriginalEnvelope(value)
		if !ok {
			return 0, false
		}
		if s.seen&postfixDSNMacroSeenEnvelope != 0 {
			return 0, equalPostfixDSNEnvelope(s.envelope, envelope)
		}
		s.envelope = envelope
		s.seen |= postfixDSNMacroSeenEnvelope
		stored := int64(len(envelope.sender))
		for _, recipient := range envelope.recipients {
			stored += int64(len(recipient))
		}
		return stored, true
	default:
		return 0, false
	}
}

func equalPostfixDSNEnvelope(left, right postfixDSNOriginalEnvelope) bool {
	if !bytes.Equal(left.sender, right.sender) || len(left.recipients) != len(right.recipients) {
		return false
	}
	for index := range left.recipients {
		if !bytes.Equal(left.recipients[index], right.recipients[index]) {
			return false
		}
	}
	return true
}

// take transfers a complete record only when the outer DSN shape is exact.
func (s *postfixDSNMacroState) take(reverse []byte, recipients [][]byte) (PostfixDSNEvidence, bool) {
	if s == nil || s.seen != postfixDSNMacroSeenAll || !s.confirmedEOH ||
		!bytes.Equal(reverse, []byte("<>")) ||
		len(recipients) != 1 {
		return PostfixDSNEvidence{}, false
	}
	evidence := PostfixDSNEvidence{originalQueueID: s.queueID, original: s.envelope}
	s.seen = 0
	s.confirmedEOH = false
	s.queueID = nil
	s.envelope = postfixDSNOriginalEnvelope{}
	return evidence, true
}

// clear erases retained proof material when a transaction ends before EOM.
func (s *postfixDSNMacroState) clear() {
	if s == nil {
		return
	}
	clear(s.queueID)
	clear(s.envelope.sender)
	clearPostfixDSNRecipients(s.envelope.recipients)
	s.seen = 0
	s.confirmedEOH = false
	s.queueID = nil
	s.envelope = postfixDSNOriginalEnvelope{}
}

// validPostfixDSNQueueID allows the opaque Postfix queue-ID alphabet only.
func validPostfixDSNQueueID(value []byte) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for _, current := range value {
		if current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' ||
			current >= '0' && current <= '9' {
			continue
		}
		return false
	}
	return true
}
