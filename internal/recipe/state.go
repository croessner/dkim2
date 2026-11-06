package recipe

import (
	"github.com/croessner/dkim2/internal/rawmsg"
)

// State stores one immutable controlled reconstruction state.
type State struct {
	headers      rawmsg.HeaderBlock
	body         rawmsg.Body
	availability BodyAvailability
	framing      rawmsg.MessageFraming
	initialized  bool
}

// NewState clones one validated raw message into a known reconstruction state.
func NewState(message rawmsg.Message) (State, error) {
	if !message.Initialized() {
		return State{}, invalidStateError()
	}
	return newKnownState(message.Headers(), message.Body(), message.Framing())
}

// NewHeadersOnlyState constructs a header-known state whose body is truthfully
// unavailable, such as the text/rfc822-headers original of a delivery-status
// report. Application and generation semantics are unchanged: the state
// behaves exactly like the body-unavailable state produced by a null recipe.
func NewHeadersOnlyState(headers rawmsg.HeaderBlock) (State, error) {
	return newUnavailableState(headers)
}

// newUnavailableState constructs a header-known state with no body bytes.
func newUnavailableState(headers rawmsg.HeaderBlock) (State, error) {
	if !headers.Initialized() {
		return State{}, invalidStateError()
	}
	return State{headers: headers, availability: BodyAvailabilityUnavailable, framing: rawmsg.MessageFramingDelimited, initialized: true}, nil
}

// newKnownState constructs one known state while preserving validated framing.
func newKnownState(headers rawmsg.HeaderBlock, body rawmsg.Body, framing rawmsg.MessageFraming) (State, error) {
	if !headers.Initialized() || !body.Initialized() || !framing.Known() {
		return State{}, invalidStateError()
	}
	if framing == rawmsg.MessageFramingHeaderOnly && (headers.Len() == 0 || body.Len() != 0) {
		return State{}, invalidStateError()
	}
	return State{headers: headers, body: body, availability: BodyAvailabilityKnown, framing: framing, initialized: true}, nil
}

// Valid reports whether the state is initialized and coherent.
func (s State) Valid() bool {
	if !s.initialized || !s.headers.Initialized() || !s.availability.Known() || !s.framing.Known() {
		return false
	}
	if s.availability == BodyAvailabilityKnown {
		if !s.body.Initialized() {
			return false
		}
		return s.framing != rawmsg.MessageFramingHeaderOnly || s.headers.Len() > 0 && s.body.Len() == 0
	}
	return !s.body.Initialized() && s.framing == rawmsg.MessageFramingDelimited
}

// Headers returns an immutable cloned header block.
func (s State) Headers() rawmsg.HeaderBlock {
	if !s.Valid() {
		return rawmsg.HeaderBlock{}
	}
	return s.headers
}

// BodyState returns the closed body availability.
func (s State) BodyState() BodyAvailability {
	if !s.Valid() {
		return ""
	}
	return s.availability
}

// Body returns a cloned known body and false when unavailable.
func (s State) Body() (rawmsg.Body, bool) {
	if !s.Valid() || s.availability != BodyAvailabilityKnown {
		return rawmsg.Body{}, false
	}
	return s.body, true
}

// Framing returns the validated header/body separator form of the state, or
// the empty value for an invalid state. A body-unavailable state always
// reports delimited framing because its body is unknown rather than empty.
func (s State) Framing() rawmsg.MessageFraming {
	if !s.Valid() {
		return ""
	}
	return s.framing
}

// Materialize returns exact raw framing when both dimensions are known.
func (s State) Materialize() (rawmsg.Message, error) {
	if !s.Valid() || s.availability != BodyAvailabilityKnown {
		return rawmsg.Message{}, invalidStateError()
	}
	return rawmsg.NewReconstructedMessageWithFraming(s.headers, s.body, rawmsg.DefaultParserOptions(), s.framing)
}

// invalidStateError constructs one bounded state-contract failure.
func invalidStateError() *Error {
	return newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
}
