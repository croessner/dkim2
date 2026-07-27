package milter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"
)

const redacted = "dkim2_milter_message{redacted}"

// Fidelity is the exact daemon evidence declaration for callback reconstruction.
type Fidelity string

const (
	// FidelityReconstructedCRLF declares Milter callback reconstruction.
	FidelityReconstructedCRLF Fidelity = "milter_reconstructed_crlf"
)

// Message is one immutable EOM snapshot.
type Message struct {
	raw        []byte
	reverse    []byte
	recipients [][]byte
	fidelity   Fidelity
}

// NewMessage snapshots one reconstructed request for an injected handler.
func NewMessage(raw, reverse []byte, recipients [][]byte) (Message, error) {
	if len(raw) == 0 || len(recipients) == 0 {
		return Message{}, &Error{Class: FailureContract}
	}
	cloned := make([][]byte, len(recipients))
	for index := range recipients {
		cloned[index] = bytes.Clone(recipients[index])
	}
	return Message{
		raw: bytes.Clone(raw), reverse: bytes.Clone(reverse),
		recipients: cloned, fidelity: FidelityReconstructedCRLF,
	}, nil
}

// newOwnedMessage transfers already isolated callback buffers into one immutable snapshot.
func newOwnedMessage(raw, reverse []byte, recipients [][]byte) (Message, error) {
	if len(raw) == 0 || len(recipients) == 0 {
		return Message{}, &Error{Class: FailureContract}
	}
	return Message{
		raw: raw, reverse: reverse, recipients: recipients,
		fidelity: FidelityReconstructedCRLF,
	}, nil
}

// Raw returns an isolated copy of reconstructed RFC 5322 bytes.
func (m Message) Raw() []byte { return bytes.Clone(m.raw) }

// ReversePath returns an isolated copy of exact callback bytes.
func (m Message) ReversePath() []byte { return bytes.Clone(m.reverse) }

// Recipients returns isolated ordered callback bytes including duplicates.
func (m Message) Recipients() [][]byte {
	output := make([][]byte, len(m.recipients))
	for index := range m.recipients {
		output[index] = bytes.Clone(m.recipients[index])
	}
	return output
}

// Fidelity returns the exact reconstruction declaration.
func (m Message) Fidelity() Fidelity { return m.fidelity }

// clear erases one synchronous handler snapshot after the call returns.
func (m *Message) clear() {
	if m == nil {
		return
	}
	clear(m.raw)
	clear(m.reverse)
	for index := range m.recipients {
		clear(m.recipients[index])
	}
	m.raw = nil
	m.reverse = nil
	m.recipients = nil
	m.fidelity = ""
}

// String returns a content-free diagnostic.
func (Message) String() string { return redacted }

// GoString returns a content-free Go diagnostic.
func (Message) GoString() string { return redacted }

// Format prevents diagnostic formatting from traversing mail data.
func (Message) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects mail-data serialization outside the daemon mapper.
func (Message) MarshalJSON() ([]byte, error) { return nil, &Error{Class: FailureInternal} }

// ActionKind identifies the sole supported Milter mutation.
type ActionKind string

const (
	// ActionAddHeader appends one validated field.
	ActionAddHeader ActionKind = "add_header"
)

// Action is one prevalidated append-only mutation.
type Action struct {
	Kind  ActionKind
	Name  string
	Value string
}

// String returns a content-free action diagnostic.
func (Action) String() string { return "dkim2_milter_action{redacted}" }

// GoString returns a content-free action Go diagnostic.
func (a Action) GoString() string { return a.String() }

// Format prevents diagnostic formatting from traversing action values.
func (Action) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2_milter_action{redacted}")
}

// MarshalJSON rejects action serialization outside the daemon mapper.
func (Action) MarshalJSON() ([]byte, error) { return nil, &Error{Class: FailureInternal} }

// Disposition is the closed daemon terminal vocabulary.
type Disposition string

const (
	// DispositionAccept applies actions and accepts.
	DispositionAccept Disposition = "accept"
	// DispositionContinue accepts unchanged.
	DispositionContinue Disposition = "continue"
	// DispositionReject rejects unchanged.
	DispositionReject Disposition = "reject"
	// DispositionTempfail tempfails unchanged.
	DispositionTempfail Disposition = "tempfail"
)

// Result is one complete daemon-authorized outcome.
type Result struct {
	Operation string
	Result    string
	Outcome   Disposition
	Actions   []Action
}

// String returns a content-free result diagnostic.
func (Result) String() string { return "dkim2_milter_result{redacted}" }

// GoString returns a content-free result Go diagnostic.
func (r Result) GoString() string { return r.String() }

// Format prevents diagnostic formatting from traversing result actions.
func (Result) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2_milter_result{redacted}")
}

// MarshalJSON rejects result serialization outside the daemon mapper.
func (Result) MarshalJSON() ([]byte, error) { return nil, &Error{Class: FailureInternal} }

// Handler owns the EOM service call.
type Handler interface {
	Handle(context.Context, Message) (Result, error)
}

// Observer receives only closed low-cardinality adapter facts.
type Observer interface {
	RecordConnectionAdmission(string)
	RecordCallback(string, string, string, time.Duration)
	RecordMessage(string, string, string, string, time.Duration, uint64, uint64, bool)
	RecordAction(string, string)
}

// FailureClass identifies one closed local failure.
type FailureClass string

const (
	// FailureContract reports invalid local or remote contract.
	FailureContract FailureClass = "contract"
	// FailureFidelity reports unprovable message reconstruction.
	FailureFidelity FailureClass = "fidelity"
	// FailureCapacity reports pre-operation overload.
	FailureCapacity FailureClass = "capacity"
	// FailureUnavailable reports daemon unavailability before response bytes.
	FailureUnavailable FailureClass = "unavailable"
	// FailureTimeout reports timeout before response bytes.
	FailureTimeout FailureClass = "timeout"
	// FailureIndeterminate reports possible operation or mutation effects.
	FailureIndeterminate FailureClass = "indeterminate"
	// FailureTrust reports a local trust-boundary conflict.
	FailureTrust FailureClass = "trust"
	// FailureInternal reports one contained invariant failure.
	FailureInternal FailureClass = "internal"
)

// Error is one content-free adapter failure.
type Error struct {
	Class FailureClass
}

// Error returns a constant mail-data-free diagnostic.
func (*Error) Error() string { return "dkim2-milter operation failure" }

// Is recognizes one exact closed failure class.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && e.Class == other.Class
}
