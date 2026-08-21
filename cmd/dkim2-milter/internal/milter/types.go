package milter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

const redacted = "dkim2_milter_message{redacted}"

const (
	domainRoleNone      = "none"
	domainRoleRecipient = "recipient"
	domainRoleSigning   = "signing"
	maxObservedDomains  = 8
)

// Fidelity is the exact daemon evidence declaration for callback reconstruction.
type Fidelity string

const (
	// FidelityReconstructedCRLF declares Milter callback reconstruction.
	FidelityReconstructedCRLF Fidelity = "milter_reconstructed_crlf"
	// FidelityPostfixDSNReconstructedCRLF declares Postfix-qualified DSN
	// reconstruction after exact local origin-enum validation.
	FidelityPostfixDSNReconstructedCRLF Fidelity = "postfix_dsn_milter_reconstructed_crlf"
)

// ValidSigningDomainAuthority reports whether value is one canonical lower-case
// ASCII DNS name suitable for an exact daemon signing route.
func ValidSigningDomainAuthority(value string) bool {
	return value != "" && len(value) <= 253 && value == strings.ToLower(value) &&
		asciiBytes([]byte(value)) && value[0] != '[' && validSMTPDomain([]byte(value))
}

// DomainSource selects one fail-closed signing-domain source.
type DomainSource string

const (
	// DomainSourceStatic uses the exact configured signing domain.
	DomainSourceStatic DomainSource = "static"
	// DomainSourceEnvelopeSender derives a canonical DNS domain from MAIL FROM.
	DomainSourceEnvelopeSender DomainSource = "envelope_sender"
	// DomainSourceVerifiedEmbedded defers Postfix DSN domain selection until the
	// daemon authenticates the highest embedded DKIM2 d= value.
	DomainSourceVerifiedEmbedded DomainSource = "verified_embedded"
)

// DomainObservation is one bounded operator-visible projection of processed
// domains without mailbox local parts or metric-label authority.
type DomainObservation struct {
	role      string
	domains   string
	count     uint64
	truncated bool
}

// NewDomainObservation validates one bounded comma-separated domain projection.
func NewDomainObservation(
	role string,
	domains string,
	count uint64,
	truncated bool,
) (DomainObservation, bool) {
	if role == domainRoleNone {
		if domains != "" || count != 0 || truncated {
			return DomainObservation{}, false
		}
		return DomainObservation{}, true
	}
	if role != domainRoleRecipient && role != domainRoleSigning {
		return DomainObservation{}, false
	}
	values := strings.Split(domains, ",")
	if domains == "" || len(values) > maxObservedDomains || count > hardRecipientCount ||
		count < uint64(len(values)) ||
		truncated != (count > uint64(len(values))) {
		return DomainObservation{}, false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !ValidSigningDomainAuthority(value) {
			return DomainObservation{}, false
		}
		if _, duplicate := seen[value]; duplicate {
			return DomainObservation{}, false
		}
		seen[value] = struct{}{}
	}
	if role == domainRoleSigning && (len(values) != 1 || count != 1 || truncated) {
		return DomainObservation{}, false
	}
	return DomainObservation{
		role: role, domains: domains, count: count, truncated: truncated,
	}, true
}

// NewSigningDomainObservation constructs one exact selected signing-domain fact.
func NewSigningDomainObservation(domain string) (DomainObservation, bool) {
	return NewDomainObservation(domainRoleSigning, domain, 1, false)
}

// Role returns the closed operational relationship for the domains.
func (d DomainObservation) Role() string {
	if d.role == "" {
		return domainRoleNone
	}
	return d.role
}

// Domains returns the bounded comma-separated canonical domain list.
func (d DomainObservation) Domains() string { return d.domains }

// Count returns the exact number of distinct canonical domains observed.
func (d DomainObservation) Count() uint64 { return d.count }

// Truncated reports whether the visible list omits additional distinct domains.
func (d DomainObservation) Truncated() bool { return d.truncated }

// ValidForMode proves that the domain role matches the adapter operation.
func (d DomainObservation) ValidForMode(mode string) bool {
	validated, ok := NewDomainObservation(
		d.Role(), d.domains, d.count, d.truncated,
	)
	if !ok || validated.Role() != d.Role() {
		return false
	}
	if d.Role() == domainRoleNone {
		return true
	}
	if mode == modeInbound {
		return d.Role() == domainRoleRecipient
	}
	return (mode == modeOriginator || mode == modeTransit || mode == modePostfixDSN) &&
		d.Role() == domainRoleSigning
}

// Message is one immutable EOM snapshot.
type Message struct {
	raw        []byte
	reverse    []byte
	recipients [][]byte
	fidelity   Fidelity
	postfixDSN *PostfixDSNEvidence
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

// newOwnedPostfixDSNMessage transfers isolated callback and Postfix evidence
// buffers into the one synchronous delivery-status handler snapshot.
func newOwnedPostfixDSNMessage(
	raw, reverse []byte,
	recipients [][]byte,
	evidence PostfixDSNEvidence,
) (Message, error) {
	message, err := newOwnedMessage(raw, reverse, recipients)
	if err != nil {
		return Message{}, err
	}
	message.postfixDSN = &evidence
	message.fidelity = FidelityPostfixDSNReconstructedCRLF
	return message, nil
}

// Raw returns an isolated copy of reconstructed RFC 5322 bytes.
func (m Message) Raw() []byte { return bytes.Clone(m.raw) }

// ReversePath returns an isolated copy of exact callback bytes.
func (m Message) ReversePath() []byte { return bytes.Clone(m.reverse) }

// SigningDomain derives one canonical ASCII DNS domain only when the complete
// originator envelope fits the current ASCII signing boundary.
func (m Message) SigningDomain() (string, bool) {
	if !m.SupportsASCIISigningEnvelope() {
		return "", false
	}
	return canonicalASCIIEnvelopeDomain(m.reverse, true)
}

// RecipientDomainObservation derives distinct canonical ASCII DNS domains from
// exact validated recipient paths and bounds only their operator-visible list.
func (m Message) RecipientDomainObservation() DomainObservation {
	seen := make(map[string]struct{}, len(m.recipients))
	visible := make([]string, 0, maxObservedDomains)
	for _, recipient := range m.recipients {
		domain, ok := canonicalASCIIEnvelopeDomain(recipient, false)
		if !ok {
			continue
		}
		if _, duplicate := seen[domain]; duplicate {
			continue
		}
		seen[domain] = struct{}{}
		if len(visible) < maxObservedDomains {
			visible = append(visible, domain)
		}
	}
	if len(seen) == 0 {
		return DomainObservation{}
	}
	observation, ok := NewDomainObservation(
		domainRoleRecipient,
		strings.Join(visible, ","),
		uint64(len(seen)),
		len(seen) > len(visible),
	)
	if !ok {
		return DomainObservation{}
	}
	return observation
}

// canonicalASCIIEnvelopeDomain returns the mailbox DNS domain without its local
// part, address literals, SMTPUTF8 normalization, aliases, or fallback.
func canonicalASCIIEnvelopeDomain(path []byte, allowNull bool) (string, bool) {
	if len(path) == 2 || !asciiBytes(path) || !validEnvelopePath(path, allowNull) {
		return "", false
	}
	mailbox := path[1 : len(path)-1]
	if mailbox[0] == '@' {
		separator := bytes.IndexByte(mailbox, ':')
		if separator < 2 || !validSourceRoute(mailbox[:separator]) {
			return "", false
		}
		mailbox = mailbox[separator+1:]
	}
	localEnd, ok := smtpLocalEnd(mailbox)
	if !ok || localEnd >= len(mailbox) || mailbox[localEnd] != '@' {
		return "", false
	}
	domain := mailbox[localEnd+1:]
	if len(domain) == 0 || domain[0] == '[' || !asciiBytes(domain) ||
		!validSMTPDomain(domain) {
		return "", false
	}
	canonical := make([]byte, len(domain))
	for index, current := range domain {
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		canonical[index] = current
	}
	return string(canonical), true
}

// NullReversePath reports whether the exact normalized SMTP sender is null.
func (m Message) NullReversePath() bool { return bytes.Equal(m.reverse, []byte("<>")) }

// SupportsASCIISigningEnvelope reports whether every exact SMTP path fits the
// pinned originator signing boundary without normalization or inference.
func (m Message) SupportsASCIISigningEnvelope() bool {
	if len(m.recipients) == 0 || !asciiBytes(m.reverse) ||
		!validEnvelopePath(m.reverse, true) {
		return false
	}
	for _, recipient := range m.recipients {
		if !asciiBytes(recipient) || !validEnvelopePath(recipient, false) {
			return false
		}
	}
	return true
}

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

// PostfixDSNEvidence returns an isolated Postfix-specific DSN provenance
// record only for the dedicated local adapter mode.
func (m Message) PostfixDSNEvidence() (PostfixDSNEvidence, bool) {
	if m.postfixDSN == nil {
		return PostfixDSNEvidence{}, false
	}
	return m.postfixDSN.clone(), true
}

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
	if m.postfixDSN != nil {
		m.postfixDSN.clear()
	}
	m.raw = nil
	m.reverse = nil
	m.recipients = nil
	m.fidelity = ""
	m.postfixDSN = nil
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
	// DispositionContinue accepts without a terminal policy decision.
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
	Domains   DomainObservation
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
	RecordMessage(
		string, string, string, string, time.Duration, uint64, uint64, bool,
		DomainObservation,
	)
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
