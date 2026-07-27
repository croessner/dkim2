package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

const operationRedacted = "dkim2d_operation{redacted}"

// Operation identifies one closed signing use case.
type Operation string

const (
	// OperationSign selects originator signing.
	OperationSign Operation = "sign"
	// OperationRevise selects ordinary-transit revision.
	OperationRevise Operation = "revise"
)

// MessageFidelity identifies the admitted HTTP evidence source.
type MessageFidelity string

const (
	// FidelityRawRFC5322 identifies direct raw API bytes.
	FidelityRawRFC5322 MessageFidelity = "raw_rfc5322"
	// FidelityMilterReconstructedCRLF identifies exact callback reconstruction.
	FidelityMilterReconstructedCRLF MessageFidelity = "milter_reconstructed_crlf"
)

// OperationRequest is one immutable generated-DTO-free service request.
type OperationRequest struct {
	state *operationRequestState
}

type operationRequestState struct {
	operation          Operation
	raw                []byte
	reverse            []byte
	recipients         [][]byte
	incomingReverse    []byte
	incomingRecipients [][]byte
	tenant             string
	domain             string
	fidelity           MessageFidelity
}

// NewRevisionOperationRequest snapshots distinct incoming verification
// evidence and outgoing signing authority for one ordinary-transit revision.
func NewRevisionOperationRequest(
	raw, incomingReverse []byte,
	incomingRecipients [][]byte,
	outgoingReverse []byte,
	outgoingRecipients [][]byte,
	tenant, domain string,
	fidelity MessageFidelity,
) (OperationRequest, error) {
	request, err := newOperationRequest(
		OperationRevise,
		raw,
		outgoingReverse,
		outgoingRecipients,
		tenant,
		domain,
		fidelity,
	)
	if err != nil || len(incomingRecipients) == 0 {
		return OperationRequest{}, &DomainError{}
	}
	request.state.incomingReverse = bytes.Clone(incomingReverse)
	request.state.incomingRecipients = cloneOperationRecipients(incomingRecipients)
	return request, nil
}

// cloneOperationRecipients isolates one exact ordered SMTP recipient list.
func cloneOperationRecipients(recipients [][]byte) [][]byte {
	output := make([][]byte, len(recipients))
	for index := range recipients {
		output[index] = bytes.Clone(recipients[index])
	}
	return output
}

// NewOperationRequest snapshots one validated originator-signing input.
func NewOperationRequest(
	operation Operation,
	raw, reverse []byte,
	recipients [][]byte,
	tenant, domain string,
	fidelity MessageFidelity,
) (OperationRequest, error) {
	if operation != OperationSign {
		return OperationRequest{}, &DomainError{}
	}
	return newOperationRequest(
		operation,
		raw,
		reverse,
		recipients,
		tenant,
		domain,
		fidelity,
	)
}

// newOperationRequest snapshots common validated operation evidence.
func newOperationRequest(
	operation Operation,
	raw, reverse []byte,
	recipients [][]byte,
	tenant, domain string,
	fidelity MessageFidelity,
) (OperationRequest, error) {
	if (operation != OperationSign && operation != OperationRevise) ||
		len(raw) == 0 || len(recipients) == 0 || tenant == "" || domain == "" ||
		(fidelity != FidelityRawRFC5322 && fidelity != FidelityMilterReconstructedCRLF) {
		return OperationRequest{}, &DomainError{}
	}
	clonedRecipients := make([][]byte, len(recipients))
	for index := range recipients {
		clonedRecipients[index] = bytes.Clone(recipients[index])
	}
	return OperationRequest{state: &operationRequestState{
		operation: operation, raw: bytes.Clone(raw), reverse: bytes.Clone(reverse),
		recipients: clonedRecipients, tenant: tenant, domain: domain, fidelity: fidelity,
	}}, nil
}

// Operation returns the closed use case.
func (r OperationRequest) Operation() Operation {
	if r.state == nil {
		return ""
	}
	return r.state.operation
}

// RawMessage returns an isolated exact message snapshot.
func (r OperationRequest) RawMessage() []byte {
	if r.state == nil {
		return nil
	}
	return bytes.Clone(r.state.raw)
}

// ReversePath returns an isolated exact SMTP reverse path.
func (r OperationRequest) ReversePath() []byte {
	if r.state == nil {
		return nil
	}
	return bytes.Clone(r.state.reverse)
}

// Recipients returns isolated ordered SMTP forward paths.
func (r OperationRequest) Recipients() [][]byte {
	if r.state == nil {
		return nil
	}
	output := make([][]byte, len(r.state.recipients))
	for index := range r.state.recipients {
		output[index] = bytes.Clone(r.state.recipients[index])
	}
	return output
}

// IncomingReversePath returns isolated inherited SMTP reverse-path evidence.
func (r OperationRequest) IncomingReversePath() []byte {
	if r.state == nil || r.state.operation != OperationRevise {
		return nil
	}
	return bytes.Clone(r.state.incomingReverse)
}

// IncomingRecipients returns isolated inherited SMTP forward-path evidence.
func (r OperationRequest) IncomingRecipients() [][]byte {
	if r.state == nil || r.state.operation != OperationRevise {
		return nil
	}
	return cloneOperationRecipients(r.state.incomingRecipients)
}

// Tenant returns the bounded administrative tenant.
func (r OperationRequest) Tenant() string {
	if r.state == nil {
		return ""
	}
	return r.state.tenant
}

// Domain returns the canonical local signing domain.
func (r OperationRequest) Domain() string {
	if r.state == nil {
		return ""
	}
	return r.state.domain
}

// Fidelity returns the exact admitted evidence declaration.
func (r OperationRequest) Fidelity() MessageFidelity {
	if r.state == nil {
		return ""
	}
	return r.state.fidelity
}

// String returns a content-free operation request.
func (OperationRequest) String() string { return operationRedacted }

// GoString returns a content-free Go representation.
func (OperationRequest) GoString() string { return operationRedacted }

// Format prevents formatting from traversing message and envelope data.
func (OperationRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, operationRedacted)
}

// MarshalJSON rejects domain request serialization.
func (OperationRequest) MarshalJSON() ([]byte, error) { return nil, &DomainError{} }

// OperationDisposition identifies one closed SMTP outcome.
type OperationDisposition string

const (
	// OperationAccept authorizes a validated action plan.
	OperationAccept OperationDisposition = "accept"
	// OperationContinue completes without mutation.
	OperationContinue OperationDisposition = "continue"
	// OperationReject refuses the message without mutation.
	OperationReject OperationDisposition = "reject"
	// OperationTempfail defers the message without mutation.
	OperationTempfail OperationDisposition = "tempfail"
)

// OperationResultClass identifies one bounded operation result.
type OperationResultClass string

const (
	// OperationPass reports successful signing or revision.
	OperationPass OperationResultClass = "pass"
	// OperationFail reports failed protocol or policy evaluation.
	OperationFail OperationResultClass = "fail"
	// OperationPermerror reports permanent invalidity.
	OperationPermerror OperationResultClass = "permerror"
	// OperationTemperror reports retryable failure.
	OperationTemperror OperationResultClass = "temperror"
)

// CompletedField is one complete daemon-owned folded RFC 5322 field.
type CompletedField struct {
	bytes []byte
}

// NewCompletedField snapshots one field generated by the signing engine.
func NewCompletedField(field []byte) (CompletedField, error) {
	if len(field) == 0 {
		return CompletedField{}, &DomainError{}
	}
	return CompletedField{bytes: bytes.Clone(field)}, nil
}

// Bytes returns one isolated complete field.
func (f CompletedField) Bytes() []byte { return bytes.Clone(f.bytes) }

// String returns a content-free completed field.
func (CompletedField) String() string { return operationRedacted }

// GoString returns a content-free Go representation.
func (CompletedField) GoString() string { return operationRedacted }

// Format prevents formatting from traversing signature material.
func (CompletedField) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, operationRedacted)
}

// OperationResult is one immutable generated-DTO-free outcome.
type OperationResult struct {
	operation   Operation
	result      OperationResultClass
	disposition OperationDisposition
	fields      []CompletedField
	valid       bool
}

// NewOperationResult constructs one closed coherent outcome.
func NewOperationResult(
	operation Operation,
	result OperationResultClass,
	disposition OperationDisposition,
	fields []CompletedField,
) (OperationResult, error) {
	if (operation != OperationSign && operation != OperationRevise) ||
		(result != OperationPass && result != OperationFail &&
			result != OperationPermerror && result != OperationTemperror) ||
		(disposition != OperationAccept && disposition != OperationContinue &&
			disposition != OperationReject && disposition != OperationTempfail) ||
		len(fields) > 2 || (disposition != OperationAccept && len(fields) != 0) ||
		!validOperationOutcome(result, disposition) {
		return OperationResult{}, &DomainError{}
	}
	return OperationResult{
		operation: operation, result: result, disposition: disposition,
		fields: append([]CompletedField(nil), fields...), valid: true,
	}, nil
}

// validOperationOutcome enforces the exact result-to-disposition matrix.
func validOperationOutcome(
	result OperationResultClass,
	disposition OperationDisposition,
) bool {
	switch result {
	case OperationPass:
		return disposition == OperationAccept || disposition == OperationContinue
	case OperationFail, OperationPermerror:
		return disposition == OperationReject
	case OperationTemperror:
		return disposition == OperationTempfail
	default:
		return false
	}
}

// Valid reports whether the outcome passed its owning constructor.
func (r OperationResult) Valid() bool { return r.valid }

// Operation returns the closed operation.
func (r OperationResult) Operation() Operation { return r.operation }

// Result returns the bounded result class.
func (r OperationResult) Result() OperationResultClass { return r.result }

// Disposition returns the closed final outcome.
func (r OperationResult) Disposition() OperationDisposition { return r.disposition }

// Fields returns isolated complete generated fields.
func (r OperationResult) Fields() []CompletedField {
	return append([]CompletedField(nil), r.fields...)
}

// String returns a content-free operation result.
func (OperationResult) String() string { return operationRedacted }

// GoString returns a content-free Go representation.
func (OperationResult) GoString() string { return operationRedacted }

// Format prevents formatting from traversing generated fields.
func (OperationResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, operationRedacted)
}

// OperationService is the narrow sign and revision application seam.
type OperationService interface {
	Sign(context.Context, OperationRequest) (OperationResult, error)
	Revise(context.Context, OperationRequest) (OperationResult, error)
}
