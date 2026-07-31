package filter

import (
	"context"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const maxInputBytes = 32 << 20

// Limits narrows the hard filter message and header ceilings.
type Limits struct {
	MessageBytes     int
	HeaderBytes      int
	HeaderCount      int
	HeaderFieldBytes int
}

// DefaultLimits returns the filter protocol maximums.
func DefaultLimits() Limits {
	return Limits{
		MessageBytes: maxInputBytes, HeaderBytes: 1 << 20,
		HeaderCount: 2_000, HeaderFieldBytes: 65_536,
	}
}

// Valid reports whether every configured limit is positive and safely bounded.
func (l Limits) Valid() bool {
	return l.MessageBytes >= 1 && l.MessageBytes <= maxInputBytes &&
		l.HeaderBytes >= 1 && l.HeaderBytes <= 1<<20 &&
		l.HeaderCount >= 1 && l.HeaderCount <= 2_000 &&
		l.HeaderFieldBytes >= 1 && l.HeaderFieldBytes <= 65_536 &&
		l.HeaderBytes <= l.MessageBytes && l.HeaderFieldBytes <= l.HeaderBytes
}

// WorkingSetBytes returns the conservative simultaneous memory and spool budget.
func (l Limits) WorkingSetBytes() (int64, bool) {
	if !l.Valid() {
		return 0, false
	}
	additions := int64(3 * (65_535 + len("DKIM2-Signature") + 2))
	transformed, ok := checkedFilterAdd(int64(l.MessageBytes), additions)
	if !ok {
		return 0, false
	}
	const envelope = int64(2 * 256)
	requestInput, ok := checkedFilterAdd(int64(l.MessageBytes), envelope)
	if !ok {
		return 0, false
	}
	requestOwners, ok := checkedFilterMultiply(requestInput, 5)
	if !ok {
		return 0, false
	}
	encoded, ok := checkedFilterAdd(int64(l.MessageBytes), 2)
	if !ok {
		return 0, false
	}
	encoded /= 3
	encoded, ok = checkedFilterMultiply(encoded, 4)
	if !ok {
		return 0, false
	}
	encodedOwners, ok := checkedFilterMultiply(encoded, 2)
	if !ok {
		return 0, false
	}
	// Raw spool, captured message, adapter request, authorized copy, and seven
	// generated/JSON request owners conservatively cover every input representation.
	baseOwners, ok := checkedFilterMultiply(int64(l.MessageBytes), 4)
	if !ok {
		return 0, false
	}
	outputOwners, ok := checkedFilterMultiply(transformed, 3)
	if !ok {
		return 0, false
	}
	const response = int64(7*(4<<20) + 3*(64<<10))
	total := int64(0)
	for _, owner := range []int64{baseOwners, requestOwners, encodedOwners, outputOwners, response, streamBufferBytes} {
		total, ok = checkedFilterAdd(total, owner)
		if !ok {
			return 0, false
		}
	}
	return total, true
}

// checkedFilterAdd rejects signed resource-accounting overflow.
func checkedFilterAdd(left int64, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > int64(^uint64(0)>>1)-right {
		return 0, false
	}
	return left + right, true
}

// checkedFilterMultiply rejects signed resource-accounting overflow.
func checkedFilterMultiply(left int64, right int64) (int64, bool) {
	if left < 0 || right < 0 || right != 0 && left > int64(^uint64(0)>>1)/right {
		return 0, false
	}
	return left * right, true
}

// EvidenceLoader loads one immutable receive-time envelope by opaque locator.
type EvidenceLoader interface {
	Load(context.Context, string) (adapter.IncomingEvidence, error)
}

// BuildRequest validates trusted direct Exim arguments before reading authority.
func BuildRequest(
	ctx context.Context,
	operation adapter.FilterOperation,
	arguments []string,
	message []byte,
	loader EvidenceLoader,
) (adapter.FilterRequest, error) {
	if ctx == nil {
		return adapter.FilterRequest{}, adapter.NewError(adapter.FailureInvalidRequest)
	}
	invocation, err := parseInvocation(operation, arguments)
	if err != nil {
		return adapter.FilterRequest{}, err
	}
	return invocation.buildRequest(ctx, message, loader)
}

// invocation owns validated direct argv state before any evidence authority is read.
type invocation struct {
	operation adapter.FilterOperation
	outgoing  adapter.OutgoingEnvelope
	locator   string
}

// parseInvocation validates exact argument counts and outgoing authority first.
func parseInvocation(operation adapter.FilterOperation, arguments []string) (invocation, error) {
	switch {
	case operation == adapter.FilterSign && len(arguments) == 2:
		outgoing, err := outgoingEnvelope(arguments[0], arguments[1])
		if err != nil {
			return invocation{}, err
		}
		return invocation{operation: operation, outgoing: outgoing}, nil
	case operation == adapter.FilterRevise && len(arguments) == 3:
		if !validOpaqueLocator(arguments[0]) {
			return invocation{}, adapter.NewError(adapter.FailureInvalidRequest)
		}
		outgoing, err := outgoingEnvelope(arguments[1], arguments[2])
		if err != nil {
			return invocation{}, err
		}
		return invocation{
			operation: operation, outgoing: outgoing, locator: arguments[0],
		}, nil
	default:
		return invocation{}, adapter.NewError(adapter.FailureInvalidRequest)
	}
}

// buildRequest adds the complete message and revision evidence to validated argv state.
func (i invocation) buildRequest(
	ctx context.Context,
	message []byte,
	loader EvidenceLoader,
) (adapter.FilterRequest, error) {
	if ctx == nil {
		return adapter.FilterRequest{}, adapter.NewError(adapter.FailureInvalidRequest)
	}
	switch i.operation {
	case adapter.FilterSign:
		return adapter.NewSignRequest(message, i.outgoing)
	case adapter.FilterRevise:
		if loader == nil {
			return adapter.FilterRequest{}, adapter.NewError(adapter.FailureInvalidRequest)
		}
		validation, err := adapter.NewSignRequest(message, i.outgoing)
		if err != nil {
			return adapter.FilterRequest{}, err
		}
		validatedMessage := validation.Message()
		defer clear(validatedMessage)
		incoming, err := loader.Load(ctx, i.locator)
		if err != nil {
			return adapter.FilterRequest{}, adapter.NewError(adapter.FailureUnavailable)
		}
		return adapter.NewReviseRequest(validatedMessage, i.outgoing, incoming)
	default:
		return adapter.FilterRequest{}, adapter.NewError(adapter.FailureInvalidRequest)
	}
}

// outgoingEnvelope rejects Bcc-like grouped delivery before any evidence or daemon authority.
func outgoingEnvelope(mailFrom, recipient string) (adapter.OutgoingEnvelope, error) {
	canonicalReverse, err := adapter.CanonicalEximPath([]byte(mailFrom), true)
	if err != nil {
		return adapter.OutgoingEnvelope{}, err
	}
	canonicalRecipient, err := adapter.CanonicalEximPath([]byte(recipient), false)
	if err != nil {
		return adapter.OutgoingEnvelope{}, adapter.NewError(adapter.FailureInvalidRequest)
	}
	return adapter.NewOutgoingEnvelope(canonicalReverse, canonicalRecipient)
}

// validOpaqueLocator proves the fixed direct-child locator argument grammar.
func validOpaqueLocator(locator string) bool {
	if len(locator) != 32 {
		return false
	}
	for _, current := range []byte(locator) {
		if current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' ||
			current >= '0' && current <= '9' || current == '-' || current == '_' {
			continue
		}
		return false
	}
	return true
}
