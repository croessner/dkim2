// Package filter owns complete-message Exim transport-filter rewriting.
package filter

import (
	"bytes"
	"slices"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const maxTransformedBytes = maxInputBytes + 3*(65_535+len("DKIM2-Signature")+2)

// Transform applies one complete admitted filter plan before any stdout write.
func Transform(message []byte, plan adapter.Plan) ([]byte, error) {
	return TransformLimited(message, plan, DefaultLimits())
}

// TransformLimited applies one plan under configured message-structure limits.
func TransformLimited(message []byte, plan adapter.Plan, limits Limits) ([]byte, error) {
	if len(message) == 0 || plan.Operation() != adapter.OperationSign && plan.Operation() != adapter.OperationRevise {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	if !limits.Valid() {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	if err := validateCompleteMessageLimited(message, limits); err != nil {
		return nil, err
	}
	switch plan.Disposition() {
	case adapter.DispositionContinue:
		return slices.Clone(message), nil
	case adapter.DispositionAccept:
	default:
		return nil, adapter.NewError(adapter.FailureContract)
	}
	actions := plan.Actions()
	if len(actions) == 0 {
		return slices.Clone(message), nil
	}
	separator := bytes.Index(message, []byte("\n\n"))
	insertion := len(message)
	if message[0] == '\n' {
		insertion = 0
	} else if separator >= 0 {
		insertion = separator + 1
	}
	additions := make([]byte, 0, len(actions)*(len("DKIM2-Signature:")+2))
	defer clear(additions)
	for _, action := range actions {
		value := action.Value()
		if len(value) == 0 || value[0] != ' ' && value[0] != '\t' {
			return nil, adapter.NewError(adapter.FailureContract)
		}
		if len(action.Name())+1+len(value)+1 > maxTransformedBytes-len(additions) {
			return nil, adapter.NewError(adapter.FailureResource)
		}
		additions = append(additions, action.Name()...)
		additions = append(additions, ':')
		additions = append(additions, value...)
		additions = append(additions, '\n')
	}
	if len(message) > maxTransformedBytes-len(additions) {
		return nil, adapter.NewError(adapter.FailureResource)
	}
	output := make([]byte, 0, len(message)+len(additions))
	output = append(output, message[:insertion]...)
	output = append(output, additions...)
	output = append(output, message[insertion:]...)
	if err := validateCompleteMessageLimited(output, limits); err != nil {
		clear(output)
		return nil, err
	}
	return output, nil
}

// validateCompleteMessageLimited enforces configured bytes, fields, and folding before authority use.
func validateCompleteMessageLimited(message []byte, limits Limits) error {
	if !limits.Valid() || len(message) > limits.MessageBytes {
		return adapter.NewError(adapter.FailureResource)
	}
	separator := bytes.Index(message, []byte("\n\n"))
	headerEnd := len(message)
	if message[0] == '\n' {
		headerEnd = 0
	} else if separator >= 0 {
		headerEnd = separator + 1
	}
	headers := message[:headerEnd]
	if len(headers) > limits.HeaderBytes {
		return adapter.NewError(adapter.FailureResource)
	}
	count, fieldBytes := 0, 0
	for len(headers) > 0 {
		lineEnd := bytes.IndexByte(headers, '\n')
		if lineEnd < 0 {
			return adapter.NewError(adapter.FailureFidelity)
		}
		lineBytes := lineEnd + 1
		continuation := headers[0] == ' ' || headers[0] == '\t'
		if !continuation {
			count++
			fieldBytes = 0
		} else if count == 0 {
			return adapter.NewError(adapter.FailureFidelity)
		}
		fieldBytes += lineBytes
		if count > limits.HeaderCount || fieldBytes > limits.HeaderFieldBytes {
			return adapter.NewError(adapter.FailureResource)
		}
		headers = headers[lineBytes:]
	}
	outgoing, err := adapter.NewOutgoingEnvelope(nil, []byte("validation@example.invalid"))
	if err != nil {
		return adapter.NewError(adapter.FailureInternal)
	}
	request, err := adapter.NewSignRequest(message, outgoing)
	if err != nil {
		return err
	}
	complete := request.Message()
	defer clear(complete)
	if !bytes.Equal(complete, message) {
		return adapter.NewError(adapter.FailureFidelity)
	}
	return nil
}
