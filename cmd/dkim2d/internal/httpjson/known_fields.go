package httpjson

import (
	"errors"

	"github.com/croessner/dkim2"
)

var errKnownFieldPreflight = errors.New("http known-field resource preflight failure")

type knownFieldFailure uint8

const (
	knownFieldInvalidContract knownFieldFailure = iota + 1
	knownFieldRequestTooLarge
)

type knownFieldError struct {
	class knownFieldFailure
}

// Error returns a constant diagnostic without retaining protected values.
func (*knownFieldError) Error() string { return errKnownFieldPreflight.Error() }

// preflightKnownFields decodes generated input only after enforcing local resource precedence.
func preflightKnownFields(
	body []byte,
	constants jsonConstants,
) error {
	raw := constants.rawMessage
	if raw.stringValue && (raw.start < 0 || raw.end < raw.start || raw.end > len(body)) {
		return &knownFieldError{class: knownFieldInvalidContract}
	}
	if raw.stringValue && raw.decodedSize > maxEncodedMessageBytes {
		return &knownFieldError{class: knownFieldRequestTooLarge}
	}
	known := constants.known
	if known.recipients.count > dkim2.HardMaxRecipients ||
		known.mailFrom.decodedSize > maxSMTPPathBytes ||
		known.recipients.maxStringSize > maxSMTPPathBytes ||
		known.mailFrom.decodedSize > maxEnvelopeBytes-known.recipients.decodedBytes {
		return &knownFieldError{class: knownFieldRequestTooLarge}
	}
	return nil
}

// validateRawMessageSpelling rejects escaped-equivalent Base64 only after schema validation.
func validateRawMessageSpelling(constants jsonConstants) error {
	raw := constants.rawMessage
	if !raw.present || !raw.stringValue || raw.escaped {
		return &knownFieldError{class: knownFieldInvalidContract}
	}
	return nil
}

// validateRouteRawMessage applies the raw-message spelling rule to every
// operation whose contract carries message bytes and refuses message bytes on
// the commit operation, whose contract carries none: a commit body that
// smuggles a raw message is an invalid contract, never a silently ignored
// field.
func validateRouteRawMessage(path string, constants jsonConstants) error {
	if path == dsnPropagateCommitPath {
		if constants.rawMessage.present {
			return &knownFieldError{class: knownFieldInvalidContract}
		}
		return nil
	}
	return validateRawMessageSpelling(constants)
}

// isKnownFieldFailure reports one closed resource-preflight class.
func isKnownFieldFailure(err error, class knownFieldFailure) bool {
	var known *knownFieldError
	return errors.As(err, &known) && known != nil && known.class == class
}
