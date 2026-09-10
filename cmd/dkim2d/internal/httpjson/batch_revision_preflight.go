package httpjson

import "github.com/croessner/dkim2/cmd/dkim2d/internal/app"

// scanBatchMessageEnvelopeMember records only bounded message/envelope facts from exact batch containers.
func (s *jsonScanner) scanBatchMessageEnvelopeMember(name string) error {
	switch name {
	case "message":
		prior := s.constants.rawMessage
		s.constants.rawMessage = jsonRawMessageToken{}
		err := s.scanMessageValue()
		s.constants.batchRawMessages = append(s.constants.batchRawMessages, s.constants.rawMessage)
		s.constants.rawMessage = prior
		if len(s.constants.batchRawMessages) > app.MaxBatchRevisionCopies+1 {
			return newJSONPreflightError(jsonPreflightRequestTooLarge)
		}
		return err
	case "smtp":
		prior := s.constants.known
		s.constants.known = jsonKnownFieldFacts{}
		err := s.scanSMTPValue()
		s.constants.batchKnown = append(s.constants.batchKnown, s.constants.known)
		s.constants.known = prior
		if len(s.constants.batchKnown) > 2*app.MaxBatchRevisionCopies+1 {
			return newJSONPreflightError(jsonPreflightRequestTooLarge)
		}
		return err
	case "via":
		return s.scanValue(jsonObjectBatchMessageEnvelope, false, 0)
	default:
		return s.scanValue(jsonObjectGeneric, false, 0)
	}
}

// preflightBatchKnownFields applies the existing per-message and envelope resource bounds to every copy.
func preflightBatchKnownFields(body []byte, constants jsonConstants) error {
	for _, raw := range constants.batchRawMessages {
		if err := preflightKnownFields(body, jsonConstants{rawMessage: raw}); err != nil {
			return err
		}
	}
	for _, known := range constants.batchKnown {
		if err := preflightKnownFields(body, jsonConstants{known: known}); err != nil {
			return err
		}
	}
	return nil
}

// validateBatchRawMessages preserves strict unescaped Base64 spelling across every batch message.
func validateBatchRawMessages(constants jsonConstants) error {
	if constants.rawMessage.present || len(constants.batchRawMessages) < 2 {
		return &knownFieldError{class: knownFieldInvalidContract}
	}
	for _, raw := range constants.batchRawMessages {
		if err := validateRawMessageSpelling(jsonConstants{rawMessage: raw}); err != nil {
			return err
		}
	}
	return nil
}
