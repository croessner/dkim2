package httpjson

// preflightConfiguredMessageSize rejects oversized message strings before
// generated DTOs or Base64 payloads are allocated. Canonical spelling and
// malformed Base64 remain the responsibility of the existing validators.
func preflightConfiguredMessageSize(body []byte, constants jsonConstants, limit int) error {
	check := func(raw jsonRawMessageToken) error {
		if !raw.stringValue {
			return nil
		}
		encodedLimit := ((limit + 2) / 3) * 4
		if raw.decodedSize > encodedLimit {
			return &knownFieldError{class: knownFieldRequestTooLarge}
		}
		// The scanner's offsets exclude the JSON quotes. A valid unescaped
		// Base64 string reveals its exact decoded size through its padding.
		if !raw.escaped && raw.start >= 0 && raw.end <= len(body) && raw.end >= raw.start {
			value := body[raw.start:raw.end]
			decoded := len(value) / 4 * 3
			for i := len(value) - 1; i >= 0 && i >= len(value)-2 && value[i] == '='; i-- {
				decoded--
			}
			if decoded > limit {
				return &knownFieldError{class: knownFieldRequestTooLarge}
			}
		}
		return nil
	}
	if err := check(constants.rawMessage); err != nil {
		return err
	}
	for _, raw := range constants.batchRawMessages {
		if err := check(raw); err != nil {
			return err
		}
	}
	return nil
}
