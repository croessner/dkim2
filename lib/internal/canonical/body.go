package canonical

import (
	"bytes"

	"github.com/croessner/dkim2/internal/rawmsg"
)

var canonicalBodyCRLF = []byte("\r\n")

// BodyHashInput builds DKIM2 Section 6.1 canonical body hash input.
func (c Canonicalizer) BodyHashInput(body rawmsg.Body) (ByteInput, error) {
	rawBody := body.Bytes()
	canonical, removedTrailingEmptyLines, terminalAction := canonicalizeBodyBytes(rawBody)
	if len(canonical) > c.options.Limits.MaxBodyInputBytes {
		return ByteInput{}, bodyLimitExceededError(len(canonical), c.options.Limits.MaxBodyInputBytes)
	}

	return NewCanonicalBytes(KindBodyHashInput, canonical, Metadata{
		InputBytes:             len(rawBody),
		BodyTrailingEmptyLines: removedTrailingEmptyLines,
		BodyTerminalAction:     terminalAction,
	})
}

// BodyHashInputFromMessage builds Section 6.1 body input from a raw message.
func (c Canonicalizer) BodyHashInputFromMessage(message rawmsg.Message) (ByteInput, error) {
	return c.BodyHashInput(message.Body())
}

// BodyHash calculates SHA-256 over DKIM2 Section 6.1 canonical body input.
func (c Canonicalizer) BodyHash(body rawmsg.Body) (Result, error) {
	canonical, err := c.BodyHashInput(body)
	if err != nil {
		return Result{}, err
	}

	digest, err := c.SHA256Digest(canonical)
	if err != nil {
		return Result{}, err
	}

	return NewResult(canonical, digest), nil
}

// BodyHashFromMessage calculates SHA-256 body hash input from a raw message.
func (c Canonicalizer) BodyHashFromMessage(message rawmsg.Message) (Result, error) {
	return c.BodyHash(message.Body())
}

// canonicalizeBodyBytes applies Section 6.1 terminal-empty-line handling.
func canonicalizeBodyBytes(body []byte) ([]byte, int, BodyTerminalAction) {
	if len(body) == 0 {
		return bytes.Clone(canonicalBodyCRLF), 0, BodyTerminalActionAppended
	}
	if !bytes.HasSuffix(body, canonicalBodyCRLF) {
		canonical := make([]byte, 0, len(body)+len(canonicalBodyCRLF))
		canonical = append(canonical, body...)
		canonical = append(canonical, canonicalBodyCRLF...)

		return canonical, 0, BodyTerminalActionAppended
	}

	end := len(body)
	removedTrailingEmptyLines := 0
	for end >= len(canonicalBodyCRLF)*2 &&
		bytes.Equal(body[end-len(canonicalBodyCRLF)*2:end-len(canonicalBodyCRLF)], canonicalBodyCRLF) {
		end -= len(canonicalBodyCRLF)
		removedTrailingEmptyLines++
	}

	action := BodyTerminalActionPreserved
	if removedTrailingEmptyLines > 0 {
		action = BodyTerminalActionCollapsed
	}

	return bytes.Clone(body[:end]), removedTrailingEmptyLines, action
}

// bodyLimitExceededError reports canonical body size violations safely.
func bodyLimitExceededError(count int, limit int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{Kind: KindBodyHashInput}, ErrorDetails{
		Class:     ErrorClassLimit,
		LimitName: "max_body_input_bytes",
		Limit:     limit,
		Count:     count,
	}, nil)
}
