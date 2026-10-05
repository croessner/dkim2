package signing

import (
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// SigningIdentity projects only the final locally generated signature through
// its owning parser, without exposing protocol parser types to public callers.
func (m CompletedMessage) SigningIdentity() (domain string, timestamp uint64, err error) {
	if !m.Valid() || len(m.generatedFields) == 0 {
		return "", 0, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	headers, parseErr := rawmsg.NewReconstructedHeaderBlock(m.generatedFields[len(m.generatedFields)-1:], rawmsg.DefaultParserOptions())
	if parseErr != nil {
		return "", 0, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	field, ok := headers.Field(0)
	if !ok {
		return "", 0, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	signed, parseErr := signature.Parse(field)
	if parseErr != nil {
		return "", 0, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	return signed.Domain(), signed.TimestampSeconds(), nil
}
