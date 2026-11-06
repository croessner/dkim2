package dsn

import (
	"bytes"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
)

// serializeHeadersOnly renders the header block of a reconstructed state as
// the body of a text/rfc822-headers part: the exact field bytes in state
// order with no header/body separator. The result is re-parsed to prove that
// it reads back as a header-only RFC 5322 message with the same fields.
func serializeHeadersOnly(state recipe.State) ([]byte, error) {
	if !state.Valid() {
		return nil, newRebuildError(RebuildErrorInternal, nil)
	}
	headers := state.Headers()
	if headers.Len() == 0 {
		return nil, newRebuildError(RebuildErrorInternal, nil)
	}
	rendered := headers.OriginalBytes()
	reparsed, err := rawmsg.Parse(rendered)
	if err != nil || reparsed.Framing() != rawmsg.MessageFramingHeaderOnly || reparsed.Headers().Len() != headers.Len() ||
		!bytes.Equal(reparsed.Headers().OriginalBytes(), rendered) {
		return nil, newRebuildError(RebuildErrorInternal, err)
	}
	return rendered, nil
}

// serializeComplete renders a body-known reconstructed state as the body of
// a message/rfc822 part through the recipe state's exact materialization.
func serializeComplete(state recipe.State) ([]byte, error) {
	if !state.Valid() || state.BodyState() != recipe.BodyAvailabilityKnown {
		return nil, newRebuildError(RebuildErrorInternal, nil)
	}
	message, err := state.Materialize()
	if err != nil {
		return nil, newRebuildError(RebuildErrorInternal, err)
	}
	return message.RawBytes(), nil
}
