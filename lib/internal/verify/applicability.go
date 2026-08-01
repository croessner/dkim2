package verify

import (
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// ProtocolApplicable reports whether an initialized message contains at least
// one DKIM2 protocol header and therefore requires verification.
func ProtocolApplicable(message rawmsg.Message) bool {
	return message.Initialized() &&
		(len(message.Headers().FieldsByName(instance.HeaderName)) != 0 ||
			len(message.Headers().FieldsByName(signature.HeaderName)) != 0)
}
