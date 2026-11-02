package app

import (
	"slices"
	"strings"

	"github.com/croessner/dkim2"
)

// completedSigningFields snapshots proved signing fields and optionally appends
// diagnostic metadata derived solely from the newly generated signature. X- fields
// are unsigned under Draft-09 Section 4; this metadata is never authentication evidence.
func completedSigningFields(message dkim2.UnrestrictedSignedMessage, interopInfo bool) ([]CompletedField, error) {
	generated := message.GeneratedFields()
	fields := make([]CompletedField, 0, len(generated)+1)
	for _, raw := range generated {
		field, err := NewCompletedField(raw)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	if !interopInfo {
		return fields, nil
	}
	info, err := signingInteropField(message)
	if err != nil {
		return nil, err
	}
	return append(fields, info), nil
}

// interopBehaviorDate is the debug-header-02 Section 5 "date" tag: the UTC
// date on which the DKIM2 behavior this daemon emits last changed. It is a
// version stamp for the code, not a signing or draft date, and must be bumped
// with every change to what the daemon signs, verifies, or emits.
const interopBehaviorDate = "2026-11-02"

// signingInteropField renders one bounded informational field from library-parsed
// output, preserving canonical domain and algorithm spelling and stamping the
// fixed behavior date.
func signingInteropField(message dkim2.UnrestrictedSignedMessage) (CompletedField, error) {
	domain, _, err := message.SigningIdentity()
	if err != nil {
		return CompletedField{}, &DomainError{}
	}
	algorithms := make([]string, 0, len(message.Facts().Algorithms()))
	for _, algorithm := range message.Facts().Algorithms() {
		name := string(algorithm)
		if !slices.Contains(algorithms, name) {
			algorithms = append(algorithms, name)
		}
	}
	return NewCompletedField([]byte("X-DKIM2-Info: draft=ietf-dkim-dkim2-spec-09;\r\n" +
		"\trepo=github.com/croessner/dkim2; date=" + interopBehaviorDate + "; sw=dkim2d;\r\n" +
		"\taction=sign d=" + domain + " a=" + strings.Join(algorithms, ",") + ";\r\n"))
}
