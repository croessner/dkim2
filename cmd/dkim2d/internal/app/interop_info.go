package app

import (
	"slices"
	"strings"
	"time"

	"github.com/croessner/dkim2"
)

// completedSigningFields snapshots proved signing fields and optionally appends
// diagnostic metadata derived solely from the newly generated signature. X- fields
// are unsigned under Draft-06 Section 4; this metadata is never authentication evidence.
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

// signingInteropField renders one bounded informational field from library-parsed
// output, preserving canonical domain and algorithm spelling and the signing date in UTC.
func signingInteropField(message dkim2.UnrestrictedSignedMessage) (CompletedField, error) {
	domain, timestamp, err := message.SigningIdentity()
	if err != nil || timestamp > 253402300799 {
		return CompletedField{}, &DomainError{}
	}
	algorithms := make([]string, 0, len(message.Facts().Algorithms()))
	for _, algorithm := range message.Facts().Algorithms() {
		name := string(algorithm)
		if !slices.Contains(algorithms, name) {
			algorithms = append(algorithms, name)
		}
	}
	date := time.Unix(int64(timestamp), 0).UTC().Format(time.DateOnly)
	return NewCompletedField([]byte("X-DKIM2-Info: draft=ietf-dkim-dkim2-spec-06;\r\n" +
		"\trepo=github.com/croessner/dkim2; date=" + date + "; sw=dkim2d;\r\n" +
		"\taction=sign d=" + domain + " a=" + strings.Join(algorithms, ",") + ";\r\n"))
}
