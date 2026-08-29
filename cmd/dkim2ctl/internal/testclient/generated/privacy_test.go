package generated

import (
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/wire"
)

// TestGeneratedRequestFormattingIsContentFree proves client DTO diagnostics
// preserve the same protected-value boundary as the generated server.
func TestGeneratedRequestFormattingIsContentFree(t *testing.T) {
	t.Parallel()

	const marker = "DO-NOT-PRINT-RFC5322-OR-ENVELOPE"
	protected, err := wire.NewProtectedString(marker)
	if err != nil {
		t.Fatalf("construct protected value: %v", err)
	}
	request := ProcessRequest{
		ApiVersion: V1,
		Draft:      DraftIetfDkimDkim2Spec06,
		Message:    MessageInput{RawRfc5322Base64: protected},
		Smtp: SMTPInput{
			MailFrom: protected,
			RcptTo:   []wire.ProtectedString{protected},
		},
	}
	values := []any{
		request,
		&request,
		any(request),
		[]any{request, &request},
		map[string]any{"request": request},
		struct{ Request ProcessRequest }{Request: request},
	}
	encodedMarker := fmt.Sprintf("%x", []byte(marker))
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%p"} {
		for _, value := range values {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, marker) || strings.Contains(output, encodedMarker) {
				t.Fatalf("format %s disclosed protected request bytes", format)
			}
		}
	}
}
