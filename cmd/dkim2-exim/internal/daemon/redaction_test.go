package daemon

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestProcessorOwnersStayOpaque proves tenant/domain/authserv identities cannot escape diagnostics.
func TestProcessorOwnersStayOpaque(t *testing.T) {
	values := []any{
		Processor{authservID: "toxic-auth.example"},
		FilterProcessor{tenant: "toxic-tenant", domain: "toxic-domain.example"},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, "toxic") || !strings.Contains(rendered, "redacted") {
				t.Fatal("processor formatting escaped")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("processor JSON serialization succeeded")
		}
	}
}
