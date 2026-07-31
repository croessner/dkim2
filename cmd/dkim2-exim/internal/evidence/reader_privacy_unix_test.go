//go:build linux || darwin

package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestReaderExplicitDereferenceStaysOpaque proves retained key bytes cannot escape diagnostics.
func TestReaderExplicitDereferenceStaysOpaque(t *testing.T) {
	const toxic = "toxic-evidence-key-marker"
	reader := &Reader{key: []byte(toxic)}
	for _, value := range []any{reader, *reader} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, toxic) || !strings.Contains(rendered, "redacted") {
				t.Fatal("reader formatting escaped")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("reader JSON serialization succeeded")
		}
	}
}
