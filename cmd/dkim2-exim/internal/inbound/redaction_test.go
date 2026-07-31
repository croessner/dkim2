package inbound

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestServiceExplicitDereferenceStaysOpaque proves runtime paths cannot escape diagnostics.
func TestServiceExplicitDereferenceStaysOpaque(t *testing.T) {
	const toxic = "/toxic/socket-marker"
	service := &Service{config: ServiceConfig{Path: toxic, AuthservID: "toxic.example"}}
	for _, value := range []any{service, *service, service.config} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, "toxic") || !strings.Contains(rendered, "redacted") {
				t.Fatal("service formatting escaped")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("service JSON serialization succeeded")
		}
	}
}
