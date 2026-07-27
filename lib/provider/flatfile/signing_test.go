package flatfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

type privacyContract interface {
	fmt.Stringer
	fmt.GoStringer
	fmt.Formatter
	json.Marshaler
}

// requirePrivacyContract makes protected formatting and JSON behavior a
// compile-time obligation.
func requirePrivacyContract[T privacyContract]() {}

// TestProviderBoundaryFormattingIsContentFree proves zero and populated
// provider wrappers cannot be traversed by formatting or JSON encoding.
func TestProviderBoundaryFormattingIsContentFree(t *testing.T) {
	requirePrivacyContract[Binding]()
	requirePrivacyContract[*Resolver]()
	for name, value := range map[string]any{
		"binding":  Binding{},
		"resolver": &Resolver{},
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
				if got := fmt.Sprintf(format, value); got != providerRedacted {
					t.Fatalf("format %q produced %q", format, got)
				}
			}
			encoded, err := json.Marshal(value)
			if err != nil || !bytes.Equal(encoded, []byte("{}")) {
				t.Fatalf("json.Marshal() = %q, %v", encoded, err)
			}
		})
	}
}
