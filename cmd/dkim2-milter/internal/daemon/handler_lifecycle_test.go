package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

// TestHandlerCloseIsIdempotentAndPreventsOperations freezes transport ownership.
func TestHandlerCloseIsIdempotentAndPreventsOperations(t *testing.T) {
	var value [32]byte
	value[0] = 1
	capability, err := newCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = capability.Close() })
	handler, err := NewHandler(
		"http://127.0.0.1:8080",
		capability,
		modeOriginator,
		"private-tenant-marker",
		"example.test",
		milter.DomainSourceStatic,
		"dsn.example.test",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	state := handler.privateState()
	if state == nil || state.transport == nil || state.closed {
		t.Fatal("handler did not retain its live transport")
	}
	subjects := []any{
		handler,
		*handler,
		any(handler),
		handler.state,
		*handler.state,
		handler.state.guard,
		*handler.state.guard,
		struct{ Value any }{Value: handler},
		struct{ Value Handler }{Value: *handler},
	}
	for _, subject := range subjects {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if formatted := fmt.Sprintf(format, subject); strings.Contains(
				formatted,
				"private-tenant-marker",
			) || strings.Contains(formatted, "example.test") ||
				strings.Contains(formatted, "127.0.0.1:8080") {
				t.Fatal("handler formatting exposed protected identity")
			}
		}
		if output, marshalErr := json.Marshal(subject); marshalErr == nil ||
			strings.Contains(string(output), "private-tenant-marker") {
			t.Fatal("handler serialization did not fail closed")
		}
		if marshaler, ok := subject.(interface{ MarshalText() ([]byte, error) }); ok {
			if output, marshalErr := marshaler.MarshalText(); marshalErr == nil ||
				strings.Contains(string(output), "private-tenant-marker") {
				t.Fatal("handler text serialization did not fail closed")
			}
		}
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if !state.closed {
		t.Fatal("handler did not transition to closed")
	}
	if state.client != nil || state.transport != nil || state.capability != nil ||
		state.mode != "" || state.tenant != "" || state.domain != "" ||
		state.domainSource != "" ||
		state.authservID != "" {
		t.Fatal("handler Close retained runtime or protected identity references")
	}
	if err := handler.Close(); err != nil {
		t.Fatal("second handler close was not idempotent")
	}
	_, err = handler.Handle(t.Context(), milter.Message{})
	var boundary *milter.Error
	if !errors.As(err, &boundary) || boundary.Class != milter.FailureContract {
		t.Fatal("closed handler accepted a new operation")
	}
}
