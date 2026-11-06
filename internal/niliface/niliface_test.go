package niliface

import "testing"

// TestIsNilDistinguishesTypedNilAndConcreteValues proves the closed reflection predicate.
func TestIsNilDistinguishesTypedNilAndConcreteValues(t *testing.T) {
	var pointer *int
	var function func()
	var mapping map[string]string
	for _, value := range []any{nil, pointer, function, mapping} {
		if !IsNil(value) {
			t.Fatalf("IsNil(%T) = false", value)
		}
	}
	for _, value := range []any{0, "", struct{}{}, new(int), func() {}, map[string]string{}} {
		if IsNil(value) {
			t.Fatalf("IsNil(%T) = true", value)
		}
	}
}
