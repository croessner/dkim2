package adapter

import (
	"reflect"
	"testing"
)

// TestLocalAuthenticationResultOccurrencesRestrictsMutations proves only
// matching local RFC 8601 authority is deleted and it is deleted descending.
func TestLocalAuthenticationResultOccurrencesRestrictsMutations(t *testing.T) {
	headers := [][]byte{
		[]byte("Authentication-Results: foreign.example; dkim=pass\n"),
		[]byte("Authentication-Results: mx.example.test; dkim=fail\n"),
		[]byte("Authentication-Results: mx.example.test\n\t; dkim=temperror\n"),
		[]byte("Authentication-Results: mx.example.test.evil; dkim=pass\n"),
	}
	if got, want := LocalAuthenticationResultOccurrences(headers, "mx.example.test"), []uint16{3, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("trusted removal occurrences = %v, want %v", got, want)
	}
}
