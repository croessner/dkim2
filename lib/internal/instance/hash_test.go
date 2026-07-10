package instance

import (
	"bytes"
	"testing"
)

// TestAccessorsReturnImmutableCopies verifies parsed state cannot be mutated.
func TestAccessorsReturnImmutableCopies(t *testing.T) {
	field := messageInstanceField(t, 3, "m=1; h=sha256:"+base64OfByte(0x33, 32)+":"+base64OfByte(0x44, 32)+"; r="+base64OfByte(0x55, 4))
	parsed, err := Parse(field)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	hashes := parsed.HashSets()
	hashes[0] = HashSet{}
	hashes = parsed.HashSets()
	if len(hashes) != 1 || hashes[0].Name() != HashAlgorithmSHA256 {
		t.Fatalf("HashSets() after slice mutation = %#v", hashes)
	}

	headerValue := hashes[0].HeaderHashValue()
	headerValue[0] = 'X'
	if got := hashes[0].HeaderHashValue(); bytes.Equal(got, headerValue) {
		t.Fatalf("HeaderHashValue() reused mutable storage")
	}

	headerHash, ok := hashes[0].HeaderHash()
	if !ok {
		t.Fatal("HeaderHash() missing")
	}
	decoded := headerHash.Decoded()
	decoded[0] = 0
	if got := headerHash.Decoded(); bytes.Equal(got, decoded) {
		t.Fatalf("HeaderHash().Decoded() reused mutable storage")
	}

	recipe, ok := parsed.Recipe()
	if !ok {
		t.Fatal("Recipe() missing")
	}
	recipeBytes := recipe.Decoded()
	recipeBytes[0] = 0
	if got := recipe.Decoded(); bytes.Equal(got, recipeBytes) {
		t.Fatalf("Recipe().Decoded() reused mutable storage")
	}
}
