package dkim2

import (
	"bytes"
	"fmt"
	"testing"
)

// TestCompositeSigningKeyCodecRoundTrips proves the public composite key
// codecs agree byte for byte and fail closed on short entropy.
func TestCompositeSigningKeyCodecRoundTrips(t *testing.T) {
	seeds := bytes.Repeat([]byte{0x5a}, 64)
	first, err := GenerateCompositeSigningKeyFrom(bytes.NewReader(seeds))
	if err != nil || !first.Valid() {
		t.Fatalf("GenerateCompositeSigningKeyFrom() valid=%t error=%v", first.Valid(), err)
	}
	second, err := GenerateCompositeSigningKeyFrom(bytes.NewReader(seeds))
	if err != nil || !bytes.Equal(first.MarshalPKCS8(), second.MarshalPKCS8()) {
		t.Fatalf("deterministic generation diverged: error=%v", err)
	}
	parsed, err := ParseCompositeSigningKeyPKCS8(first.MarshalPKCS8())
	if err != nil || !bytes.Equal(parsed.PublicKey(), first.PublicKey()) {
		t.Fatalf("ParseCompositeSigningKeyPKCS8() error=%v", err)
	}
	raw := first.PublicKey()
	if len(raw) != 1344 {
		t.Fatalf("PublicKey() length = %d", len(raw))
	}
	spki, err := MarshalCompositePublicKeySPKI(raw)
	if err != nil || !bytes.Equal(spki, first.PublicKeySPKI()) {
		t.Fatalf("MarshalCompositePublicKeySPKI() error=%v", err)
	}
	decoded, err := ParseCompositePublicKeySPKI(spki)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("ParseCompositePublicKeySPKI() error=%v", err)
	}
	if _, err := MarshalCompositePublicKeySPKI(raw[:len(raw)-1]); err == nil {
		t.Fatal("MarshalCompositePublicKeySPKI(short) accepted")
	}
	if _, err := ParseCompositeSigningKeyPKCS8(append(first.MarshalPKCS8(), 0)); err == nil {
		t.Fatal("ParseCompositeSigningKeyPKCS8(trailing byte) accepted")
	}
	if _, err := GenerateCompositeSigningKeyFrom(bytes.NewReader(seeds[:63])); err == nil {
		t.Fatal("GenerateCompositeSigningKeyFrom(short entropy) accepted")
	}
	if _, err := GenerateCompositeSigningKeyFrom(nil); err == nil {
		t.Fatal("GenerateCompositeSigningKeyFrom(nil) accepted")
	}
	if got := fmt.Sprintf("%v %+v %#v %s", first, first, first, first); bytes.Contains([]byte(got), seeds[:8]) ||
		got != "dkim2.CompositeSigningKey{redacted} dkim2.CompositeSigningKey{redacted} dkim2.CompositeSigningKey{redacted} dkim2.CompositeSigningKey{redacted}" {
		t.Fatalf("formatted key = %q", got)
	}
	shared := first
	first.Clear()
	if first.Valid() || first.MarshalPKCS8() != nil {
		t.Fatal("Clear() retained key material")
	}
	if shared.Valid() || shared.MarshalPKCS8() != nil {
		t.Fatal("copy sharing cleared seeds still reports a valid key")
	}
	if _, err := GenerateCompositeSigningKeyFrom(bytes.NewReader(make([]byte, 64))); err == nil {
		t.Fatal("GenerateCompositeSigningKeyFrom(all-zero seeds) accepted")
	}
}
