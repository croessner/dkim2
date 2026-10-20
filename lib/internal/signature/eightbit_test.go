package signature

import (
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestParseRejectsEightBitSignatureValues proves that the DKIM2-Signature
// parsers stay ASCII-only now that the raw-message parser accepts 8-bit
// header octets: an 8-bit byte in an unknown extension tag or in a known tag
// value is malformed.
func TestParseRejectsEightBitSignatureValues(t *testing.T) {
	const valid = "i=1; m=1; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=sel:ed25519-sha256:" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	if _, err := Parse(eightBitField(t, valid)); err != nil {
		t.Fatalf("Parse(valid control) error = %v", err)
	}
	for _, value := range []string{
		valid + "; x=\xff",
		"i=1; m=1; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=caf\xe9.example; s=sel:ed25519-sha256:AAAA",
		valid + "; n=nonce\xe9",
	} {
		if _, err := Parse(eightBitField(t, value)); err == nil {
			t.Fatalf("Parse() accepted an 8-bit DKIM2-Signature value")
		}
	}
}

// eightBitField parses one DKIM2-Signature header occurrence with raw bytes.
func eightBitField(t *testing.T, value string) rawmsg.HeaderField {
	t.Helper()
	message, err := rawmsg.Parse([]byte("DKIM2-Signature: " + value + "\r\n\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	return message.Headers().FieldsByName(HeaderName)[0]
}
