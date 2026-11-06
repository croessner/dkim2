package instance

import (
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestParseRejectsEightBitInstanceValues proves that the Message-Instance
// parser stays ASCII-only now that the raw-message parser accepts 8-bit
// header octets: an 8-bit byte in an unknown extension tag, a hash name, or a
// hash value is malformed.
func TestParseRejectsEightBitInstanceValues(t *testing.T) {
	const hashes = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	if _, err := Parse(eightBitInstanceField(t, "m=1; h="+hashes)); err != nil {
		t.Fatalf("Parse(valid control) error = %v", err)
	}
	for _, value := range []string{
		"m=1; h=" + hashes + "; x=\xff",
		"m=1; h=sha\xe9:AAAA:AAAA",
		"m=1; h=sha256:AAAA\xe9:AAAA",
	} {
		if _, err := Parse(eightBitInstanceField(t, value)); err == nil {
			t.Fatalf("Parse() accepted an 8-bit Message-Instance value")
		}
	}
}

// eightBitInstanceField parses one Message-Instance header occurrence with raw bytes.
func eightBitInstanceField(t *testing.T, value string) rawmsg.HeaderField {
	t.Helper()
	message, err := rawmsg.Parse([]byte("Message-Instance: " + value + "\r\n\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	return message.Headers().FieldsByName("message-instance")[0]
}
