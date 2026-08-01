package verify

import (
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestProtocolApplicableRequiresAtLeastOneProtocolHeader freezes the parser-owner boundary.
func TestProtocolApplicableRequiresAtLeastOneProtocolHeader(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  string
		want bool
	}{
		{name: "unsigned", raw: "From: sender@example.test\r\n\r\nbody\r\n"},
		{name: "instance only", raw: "Message-Instance: invalid\r\n\r\nbody\r\n", want: true},
		{name: "signature only", raw: "DKIM2-Signature: invalid\r\n\r\nbody\r\n", want: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			message, parseErr := rawmsg.Parse([]byte(testCase.raw))
			if parseErr != nil {
				t.Fatalf("Parse() error = %v", parseErr)
			}
			if got := ProtocolApplicable(message); got != testCase.want {
				t.Fatalf("ProtocolApplicable() = %t, want %t", got, testCase.want)
			}
		})
	}
	if ProtocolApplicable(rawmsg.Message{}) {
		t.Fatal("zero message was classified applicable")
	}
}
