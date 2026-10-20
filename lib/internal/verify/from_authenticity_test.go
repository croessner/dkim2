package verify

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

// fromTestSignature builds one syntactically valid DKIM2-Signature for the
// From authenticity unit tests; only i=, m=, and d= matter to the rule.
func fromTestSignature(t *testing.T, sequence, instance uint64, domain string) signature.Signature {
	t.Helper()
	path := base64.StdEncoding.EncodeToString([]byte("<a@" + domain + ">"))
	value := fmt.Sprintf("i=%d; m=%d; t=1700000000; mf=%s; rt=%s; d=%s; s=sel:ed25519-sha256:%s",
		sequence, instance, path, path, domain, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	message, err := rawmsg.Parse([]byte("DKIM2-Signature: " + value + "\r\n\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	parsed, err := signature.Parse(message.Headers().FieldsByName(signature.HeaderName)[0])
	if err != nil {
		t.Fatalf("signature.Parse() error = %v", err)
	}
	return parsed
}

// fromTestState builds one reconstructed message state with the given From lines.
func fromTestState(t *testing.T, fromLines ...string) recipe.State {
	t.Helper()
	var raw strings.Builder
	for _, line := range fromLines {
		raw.WriteString("From: " + line + "\r\n")
	}
	raw.WriteString("Subject: x\r\n\r\nbody\r\n")
	message, err := rawmsg.Parse([]byte(raw.String()))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	state, err := recipe.NewState(message)
	if err != nil {
		t.Fatalf("recipe.NewState() error = %v", err)
	}
	return state
}

// TestFromAuthenticityFollowsDraft07Section11 reproduces the Draft-07
// Sections 11 and 14.8 rules on the From states of an authenticated history.
// States are ordered from the highest m= down to m=1.
func TestFromAuthenticityFollowsDraft07Section11(t *testing.T) {
	origin := fromTestSignature(t, 1, 1, "example.test")
	forwarder := fromTestSignature(t, 2, 1, "forwarder.test")
	reviser := fromTestSignature(t, 2, 2, "list.test")
	tests := []struct {
		name       string
		states     []recipe.State
		signatures []signature.Signature
		accepted   bool
		offending  uint64
	}{
		{"authentic original", []recipe.State{fromTestState(t, "a@example.test")}, []signature.Signature{origin}, true, 0},
		{"relaxed original", []recipe.State{fromTestState(t, "Name <a@mail.example.test>")}, []signature.Signature{origin}, true, 0},
		{"forged original", []recipe.State{fromTestState(t, "a@other.test")}, []signature.Signature{origin}, false, 1},
		{"parent From is not authentic for child d", []recipe.State{fromTestState(t, "a@test")}, []signature.Signature{origin}, false, 1},
		{"forwarder keeps original From", []recipe.State{fromTestState(t, "a@example.test")}, []signature.Signature{origin, forwarder}, true, 0},
		{"aligned rewrite", []recipe.State{fromTestState(t, "list@list.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin, reviser}, true, 0},
		{"unaligned rewrite", []recipe.State{fromTestState(t, "list@example.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin, reviser}, false, 2},
		{"unchanged From after revision stays with origin", []recipe.State{fromTestState(t, "a@example.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin, reviser}, true, 0},
		{"forged origin under later aligned state", []recipe.State{fromTestState(t, "list@list.test"), fromTestState(t, "a@other.test")}, []signature.Signature{origin, reviser}, false, 1},
		{"multiple mailboxes", []recipe.State{fromTestState(t, "a@example.test, b@example.test")}, []signature.Signature{origin}, false, 1},
		{"one-mailbox group", []recipe.State{fromTestState(t, "Team: a@example.test;")}, []signature.Signature{origin}, true, 0},
		{"empty group", []recipe.State{fromTestState(t, "Team: ;")}, []signature.Signature{origin}, false, 1},
		{"domain literal", []recipe.State{fromTestState(t, "a@[192.0.2.1]")}, []signature.Signature{origin}, false, 1},
		{"missing From", []recipe.State{fromTestState(t)}, []signature.Signature{origin}, false, 1},
		{"duplicate From", []recipe.State{fromTestState(t, "a@example.test", "a@example.test")}, []signature.Signature{origin}, false, 1},
		{"EAI domain", []recipe.State{fromTestState(t, "jörg@bücher.example")}, []signature.Signature{fromTestSignature(t, 1, 1, "xn--bcher-kva.example")}, true, 0},
		{"no responsible signature", []recipe.State{fromTestState(t, "x@list.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin}, false, 0},
	}
	for _, test := range tests {
		offending, accepted := fromAuthenticityAccepted(test.states, test.signatures)
		if accepted != test.accepted || offending != test.offending {
			t.Fatalf("%s: accepted=%t offending=%d, want %t/%d", test.name, accepted, offending, test.accepted, test.offending)
		}
	}
}
