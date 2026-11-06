package verify

import (
	"encoding/base64"
	"fmt"
	"slices"
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

// TestFromAuthenticityFollowsDraft09Section11 reproduces the pure phase of
// the Draft-09 Sections 11, 11.1, and 14.8 rules on the From states of an
// authenticated history. States are ordered from the highest m= down to m=1.
// A state that only the reversed (upward) match makes Authentic is accepted
// as a candidate whose Domain Policy Record still decides it; candidates are
// deduplicated by A-label From domain in field order.
func TestFromAuthenticityFollowsDraft09Section11(t *testing.T) {
	origin := fromTestSignature(t, 1, 1, "example.test")
	forwarder := fromTestSignature(t, 2, 1, "forwarder.test")
	reviser := fromTestSignature(t, 2, 2, "list.test")
	subOrigin := fromTestSignature(t, 1, 1, "mail.example.test")
	subReviser := fromTestSignature(t, 2, 2, "lists.example.test")
	tests := []struct {
		name       string
		states     []recipe.State
		signatures []signature.Signature
		accepted   bool
		offending  uint64
		upward     []string
	}{
		{"authentic original", []recipe.State{fromTestState(t, "a@example.test")}, []signature.Signature{origin}, true, 0, nil},
		{"relaxed original", []recipe.State{fromTestState(t, "Name <a@mail.example.test>")}, []signature.Signature{origin}, true, 0, nil},
		{"forged original", []recipe.State{fromTestState(t, "a@other.test")}, []signature.Signature{origin}, false, 1, nil},
		{"parent From is an upward candidate", []recipe.State{fromTestState(t, "a@test")}, []signature.Signature{origin}, true, 0, []string{"test"}},
		{"subdomain d is an upward candidate", []recipe.State{fromTestState(t, "a@example.test")}, []signature.Signature{subOrigin}, true, 0, []string{testDomain}},
		{"sibling never matches", []recipe.State{fromTestState(t, "a@other.example.test")}, []signature.Signature{subOrigin}, false, 1, nil},
		{"suffix without label boundary never matches", []recipe.State{fromTestState(t, "a@ample.test")}, []signature.Signature{origin}, false, 1, nil},
		{"upward candidates deduplicated", []recipe.State{fromTestState(t, "b@example.test"), fromTestState(t, "a@example.test")}, []signature.Signature{subOrigin, subReviser}, true, 0, []string{testDomain}},
		{"upward candidates in field order", []recipe.State{fromTestState(t, "b@lists.example.test"), fromTestState(t, "a@example.test")}, []signature.Signature{subOrigin, fromTestSignature(t, 2, 2, "x.lists.example.test")}, true, 0, []string{testDomain, "lists." + testDomain}},
		{"forwarder keeps original From", []recipe.State{fromTestState(t, "a@example.test")}, []signature.Signature{origin, forwarder}, true, 0, nil},
		{"aligned rewrite", []recipe.State{fromTestState(t, "list@list.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin, reviser}, true, 0, nil},
		{"unaligned rewrite", []recipe.State{fromTestState(t, "list@example.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin, reviser}, false, 2, nil},
		{"unchanged From after revision stays with origin", []recipe.State{fromTestState(t, "a@example.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin, reviser}, true, 0, nil},
		{"forged origin under later aligned state", []recipe.State{fromTestState(t, "list@list.test"), fromTestState(t, "a@other.test")}, []signature.Signature{origin, reviser}, false, 1, nil},
		{"not authentic rejects before later upward candidate", []recipe.State{fromTestState(t, "b@example.test"), fromTestState(t, "a@other.test")}, []signature.Signature{origin, subReviser}, false, 1, nil},
		{"multiple mailboxes", []recipe.State{fromTestState(t, "a@example.test, b@example.test")}, []signature.Signature{origin}, false, 1, nil},
		{"multiple mailboxes under subdomain d", []recipe.State{fromTestState(t, "a@example.test, b@example.test")}, []signature.Signature{subOrigin}, false, 1, nil},
		{"one-mailbox group", []recipe.State{fromTestState(t, "Team: a@example.test;")}, []signature.Signature{origin}, true, 0, nil},
		{"empty group", []recipe.State{fromTestState(t, "Team: ;")}, []signature.Signature{origin}, false, 1, nil},
		{"domain literal", []recipe.State{fromTestState(t, "a@[192.0.2.1]")}, []signature.Signature{origin}, false, 1, nil},
		{"missing From", []recipe.State{fromTestState(t)}, []signature.Signature{origin}, false, 1, nil},
		{"duplicate From", []recipe.State{fromTestState(t, "a@example.test", "a@example.test")}, []signature.Signature{origin}, false, 1, nil},
		{"EAI domain", []recipe.State{fromTestState(t, "jörg@bücher.example")}, []signature.Signature{fromTestSignature(t, 1, 1, "xn--bcher-kva.example")}, true, 0, nil},
		{"EAI upward candidate uses the A-label", []recipe.State{fromTestState(t, "jörg@bücher.example")}, []signature.Signature{fromTestSignature(t, 1, 1, "mail.xn--bcher-kva.example")}, true, 0, []string{"xn--bcher-kva.example"}},
		{"no responsible signature", []recipe.State{fromTestState(t, "x@list.test"), fromTestState(t, "a@example.test")}, []signature.Signature{origin}, false, 0, nil},
	}
	for _, test := range tests {
		plan := classifyFromAuthenticity(test.states, test.signatures)
		if plan.accepted != test.accepted || plan.offending != test.offending || !slices.Equal(plan.upward, test.upward) {
			t.Fatalf("%s: accepted=%t offending=%d upward=%q, want %t/%d/%q", test.name, plan.accepted, plan.offending, plan.upward, test.accepted, test.offending, test.upward)
		}
	}
}

// TestSignerFromAuthenticForStaysDownwardOnly pins disposition D8: the
// signer and DSN identity rule never uses the upward match.
func TestSignerFromAuthenticForStaysDownwardOnly(t *testing.T) {
	headers := fromTestState(t, "a@example.test").Headers()
	if !SignerFromAuthenticFor(headers, "example.test") || !SignerFromAuthenticFor(headers, "test") {
		t.Fatal("downward signer match rejected")
	}
	if SignerFromAuthenticFor(headers, "mail.example.test") {
		t.Fatal("signer accepted an upward match")
	}
}
