package daemon

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

// TestMapProcessRequestPreservesObservedBytes proves local-scan reconstruction,
// SMTPUTF8 envelope fidelity, duplicate order, and the exact generated enum.
func TestMapProcessRequestPreservesObservedBytes(t *testing.T) {
	request, err := adapter.NewLocalScanRequest(
		bytes.Repeat([]byte{'a'}, 64),
		adapter.SessionSMTP,
		nil,
		0,
		nil,
		nil,
		[]byte("<séndér@example.test>"),
		[][]byte{
			[]byte("<first@example.test>"),
			[]byte("<first@example.test>"),
		},
		[][]byte{
			[]byte("Subject: value\n"),
			[]byte("X-Folded: first\n\tsecond\n"),
		},
		[]byte("body\nexisting\r\nbare\rnul\x00"),
	)
	if err != nil {
		t.Fatal("valid local-scan request construction failed")
	}
	mapped, err := MapProcessRequest(request, "mx.example.test")
	if err != nil {
		t.Fatal("valid process mapping failed")
	}
	want := []byte(
		"Subject: value\r\nX-Folded: first\r\n\tsecond\r\n\r\n" +
			"body\r\nexisting\r\nbare\rnul\x00",
	)
	if got := decodeMessage(t, mapped.Message); !bytes.Equal(got, want) {
		t.Fatal("local-scan reconstruction changed observed bytes")
	}
	if mapped.Message.Fidelity == nil ||
		*mapped.Message.Fidelity != generated.EximLocalScanObservedCrlf ||
		mapped.Reporting == nil || mapped.Reporting.AuthservId != "mx.example.test" {
		t.Fatal("process mapping changed generated authority or fidelity")
	}
	assertSMTP(t, mapped.Smtp, "<séndér@example.test>", []string{
		"<first@example.test>", "<first@example.test>",
	})
}

// TestMapProcessRequestCanonicalizesBareEximPaths proves local-scan evidence
// and transport-filter authority reach the daemon in one RFC 5321 form.
func TestMapProcessRequestCanonicalizesBareEximPaths(t *testing.T) {
	request, err := adapter.NewLocalScanRequest(
		bytes.Repeat([]byte{'a'}, 64), adapter.SessionSMTP, nil, 0, nil, nil,
		[]byte("mü@example.test"), [][]byte{[]byte("recipient@example.test")},
		[][]byte{[]byte("Subject: canonical paths\n")}, []byte("body\n"),
	)
	if err != nil {
		t.Fatal("valid bare Exim paths failed local-scan construction")
	}
	mapped, err := MapProcessRequest(request, "")
	if err != nil {
		t.Fatal("bare Exim paths failed process mapping")
	}
	assertSMTP(t, mapped.Smtp, "<mü@example.test>", []string{"<recipient@example.test>"})
}

// TestMapSignRequestUsesOnlyOutgoingAuthority proves the generated sign DTO
// carries the current one-recipient delivery batch and transport fidelity.
func TestMapSignRequestUsesOnlyOutgoingAuthority(t *testing.T) {
	outgoing, err := adapter.NewOutgoingEnvelope(
		[]byte("<current@example.test>"), []byte("<batch@example.net>"),
	)
	if err != nil {
		t.Fatal("valid outgoing construction failed")
	}
	input, err := adapter.NewSignRequest(
		[]byte("Subject: sign\n\nbody"), outgoing,
	)
	if err != nil {
		t.Fatal("valid sign request construction failed")
	}
	mapped, err := MapSignRequest(input, "tenant-1", "example.test")
	if err != nil {
		t.Fatal("valid sign mapping failed")
	}
	if mapped.Context.Tenant != "tenant-1" || mapped.Context.Domain != "example.test" ||
		mapped.Message.Fidelity == nil ||
		*mapped.Message.Fidelity != generated.EximTransportFilterCrlf {
		t.Fatal("sign mapping changed generated context or fidelity")
	}
	assertSMTP(t, mapped.Smtp, "<current@example.test>", []string{"<batch@example.net>"})
	if got := decodeMessage(t, mapped.Message); string(got) !=
		"Subject: sign\r\n\r\nbody\r\n" {
		t.Fatal("transport-filter conversion changed message bytes")
	}
}

// FuzzMapTransportFilterMessage proves LF reconstruction preserves every
// non-line-ending byte and never doubles an inherited CRLF sequence.
func FuzzMapTransportFilterMessage(f *testing.F) {
	f.Add([]byte("Subject: seed\n\nbody\n"))
	f.Add([]byte("Subject: seed\r\n\r\nbody\r\n"))
	f.Add([]byte("\nbody\x00\r\nbare\r\n"))
	f.Fuzz(func(t *testing.T, message []byte) {
		if len(message) > 1<<20 {
			return
		}
		mapped, err := mapTransportFilterMessage(append([]byte(nil), message...))
		if err != nil {
			return
		}
		protected, err := mapped.RawRfc5322Base64.Bytes()
		if err != nil {
			t.Fatal("mapped transport message lost protected encoding")
		}
		defer clear(protected)
		actual, err := base64.StdEncoding.Strict().DecodeString(string(protected))
		if err != nil {
			t.Fatal("mapped transport message was not canonical base64")
		}
		defer clear(actual)
		expected := make([]byte, 0, len(message)+bytes.Count(message, []byte{'\n'}))
		previous := byte(0)
		for _, current := range message {
			if current == '\n' && previous != '\r' {
				expected = append(expected, '\r')
			}
			expected = append(expected, current)
			previous = current
		}
		defer clear(expected)
		if !bytes.Equal(actual, expected) {
			t.Fatal("transport LF reconstruction changed admitted bytes")
		}
	})
}

// TestMapReviseRequestKeepsIncomingAndOutgoingDistinct proves neither SMTP
// authority can be aliased or substituted for the other generated member.
func TestMapReviseRequestKeepsIncomingAndOutgoingDistinct(t *testing.T) {
	incoming, err := adapter.NewIncomingEvidence(
		[]byte("<incoming-marker@example.test>"),
		[][]byte{[]byte("<incoming-recipient-marker@example.net>")},
		adapter.SessionSMTP,
	)
	if err != nil {
		t.Fatal("valid incoming evidence construction failed")
	}
	outgoing, err := adapter.NewOutgoingEnvelope(
		[]byte("<outgoing-marker@example.test>"),
		[]byte("<outgoing-recipient-marker@example.net>"),
	)
	if err != nil {
		t.Fatal("valid outgoing evidence construction failed")
	}
	input, err := adapter.NewReviseRequest(
		[]byte("Subject: revise\n\nbody\n"), outgoing, incoming,
	)
	if err != nil {
		t.Fatal("valid revise request construction failed")
	}
	mapped, err := MapReviseRequest(input, "tenant", "example.test")
	if err != nil {
		t.Fatal("valid revise mapping failed")
	}
	assertSMTP(t, mapped.IncomingSmtp, "<incoming-marker@example.test>",
		[]string{"<incoming-recipient-marker@example.net>"})
	assertSMTP(t, mapped.Smtp, "<outgoing-marker@example.test>",
		[]string{"<outgoing-recipient-marker@example.net>"})
	if mapped.Message.Fidelity == nil ||
		*mapped.Message.Fidelity != generated.EximTransportFilterCrlf {
		t.Fatal("revise mapping changed transport-filter fidelity")
	}
}

// TestRequestMappingRejectsInvalidAuthority proves generated DTO creation
// fails before non-ASCII outgoing or invalid administrative values escape.
func TestRequestMappingRejectsInvalidAuthority(t *testing.T) {
	if _, err := mapSMTP(
		[]byte("<séndér@example.test>"),
		[][]byte{[]byte("<recipient@example.net>")},
		true,
	); err == nil {
		t.Fatal("non-ASCII outgoing sender was accepted")
	}
	if _, err := mapSMTP(
		[]byte("<sender@example.test>"),
		[][]byte{[]byte("<récipient@example.net>")},
		true,
	); err == nil {
		t.Fatal("non-ASCII outgoing recipient was accepted")
	}
	if validSigningContext("Tenant", "example.test") ||
		validSigningContext("tenant", "Example.test") ||
		validAdministrativeDomain("-invalid.example") {
		t.Fatal("invalid generated administrative authority was accepted")
	}
}

// decodeMessage returns decoded generated message bytes for structural tests.
func decodeMessage(t *testing.T, message generated.MessageInput) []byte {
	t.Helper()
	encoded, err := message.RawRfc5322Base64.Bytes()
	if err != nil {
		t.Fatal("protected generated message was invalid")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil {
		t.Fatal("generated message was not canonical base64")
	}
	return raw
}

// assertSMTP verifies protected generated SMTP members without formatting them.
func assertSMTP(
	t *testing.T,
	value generated.SMTPInput,
	mailFrom string,
	recipients []string,
) {
	t.Helper()
	reverse, err := value.MailFrom.Bytes()
	if err != nil || string(reverse) != mailFrom || len(value.RcptTo) != len(recipients) {
		t.Fatal("generated SMTP reverse path or recipient count changed")
	}
	for index := range recipients {
		path, pathErr := value.RcptTo[index].Bytes()
		if pathErr != nil || string(path) != recipients[index] {
			t.Fatal("generated SMTP recipient order or bytes changed")
		}
	}
}
