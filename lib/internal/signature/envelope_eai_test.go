package signature

import (
	"bytes"
	"testing"
)

// TestCanonicalEnvelopePathMapsULabelsToALabels reproduces Draft-08 Section
// 18: SMTP domains are mapped from U-labels to A-labels before comparison,
// while local parts, including RFC 6531 UTF-8 local parts, stay unchanged.
func TestCanonicalEnvelopePathMapsULabelsToALabels(t *testing.T) {
	for input, want := range map[string]string{
		"<user@Bücher.example>":             "<user@xn--bcher-kva.example>",
		"<User@xn--BCHER-kva.Example>":      "<User@xn--bcher-kva.example>",
		"<üser@bücher.example>":             "<üser@xn--bcher-kva.example>",
		"<\"ü ser\"@example.test>":          "<\"ü ser\"@example.test>",
		"<@relay.example:u@bücher.example>": "<@relay.example:u@xn--bcher-kva.example>",
		"<>":                                "<>",
	} {
		got, ok := CanonicalEnvelopePath([]byte(input), true)
		if !ok || string(got) != want {
			t.Fatalf("CanonicalEnvelopePath(%q) = %q/%t, want %q", input, got, ok, want)
		}
	}
	if domain, ok := CanonicalEnvelopeDomain([]byte("<üser@Bücher.example>"), false); !ok || domain != "xn--bcher-kva.example" {
		t.Fatalf("CanonicalEnvelopeDomain() = %q/%t", domain, ok)
	}
	for _, input := range []string{"<user@bücher.example>", "<user@ｅxample.test>", "<\xff@example.test>", "<user@example。test>"} {
		if got, ok := CanonicalEnvelopePath([]byte(input), false); ok || got != nil {
			t.Fatalf("CanonicalEnvelopePath(%q) accepted invalid input", input)
		}
	}
}

// TestRecordableEnvelopePathConvertsOnlyULabelDomains proves that signers
// record A-labels and otherwise keep the caller's exact path bytes.
func TestRecordableEnvelopePathConvertsOnlyULabelDomains(t *testing.T) {
	for input, want := range map[string]string{
		"<üser@Bücher.example>": "<üser@xn--bcher-kva.example>",
		"<User@Example.TEST>":   "<User@Example.TEST>",
		testIPv4LiteralPath:     testIPv4LiteralPath,
		"<>":                    "<>",
	} {
		got, ok := RecordableEnvelopePath([]byte(input), true)
		if !ok || !bytes.Equal(got, []byte(want)) {
			t.Fatalf("RecordableEnvelopePath(%q) = %q/%t, want %q", input, got, ok, want)
		}
	}
}

// TestParseAcceptsRecordedUTF8LocalPart proves that a recorded RFC 6531 local
// part is accepted unchanged when the domain is an A-label.
func TestParseAcceptsRecordedUTF8LocalPart(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("rt", baseValue("<üser@xn--bcher-kva.example>"))))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.Recipients()[0].Value(); !bytes.Equal(got, []byte("<üser@xn--bcher-kva.example>")) {
		t.Fatalf("recorded recipient = %q", got)
	}
}

// TestUnsignedTargetRecordsALabelEnvelopeDomains proves that a signer given
// an SMTPUTF8 envelope records A-label domains and unchanged local parts.
func TestUnsignedTargetRecordsALabelEnvelopeDomains(t *testing.T) {
	request := TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1700000000,
		MailFrom:   []byte("<sénder@Bücher.example>"),
		Recipients: [][]byte{[]byte("<üser@例え.テスト>")},
		Domain:     "xn--bcher-kva.example",
		Sets:       []SetPlan{{Selector: "sel", Algorithm: AlgorithmEd25519SHA256}},
	}
	target, err := NewUnsignedTarget(request, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	field := target.UnsignedBytes()
	for _, want := range []string{"<sénder@xn--bcher-kva.example>", "<üser@xn--r8jz45g.xn--zckzah>"} {
		if !bytes.Contains(field, []byte(baseValue(want))) {
			t.Fatalf("unsigned target does not record %q", want)
		}
	}
}
