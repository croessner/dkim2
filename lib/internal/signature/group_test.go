package signature

import (
	"bytes"
	"slices"
	"testing"

	"github.com/croessner/dkim2/internal/combine"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

// TestSignatureSetFWSPositions pins every Draft-08 Section 10.9 white-space
// position of sig-s-tag: [FWS] after "=", around the selector, around
// sig-name, before and inside message-sig, and around "," are accepted;
// white space inside a selector or a sig-name is rejected.
func TestSignatureSetFWSPositions(t *testing.T) {
	sig := base64OfByte(0xaa, 64)
	other := "two:ed25519-sha256:" + base64OfByte(0xbb, 64)
	accepted := map[string]string{
		"after equals":            " \tone:ed25519-sha256:" + sig,
		"before first colon":      "one \t:ed25519-sha256:" + sig,
		"after first colon":       "one: \ted25519-sha256:" + sig,
		"before second colon":     "one:ed25519-sha256 \t:" + sig,
		"before message-sig":      "one:ed25519-sha256: \t" + sig,
		"inside message-sig":      "one:ed25519-sha256:" + sig[:10] + " \t" + sig[10:],
		"inside padding":          "one:ed25519-sha256:" + sig[:len(sig)-2] + "= =",
		"after message-sig":       "one:ed25519-sha256:" + sig + " \t",
		"around comma":            "one:ed25519-sha256:" + sig + " \t, \t" + other,
		"tab before comma no wsp": "one:ed25519-sha256:" + sig + "\t," + other,
	}
	for name, value := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", value)))
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", value, err)
			}
			if parsed.SignatureLayout().Sets() != len(parsed.SignatureSets()) {
				t.Fatalf("SignatureLayout() = %v", parsed.SignatureLayout().GroupSizes())
			}
		})
	}
	rejected := map[string]string{
		"inside selector":       "o ne:ed25519-sha256:" + sig,
		"inside sig-name":       "one:ed25519 -sha256:" + sig,
		"empty selector":        " :ed25519-sha256:" + sig,
		"empty message-sig":     "one:ed25519-sha256: \t",
		"leading comma":         "," + "one:ed25519-sha256:" + sig,
		"trailing comma":        "one:ed25519-sha256:" + sig + ",",
		"doubled comma":         "one:ed25519-sha256:" + sig + ",," + other,
		"leading bar":           "|one:ed25519-sha256:" + sig,
		"trailing bar":          "one:ed25519-sha256:" + sig + "|",
		"doubled bar":           "one:ed25519-sha256:" + sig + "||" + other,
		"empty group wsp only":  "one:ed25519-sha256:" + sig + "| \t|" + other,
		"comma before bar":      "one:ed25519-sha256:" + sig + ",|" + other,
		"bar before comma":      "one:ed25519-sha256:" + sig + "|," + other,
		"missing message colon": "one:ed25519-sha256",
	}
	for name, value := range rejected {
		t.Run("rejected/"+name, func(t *testing.T) {
			if _, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", value))); !IsErrorCode(err, ErrorCodeMalformedSignatureSet) {
				t.Fatalf("Parse(%q) error = %v, want malformed signature set", value, err)
			}
		})
	}
}

// TestSignatureGroupsRejectDuplicateSelectorAcrossGroups pins Section 10.9:
// a Selector must not appear more than once in one DKIM2-Signature, in any
// group, compared case-insensitively as a DNS name.
func TestSignatureGroupsRejectDuplicateSelectorAcrossGroups(t *testing.T) {
	value := "one:ed25519-sha256:" + base64OfByte(0xaa, 64) + " | ONE:rsa-sha256:" + base64OfByte(0xbb, 128)
	if _, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", value))); !IsErrorCode(err, ErrorCodeDuplicateSelector) {
		t.Fatalf("Parse() error = %v, want duplicate selector across groups", err)
	}
}

// TestSignatureGroupsCountSetsAcrossGroupsForLimit pins that
// max_signature_sets counts every set in every group.
func TestSignatureGroupsCountSetsAcrossGroupsForLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxSignatureSets = 2
	parser, err := NewParser(limits)
	if err != nil {
		t.Fatal(err)
	}
	value := "a:x:YQ==|b:x:YQ==|c:x:YQ=="
	if _, err := parser.ParseField(dkim2SignatureField(t, 0, signatureValueWith("s", value))); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseField() error = %v, want limit exceeded", err)
	}
}

// TestSignatureAlternativeGroupsFailClosedUntilAlgebra pins that a "|"
// alternative group is rejected while the Section 14.6 combination is not
// evaluated.
func TestSignatureAlternativeGroupsFailClosedUntilAlgebra(t *testing.T) {
	value := "one:ed25519-sha256:" + base64OfByte(0xaa, 64) + "|two:" + testExtensionAlgorithm + ":" + base64OfByte(0xbb, 48)
	if _, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", value))); !IsErrorCode(err, ErrorCodeMalformedSignatureSet) {
		t.Fatalf("Parse() error = %v, want malformed signature set", err)
	}
}

// TestUnsignedSignatureValueKeepsReceivedSpelling proves the Section 12.8
// unsigned s= value keeps the received selector spelling and algorithm name,
// nulls only the signature values, and removes all white space.
func TestUnsignedSignatureValueKeepsReceivedSpelling(t *testing.T) {
	value := " Sel-One \t: ed25519-sha256 :" + base64OfByte(0xaa, 64) + " , two:" + testExtensionAlgorithm + ": " + base64OfByte(0xbb, 48)
	parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", value)))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parsed.UnsignedSignatureValue()
	if !ok || string(got) != "Sel-One:ed25519-sha256:,two:"+testExtensionAlgorithm+":" {
		t.Fatalf("UnsignedSignatureValue() = %q ok=%t", got, ok)
	}
	if parsed.SignatureSets()[0].Selector() != "sel-one" {
		t.Fatalf("Selector() = %q, want canonical lowercase lookup name", parsed.SignatureSets()[0].Selector())
	}
}

// TestSharedUnsignedRendererKeepsGroupSeparators proves the shared renderer
// emits "|" between groups and "," inside a group with null signatures.
func TestSharedUnsignedRendererKeepsGroupSeparators(t *testing.T) {
	layout, ok := combine.NewLayout(2, 1)
	if !ok {
		t.Fatal("NewLayout rejected")
	}
	sets := []unsignedSetComponent{{"a", string(AlgorithmRSASHA256)}, {"b", string(AlgorithmEd25519SHA256)}, {"c", "mldsa44"}}
	got, ok := appendUnsignedSetList(nil, sets, layout)
	if !ok || string(got) != "a:rsa-sha256:,b:ed25519-sha256:|c:mldsa44:" {
		t.Fatalf("appendUnsignedSetList() = %q ok=%t", got, ok)
	}
	if _, ok := appendUnsignedSetList(nil, sets[:2], layout); ok {
		t.Fatal("appendUnsignedSetList accepted a layout that does not describe the sets")
	}
	if _, ok := appendUnsignedSetList(nil, []unsignedSetComponent{{"", string(AlgorithmRSASHA256)}}, mustSingleGroup(t, 1)); ok {
		t.Fatal("appendUnsignedSetList accepted an empty selector")
	}
}

// TestGeneratedLayoutGroupsClassicalCredentialsFirst pins the fixed signer
// layout: classical algorithms share the first sig-all group in canonical
// order; any other algorithm starts a separate alternative group.
func TestGeneratedLayoutGroupsClassicalCredentialsFirst(t *testing.T) {
	classical := []SetPlan{{Selector: "r", Algorithm: AlgorithmRSASHA256}, {Selector: "e", Algorithm: AlgorithmEd25519SHA256}}
	layout, ok := generatedSetLayout(classical)
	if !ok || !slices.Equal(layout.GroupSizes(), []int{2}) {
		t.Fatalf("generatedSetLayout(classical) = %v ok=%t", layout.GroupSizes(), ok)
	}
	mixed := append(slices.Clone(classical), SetPlan{Selector: "p", Algorithm: Algorithm("mldsa44")})
	layout, ok = generatedSetLayout(mixed)
	if !ok || !slices.Equal(layout.GroupSizes(), []int{2, 1}) {
		t.Fatalf("generatedSetLayout(mixed) = %v ok=%t", layout.GroupSizes(), ok)
	}
	only := []SetPlan{{Selector: "p", Algorithm: Algorithm("mldsa44")}}
	layout, ok = generatedSetLayout(only)
	if !ok || !slices.Equal(layout.GroupSizes(), []int{1}) {
		t.Fatalf("generatedSetLayout(post-quantum only) = %v ok=%t", layout.GroupSizes(), ok)
	}
	if _, ok := generatedSetLayout([]SetPlan{{Selector: "p", Algorithm: Algorithm("mldsa44")}, {Selector: "r", Algorithm: AlgorithmRSASHA256}}); ok {
		t.Fatal("generatedSetLayout accepted plans outside canonical group order")
	}
	if _, ok := generatedSetLayout(nil); ok {
		t.Fatal("generatedSetLayout accepted no plans")
	}
}

// TestSignerUnsignedTargetMatchesVerifierRendering proves the folded
// unsigned field the signer emits reduces, after Section 12.8 white-space
// deletion, to the s= value the verifier renders from the parsed field.
func TestSignerUnsignedTargetMatchesVerifierRendering(t *testing.T) {
	request := TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: []byte("<>"),
		Recipients: [][]byte{[]byte("<user@example.test>")}, Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: "ed", Algorithm: AlgorithmEd25519SHA256}, {Selector: "rsa", Algorithm: AlgorithmRSASHA256}},
	}
	target, err := NewUnsignedTarget(request, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	complete, err := target.Complete([]SetValue{
		{Selector: "rsa", Algorithm: AlgorithmRSASHA256, Signature: bytes.Repeat([]byte{1}, 256)},
		{Selector: "ed", Algorithm: AlgorithmEd25519SHA256, Signature: bytes.Repeat([]byte{2}, 64)},
	})
	if err != nil {
		t.Fatalf("Complete() code=%s", signatureTestErrorCode(err))
	}
	message, err := rawmsg.Parse(complete.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(message.Headers().FieldsByName(HeaderName)[0])
	if err != nil {
		t.Fatal(err)
	}
	verifierValue, ok := parsed.UnsignedSignatureValue()
	if !ok || string(verifierValue) != "rsa:rsa-sha256:,ed:ed25519-sha256:" {
		t.Fatalf("UnsignedSignatureValue() = %q ok=%t", verifierValue, ok)
	}
	unsignedMessage, err := rawmsg.Parse(target.UnsignedBytes())
	if err != nil {
		t.Fatal(err)
	}
	tags, err := tagvalue.ScanHeader(unsignedMessage.Headers().FieldsByName(HeaderName)[0].UnfoldedValue(), knownSignatureTags, tagvalue.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := tags.Get(string(TagNameSignatures))
	if !bytes.Equal(signatureValueWithoutWSP(tag.Value()), verifierValue) {
		t.Fatalf("signer unsigned s= = %q, verifier = %q", signatureValueWithoutWSP(tag.Value()), verifierValue)
	}
	if _, err := target.RebuildUnsignedFromComplete(complete); err != nil {
		t.Fatalf("RebuildUnsignedFromComplete() code=%s", signatureTestErrorCode(err))
	}
}

// mustSingleGroup builds a one-group layout for renderer tests.
func mustSingleGroup(t *testing.T, count int) combine.Layout {
	t.Helper()
	layout, ok := combine.SingleGroup(count)
	if !ok {
		t.Fatal("SingleGroup rejected")
	}
	return layout
}
