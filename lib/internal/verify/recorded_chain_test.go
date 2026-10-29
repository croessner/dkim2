package verify

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/recipe"
)

// recordedSubjectHeader is the header name the list hop of the fixture rewrites.
const recordedSubjectHeader = "subject"

// recordedChainMessage builds an unsigned three-hop message: the origin, a list that
// rewrote Subject and the body under Message-Instance 2, and a relay that re-signed m=2.
func recordedChainMessage(t *testing.T, recipeJSON string) verificationFixture {
	t.Helper()
	hashSet := "sha256:" + base64.StdEncoding.EncodeToString(bytesOf(0x11, 32)) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0x22, 32))
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	hop := func(sequence uint64, instance, domain string) string {
		field := strings.Replace(signatureField(sequence, placeholder), "m=1", "m="+instance, 1)
		return "DKIM2-Signature: " + strings.Replace(field, "d="+testDomain, "d="+domain, 1) + "\r\n"
	}
	raw := baseVerificationHeaders() +
		"Message-Instance: m=1; h=" + hashSet + ";\r\n" +
		"Message-Instance: m=2; h=" + hashSet + "; r=" + base64.StdEncoding.EncodeToString([]byte(recipeJSON)) + ";\r\n" +
		hop(1, "1", testDomain) + hop(2, "2", "lists.example.test") + hop(3, "2", "relay.example.test") +
		"\r\n" + verificationBody()
	parsed, err := parseVerificationFixture(raw)
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	return parsed
}

// TestDescribeRecordedChainAttributesRecipeToIntroducingHop locks hop order and Recipe ownership.
func TestDescribeRecordedChainAttributesRecipeToIntroducingHop(t *testing.T) {
	fixture := recordedChainMessage(t, `{"h":{"subject":[{"d":["[list] original"]}]},"b":[{"c":[1,1]}]}`)
	hops, err := DescribeRecordedChain(fixture.message)
	if err != nil || len(hops) != 3 {
		t.Fatalf("DescribeRecordedChain() = %d hops, %v", len(hops), err)
	}
	origin, list, relay := hops[0], hops[1], hops[2]
	if origin.Sequence() != 1 || origin.SignerDomain() != testDomain || origin.RecipeMode() != VerifierRecipeUnchanged || !origin.IntroducesInstance() {
		t.Fatalf("origin hop = seq %d %q %q introduces=%t", origin.Sequence(), origin.SignerDomain(), origin.RecipeMode(), origin.IntroducesInstance())
	}
	if list.SignerDomain() != "lists.example.test" || list.MessageInstance() != 2 || list.RecipeMode() != VerifierRecipeApplied || !list.IntroducesInstance() {
		t.Fatalf("list hop = %q m=%d %q introduces=%t", list.SignerDomain(), list.MessageInstance(), list.RecipeMode(), list.IntroducesInstance())
	}
	if !slices.Equal(list.Recipe().AffectedHeaders(), []string{recordedSubjectHeader}) || list.Recipe().BodyMode() != recipe.BodyModeSteps ||
		!slices.Equal(list.Recipe().ChangeClasses(), []recipe.ChangeClass{recipe.ChangeClassBodyRewrite, recipe.ChangeClassHeaderRewrite}) {
		t.Fatalf("list recipe = %v %q %v", list.Recipe().AffectedHeaders(), list.Recipe().BodyMode(), list.Recipe().ChangeClasses())
	}
	if relay.SignerDomain() != "relay.example.test" || relay.MessageInstance() != 2 || relay.IntroducesInstance() || relay.RecipeMode() != VerifierRecipeUnchanged {
		t.Fatalf("relay hop = %q m=%d introduces=%t %q", relay.SignerDomain(), relay.MessageInstance(), relay.IntroducesInstance(), relay.RecipeMode())
	}
	for _, hop := range hops {
		if !hop.Valid() || strings.Contains(hop.String()+hop.GoString(), "example") {
			t.Fatalf("hop invalid or leaking: %s", hop.String())
		}
	}
}

// TestDescribeRecordedChainReportsUnavailableBody describes a null body Recipe as recorded; a
// verifier never passes such a chain (Draft-08 Section 13), so trusted consumers do not see it.
func TestDescribeRecordedChainReportsUnavailableBody(t *testing.T) {
	fixture := recordedChainMessage(t, `{"b":null}`)
	hops, err := DescribeRecordedChain(fixture.message)
	if err != nil || len(hops) != 3 || hops[1].Recipe().BodyMode() != recipe.BodyModeUnavailable || hops[1].Recipe().HasHeaderChanges() {
		t.Fatalf("DescribeRecordedChain() = %d hops, %v", len(hops), err)
	}
}

// TestDescribeRecordedChainRejectsMalformedRecipe fails closed instead of describing part of a chain.
func TestDescribeRecordedChainRejectsMalformedRecipe(t *testing.T) {
	for name, recipeJSON := range map[string]string{
		"not json":        `{"h":`,
		"unsigned header": `{"h":{"x-unsigned-trace":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := recordedChainMessage(t, recipeJSON)
			if hops, err := DescribeRecordedChain(fixture.message); err == nil || hops != nil {
				t.Fatalf("DescribeRecordedChain() = %d hops, %v; want error", len(hops), err)
			}
		})
	}
}

// TestDescribeRecordedChainRejectsUninitializedMessage guards the zero message.
func TestDescribeRecordedChainRejectsUninitializedMessage(t *testing.T) {
	if _, err := DescribeRecordedChain(verificationFixture{}.message); !IsErrorCode(err, ErrorCodeInternalMisuse) {
		t.Fatalf("DescribeRecordedChain(zero) error = %v", err)
	}
}

// recordedChainFields parses an unsigned message from explicit DKIM2 fields.
func recordedChainFields(t *testing.T, fields string) verificationFixture {
	t.Helper()
	parsed, err := parseVerificationFixture(baseVerificationHeaders() + fields + "\r\n" + verificationBody())
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	return parsed
}

// recordedChainSignature renders one placeholder DKIM2-Signature field for sequence and instance.
func recordedChainSignature(sequence uint64, instance, domain string) string {
	placeholder := testSelector + ":" + string(AlgorithmRSASHA256) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0xa5, 128))
	field := strings.Replace(signatureField(sequence, placeholder), "m=1", "m="+instance, 1)
	return "DKIM2-Signature: " + strings.Replace(field, "d="+testDomain, "d="+domain, 1) + "\r\n"
}

// TestDescribeRecordedChainEnforcesVerifierCollectionRules refuses shapes the verifier never passes.
func TestDescribeRecordedChainEnforcesVerifierCollectionRules(t *testing.T) {
	hashSet := "sha256:" + base64.StdEncoding.EncodeToString(bytesOf(0x11, 32)) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0x22, 32))
	instances := func(numbers ...string) string {
		var fields string
		for _, number := range numbers {
			fields += "Message-Instance: m=" + number + "; h=" + hashSet + ";\r\n"
		}
		return fields
	}
	for name, fields := range map[string]string{
		"decreasing m=": instances("1", "2") + recordedChainSignature(1, "2", testDomain) + recordedChainSignature(2, "1", "lists.example.test"),
		"highest instance unsigned": instances("1", "2", "3") + recordedChainSignature(1, "1", testDomain) +
			recordedChainSignature(2, "2", "lists.example.test"),
	} {
		t.Run(name, func(t *testing.T) {
			if hops, err := DescribeRecordedChain(recordedChainFields(t, fields).message); err == nil || hops != nil {
				t.Fatalf("DescribeRecordedChain() = %d hops, %v; want error", len(hops), err)
			}
		})
	}
}

// TestDescribeRecordedChainNewInstanceWithoutRecipe reports a revision without recorded changes.
func TestDescribeRecordedChainNewInstanceWithoutRecipe(t *testing.T) {
	hashSet := "sha256:" + base64.StdEncoding.EncodeToString(bytesOf(0x11, 32)) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0x22, 32))
	fields := "Message-Instance: m=1; h=" + hashSet + ";\r\nMessage-Instance: m=2; h=" + hashSet + ";\r\n" +
		recordedChainSignature(1, "1", testDomain) + recordedChainSignature(2, "2", "lists.example.test")
	hops, err := DescribeRecordedChain(recordedChainFields(t, fields).message)
	if err != nil || len(hops) != 2 || !hops[1].IntroducesInstance() || hops[1].RecipeMode() != VerifierRecipeUnchanged {
		t.Fatalf("DescribeRecordedChain() = %d hops, %v", len(hops), err)
	}
}
