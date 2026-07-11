package dkim2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/policy"
)

// TestPolicyFormattingOmitsMessageIdentityKeyAndRouteMaterial proves all formatting surfaces remain bounded.
func TestPolicyFormattingOmitsMessageIdentityKeyAndRouteMaterial(t *testing.T) {
	raw, key := signedPublicFlaggedPolicyMessage(t, publicVectorClock)
	verifier, err := NewVerifier(publicGoldenProvider{mode: goldenProviderKeys, rsa: key}, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	decision, err := EvaluatePolicy(result)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}
	decisions := []PolicyDecision{decision}
	for _, request := range []VerifyRequest{
		NewVerifyRequest([]byte("X-Toxic: TOXIC-MESSAGE\r\n"+strings.Replace(string(raw), "body line", "TOXIC-BODY", 1)), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
		NewVerifyRequest(raw, []byte("<TOXIC-ROUTE@example.test>"), [][]byte{[]byte("<TOXIC-IDENTITY@example.test>")}),
	} {
		variant, verifyErr := verifier.Verify(context.Background(), request)
		if verifyErr != nil {
			t.Fatalf("Verify(toxic variant) error = %v", verifyErr)
		}
		variantDecision, evaluateErr := EvaluatePolicy(variant)
		if evaluateErr != nil {
			t.Fatalf("EvaluatePolicy(toxic variant) error = %v", evaluateErr)
		}
		decisions = append(decisions, variantDecision)
	}
	providerVerifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return PublicKeyResult{}, errors.New("TOXIC-PROVIDER")
	}), WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier(toxic provider) error = %v", err)
	}
	providerResult, err := providerVerifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify(toxic provider) error = %v", err)
	}
	providerDecision, err := EvaluatePolicy(providerResult)
	if err != nil {
		t.Fatalf("EvaluatePolicy(toxic provider) error = %v", err)
	}
	decisions = append(decisions, providerDecision)
	corpus := loadPublicGoldenCorpus(t)
	dnsTransport := &dnsVectorTransport{lookup: func(context.Context, string) (TXTLookupResult, error) {
		return foundPublicTXT(t, "p=TOXIC-DNS-KEY", DNSSECStatusUnavailable), nil
	}}
	dnsResult := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, dnsTransport, DefaultDNSProviderConfig()))
	dnsDecision, err := EvaluatePolicy(dnsResult)
	if err != nil {
		t.Fatalf("EvaluatePolicy(toxic DNS) error = %v", err)
	}
	decisions = append(decisions, dnsDecision)
	toxicOptionDecision, toxicOptionErr := EvaluatePolicy(result, WithPolicyMode(PolicyMode("TOXIC-POLICY-OPTION")))
	if !toxicOptionDecision.IsZero() || toxicOptionErr == nil {
		t.Fatalf("toxic policy option returned %#v/%v", toxicOptionDecision, toxicOptionErr)
	}
	formattedParts := []string{fmt.Sprintf("%v", toxicOptionErr), fmt.Sprintf("%#v", toxicOptionErr)}
	for _, current := range decisions {
		formattedParts = append(formattedParts,
			fmt.Sprintf("%v", current), fmt.Sprintf("%#v", current),
			fmt.Sprintf("%v", current.Findings()), fmt.Sprintf("%#v", current.Findings()),
			fmt.Sprintf("%v", current.ActionPlan()), fmt.Sprintf("%#v", current.ActionPlan()),
			fmt.Sprintf("%v", current.FeedbackIntent()), fmt.Sprintf("%#v", current.FeedbackIntent()),
		)
	}
	formatted := strings.Join(formattedParts, "\n")
	for _, marker := range []string{
		"From: sender", "sender@example.test", "selector.test", "example.test", "body line", "<rcpt@example.test>",
		"TOXIC-MESSAGE", "TOXIC-BODY", "TOXIC-IDENTITY", "TOXIC-UNKNOWN",
		"TOXIC-DNS-KEY", "TOXIC-PROVIDER", "TOXIC-ROUTE", "TOXIC-POLICY-OPTION",
	} {
		if strings.Contains(formatted, marker) {
			t.Fatalf("policy formatting leaked forbidden marker %q", marker)
		}
	}
	for _, finding := range decision.Findings() {
		if !finding.Reason().Known() || !finding.Severity().Known() {
			t.Fatal("decision accessor escaped closed vocabulary")
		}
	}
	exampleSource, readErr := os.ReadFile("verification_example_test.go")
	if readErr != nil {
		t.Fatal("policy example source unavailable")
	}
	for _, output := range policyExampleOutputBlocks(string(exampleSource)) {
		if strings.Contains(output, "example.test") || strings.Contains(output, "selector") || strings.Contains(output, "body line") {
			t.Fatal("runnable example output contains forbidden input material")
		}
	}
}

// policyExampleOutputBlocks returns only runnable expected-output comment blocks.
func policyExampleOutputBlocks(source string) []string {
	blocks := make([]string, 0, 2)
	lines := strings.Split(source, "\n")
	for index, line := range lines {
		if !strings.Contains(line, "// Output:") {
			continue
		}
		output := make([]string, 0, 4)
		for next := index + 1; next < len(lines); next++ {
			trimmed := strings.TrimSpace(lines[next])
			if !strings.HasPrefix(trimmed, "//") {
				break
			}
			output = append(output, strings.TrimSpace(strings.TrimPrefix(trimmed, "//")))
		}
		blocks = append(blocks, strings.Join(output, "\n"))
	}
	return blocks
}

// TestPolicyEvaluationRacesSafelyWithCallerCloneMutation proves every exposed collection has independent ownership.
func TestPolicyEvaluationRacesSafelyWithCallerCloneMutation(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	result := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)})
	decision, err := EvaluatePolicy(result)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(2)
		go func() {
			defer wait.Done()
			for range 32 {
				got, evaluateErr := EvaluatePolicy(result)
				if evaluateErr != nil || !got.Valid() {
					t.Errorf("EvaluatePolicy() = %#v, %v", got, evaluateErr)
					return
				}
			}
		}()
		go func() {
			defer wait.Done()
			for range 32 {
				checks, signatures := result.Checks(), result.SignatureSets()
				hops, sealedSignatures := result.policyProjection.Hops(), result.policyProjection.SignatureFacts()
				findings, actions := decision.Findings(), decision.ActionPlan().Actions()
				if len(checks) > 0 {
					checks[0] = CheckFact{}
				}
				if len(signatures) > 0 {
					signatures[0] = SignatureSetFact{}
				}
				if len(hops) > 0 {
					hops[0] = policy.HopFact{}
				}
				if len(sealedSignatures) > 0 {
					sealedSignatures[0] = policy.SignatureFact{}
				}
				if len(findings) > 0 {
					findings[0] = PolicyFinding{}
				}
				if len(actions) > 0 {
					actions[0] = PolicyAction{}
				}
			}
		}()
	}
	wait.Wait()
	if !decision.Valid() || !result.policyProjection.Valid() {
		t.Fatal("caller clone mutation corrupted retained policy state")
	}
}
