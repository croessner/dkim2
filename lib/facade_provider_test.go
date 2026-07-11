package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

type temporaryProviderDeadline struct{}

// Error returns a bounded provider-owned deadline diagnostic.
func (temporaryProviderDeadline) Error() string { return "provider deadline" }

// Unwrap exposes deadline identity only for control-flow discrimination.
func (temporaryProviderDeadline) Unwrap() error { return context.DeadlineExceeded }

// ProviderErrorClass explicitly classifies this provider-owned deadline as temporary.
func (temporaryProviderDeadline) ProviderErrorClass() ProviderErrorClass {
	return ProviderErrorClassTemporary
}

// TestFacadeVerifiesEd25519WithClonedProviderKey proves the named-key bridge through real crypto.
func TestFacadeVerifiesEd25519WithClonedProviderKey(t *testing.T) {
	raw, publicKey := publicEd25519Fixture(t)
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		// The found-result constructor is the provider-to-library ownership boundary.
		result := FoundEd25519PublicKey(publicKey)
		publicKey[0] ^= 0xff
		return result, nil
	}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || result.State() != ResultStatePASS || result.PrimaryReason() != ReasonNone {
		t.Fatalf("Verify() = %q/%q, %v", result.State(), result.PrimaryReason(), err)
	}
	if result.Draft() != DraftIdentifier || result.Scope() != VerificationScopeCurrent ||
		result.HistoricalContent() != HistoricalStateNotEvaluated || result.HistoricalSignatures() != HistoricalStateNotEvaluated ||
		result.CustodyStructure() != CustodyStructureNotPresent || result.Target().Sequence() != 1 || result.Target().Instance() != 1 {
		t.Fatalf("result coverage = %q/%q/%q/%q/%q target=%d/%d", result.Draft(), result.Scope(), result.HistoricalContent(), result.HistoricalSignatures(), result.CustodyStructure(), result.Target().Sequence(), result.Target().Instance())
	}
	checks := result.Checks()
	signatures := result.SignatureSets()
	if len(checks) == 0 || len(checks) > HardMaxCheckFacts || len(signatures) != 1 ||
		signatures[0].Algorithm() != AlgorithmEd25519SHA256 || signatures[0].Status() != SignatureStatusPASS || signatures[0].Reason() != ReasonNone {
		t.Fatalf("bounded facts = checks:%d signatures:%#v", len(checks), signatures)
	}
	for _, check := range checks {
		if !check.Class().Known() || !check.Reason().Known() {
			t.Fatalf("unknown public check fact = %q/%q", check.Class(), check.Reason())
		}
	}
	checks[0] = CheckFact{}
	signatures[0] = SignatureSetFact{}
	if result.Checks()[0].Class() == "" || result.SignatureSets()[0].Algorithm() != AlgorithmEd25519SHA256 {
		t.Fatal("public result accessors exposed mutable result storage")
	}
}

// TestFacadeMapsDeclaredProviderOutcomes verifies public provider facts through the real facade.
func TestFacadeMapsDeclaredProviderOutcomes(t *testing.T) {
	raw := publicProviderFixture(t)
	tests := []struct {
		name   string
		result PublicKeyResult
		err    error
		state  ResultState
		reason ReasonCode
	}{
		{name: string(PublicKeyStatusMissing), result: MissingPublicKey(AlgorithmRSASHA256), state: ResultStatePERMERROR, reason: ReasonMissingKey},
		{name: string(PublicKeyStatusInvalid), result: InvalidPublicKey(AlgorithmRSASHA256), state: ResultStatePERMERROR, reason: ReasonInvalidKey},
		{name: string(PublicKeyStatusAmbiguous), result: AmbiguousPublicKey(AlgorithmRSASHA256), state: ResultStatePERMERROR, reason: ReasonAmbiguousKey},
		{name: string(ProviderErrorClassTemporary), err: NewTemporaryProviderError(), state: ResultStateTEMPERROR, reason: ReasonProviderTemporary},
		{name: "classified provider deadline", err: temporaryProviderDeadline{}, state: ResultStateTEMPERROR, reason: ReasonProviderTemporary},
		{name: "permanent provider deadline", err: permanentProviderDeadline{}, state: ResultStatePERMERROR, reason: ReasonProviderContract},
		{name: "unclassified deadline", err: context.DeadlineExceeded, state: ResultStatePERMERROR, reason: ReasonProviderContract},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
				return tt.result, tt.err
			}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if err != nil || result.State() != tt.state || result.PrimaryReason() != tt.reason {
				t.Fatalf("Verify() = %q/%q, %v", result.State(), result.PrimaryReason(), err)
			}
		})
	}
}

// publicProviderFixture builds current parser-valid input whose provider outcome precedes cryptographic use.
func publicProviderFixture(t testing.TB) []byte {
	t.Helper()
	base := []byte("From: sender@example.test\r\nSubject: provider facade\r\n\r\nbody\r\n")
	message, err := rawmsg.Parse(base)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	header, _ := canonicalizer.HeaderHashFromMessage(message)
	body, _ := canonicalizer.BodyHashFromMessage(message)
	headerDigest, _ := header.Digest()
	bodyDigest, _ := body.Digest()
	hashSet := "sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64()
	signature := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 128))
	return []byte("From: sender@example.test\r\nSubject: provider facade\r\n" +
		"Message-Instance: m=1; h=" + hashSet + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatInt(1700000000, 10) + "; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=selector.test:rsa-sha256:" + signature + ";\r\n\r\nbody\r\n")
}

// publicEd25519Fixture builds a current Ed25519-SHA256 message signed over the Section 9.6 digest.
func publicEd25519Fixture(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	placeholder := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, ed25519.SignatureSize))
	unsigned := publicFixtureForAlgorithm(t, "ed25519-sha256", placeholder)
	message, err := rawmsg.Parse(unsigned)
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: message.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	return bytes.Replace(unsigned, []byte(placeholder), []byte(signature), 1), publicKey
}

// publicFixtureForAlgorithm builds current input with caller-supplied signature material.
func publicFixtureForAlgorithm(t *testing.T, algorithm, signature string) []byte {
	t.Helper()
	base := []byte("From: sender@example.test\r\nSubject: provider facade\r\n\r\nbody\r\n")
	message, err := rawmsg.Parse(base)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	header, _ := canonicalizer.HeaderHashFromMessage(message)
	body, _ := canonicalizer.BodyHashFromMessage(message)
	headerDigest, _ := header.Digest()
	bodyDigest, _ := body.Digest()
	return []byte("From: sender@example.test\r\nSubject: provider facade\r\n" +
		"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=selector.test:" + algorithm + ":" + signature + ";\r\n\r\nbody\r\n")
}
