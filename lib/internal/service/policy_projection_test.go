package service

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

type passingPolicyProvider struct {
	key     *rsa.PublicKey
	testing bool
}

type mixedPolicyProvider struct {
	rsaKey     *rsa.PublicKey
	ed25519Key ed25519.PublicKey
}

// LookupKey returns algorithm-specific keys with testing only on RSA.
func (p mixedPolicyProvider) LookupKey(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
	switch query.Algorithm {
	case verify.AlgorithmRSASHA256:
		return verify.PublicKey{Algorithm: query.Algorithm, Material: p.rsaKey, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound, Policy: verify.KeyPolicyMetadata{TestingDeclared: true}}}, nil
	case verify.AlgorithmEd25519SHA256:
		return verify.PublicKey{Algorithm: query.Algorithm, Material: p.ed25519Key, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}}, nil
	default:
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailurePermanent)
	}
}

// LookupKey returns the exact synthetic RSA key used by a projection fixture.
func (p passingPolicyProvider) LookupKey(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
	return verify.PublicKey{Algorithm: verify.AlgorithmRSASHA256, Material: p.key, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound, Policy: verify.KeyPolicyMetadata{TestingDeclared: p.testing}}}, nil
}

// TestServiceAloneUpgradesPassingCandidateAndDiscardsNonPassFlags verifies provenance ownership.
func TestServiceAloneUpgradesPassingCandidateAndDiscardsNonPassFlags(t *testing.T) {
	const timestamp = uint64(1700000000)
	raw := strings.Replace(string(syntheticCurrentMessage(t, timestamp, 1, 1)), "; d=example.test;", "; f=donotmodify,donotexplode,feedback,feedhere,exploded,TOXIC-UNKNOWN; d=example.test;", 1)
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
	coordinator, err := NewVerifier(&countingProvider{}, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := coordinator.Verify(context.Background(), NewRequest([]byte(raw), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	nonPassProjection := result.PolicyProjection()
	if result.State() == StatePASS || !nonPassProjection.Valid() || len(nonPassProjection.Hops()) != 0 || len(nonPassProjection.SignatureFacts()) != 1 {
		t.Fatalf("non-PASS projection = %#v state=%q", nonPassProjection, result.State())
	}

	passingRaw, key := signedFlaggedPolicyMessage(t, timestamp)
	passingCoordinator, err := NewVerifier(passingPolicyProvider{key: key}, config)
	if err != nil {
		t.Fatalf("NewVerifier(passing) error = %v", err)
	}
	passingResult, err := passingCoordinator.Verify(context.Background(), NewRequest(passingRaw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || passingResult.State() != StatePASS {
		t.Fatalf("passing Verify() = %q error=%v", passingResult.State(), err)
	}
	passing := passingResult.PolicyProjection()
	hops := passing.Hops()
	if !passing.Valid() || passing.Protocol() != policy.ProtocolPASS || passing.HistoryCoverage() != policy.HistoryNotEvaluated || len(hops) != 1 ||
		hops[0].Sequence() != 1 || hops[0].Transition() != policy.TransitionOrigin || !hops[0].DoNotModify() || !hops[0].DoNotExplode() || !hops[0].Feedback() || !hops[0].FeedHere() || !hops[0].Exploded() {
		t.Fatalf("PASS projection = %#v hops=%#v", passing, hops)
	}
}

// TestPolicyProjectionPreservesPreRetentionSignatureFacts verifies public narrowing independence.
func TestPolicyProjectionPreservesPreRetentionSignatureFacts(t *testing.T) {
	const timestamp = uint64(1700000000)
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
	config.Limits.MaxSignatureFacts = 1
	config.Limits.MaxSignatureSets = 2
	raw, provider := signedMixedTestingPolicyMessage(t, timestamp)
	coordinator, err := NewVerifier(provider, config)
	if err != nil {
		t.Fatalf("NewVerifier(passing) error = %v", err)
	}
	result, err := coordinator.Verify(context.Background(), NewRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	projection := result.PolicyProjection()
	if len(result.SignatureSets()) != 1 || len(projection.SignatureFacts()) != 2 || !projection.Valid() || projection.Protocol() != policy.ProtocolPASS {
		t.Fatalf("retention result=%d projection=%#v", len(result.SignatureSets()), projection)
	}
	if result.SignatureSets()[0].KeyPolicy.TestingDeclared {
		t.Fatal("public retained slice unexpectedly contains DNS testing metadata")
	}
	sealedTesting := false
	for _, fact := range projection.SignatureFacts() {
		sealedTesting = sealedTesting || fact.TestingDeclared()
	}
	if !sealedTesting {
		t.Fatal("hidden pre-retention DNS testing metadata was lost")
	}
	evaluator, err := policy.NewEvaluator(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("policy.NewEvaluator() error = %v", err)
	}
	decision, err := evaluator.EvaluateProjection(projection)
	if err != nil || !decision.Valid() || !serviceDecisionHasReason(decision, policy.ReasonDNSTestingMixed) {
		t.Fatalf("pre-retention evaluation = %#v error=%v", decision, err)
	}
}

// signedMixedTestingPolicyMessage creates valid Ed25519/plain and RSA/testing sets.
func signedMixedTestingPolicyMessage(t *testing.T, timestamp uint64) ([]byte, mixedPolicyProvider) {
	t.Helper()
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: retained policy\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	build := func(edSignature, rsaSignature string) string {
		return "From: sender@example.test\r\nSubject: retained policy\r\n" +
			"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n" +
			"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatUint(timestamp, 10) + "; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=ed.test:ed25519-sha256:" + edSignature + ",rsa.test:rsa-sha256:" + rsaSignature + ";\r\n\r\nbody line\r\n"
	}
	unsigned, err := rawmsg.Parse([]byte(build(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)), base64.StdEncoding.EncodeToString(make([]byte, 128)))))
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	edSignature := ed25519.Sign(edPrivate, digest[:])
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivate, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return []byte(build(base64.StdEncoding.EncodeToString(edSignature), base64.StdEncoding.EncodeToString(rsaSignature))), mixedPolicyProvider{rsaKey: &rsaPrivate.PublicKey, ed25519Key: edPublic}
}

// serviceDecisionHasReason reports whether an internal policy decision contains one reason.
func serviceDecisionHasReason(decision policy.Decision, reason policy.PolicyReason) bool {
	for _, finding := range decision.Findings() {
		if finding.Reason() == reason {
			return true
		}
	}
	return false
}

// signedFlaggedPolicyMessage creates a real passing RSA fixture with all five known flags.
func signedFlaggedPolicyMessage(t *testing.T, timestamp uint64) ([]byte, *rsa.PublicKey) {
	t.Helper()
	return signedFlaggedPolicyMessageSets(t, timestamp, 1)
}

// signedFlaggedPolicyMessageSets creates a passing fixture with a bounded set count.
func signedFlaggedPolicyMessageSets(t *testing.T, timestamp uint64, setCount int) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: flagged policy\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	build := func(signature string) string {
		sets := make([]string, setCount)
		for index := range sets {
			algorithm := "rsa-sha256"
			if index > 0 {
				algorithm = "future-sha256"
			}
			sets[index] = "selector" + strconv.Itoa(index+1) + ".test:" + algorithm + ":" + signature
		}
		return "From: sender@example.test\r\nSubject: flagged policy\r\n" +
			"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n" +
			"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatUint(timestamp, 10) + "; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; f=donotmodify,donotexplode,feedback,feedhere,exploded,TOXIC-UNKNOWN; d=example.test; s=" + strings.Join(sets, ",") + ";\r\n\r\nbody line\r\n"
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsigned, err := rawmsg.Parse([]byte(build(placeholder)))
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return []byte(build(base64.StdEncoding.EncodeToString(signature))), &key.PublicKey
}

// TestUnavailablePolicyProjectionCoversExactReasons verifies every valid zero-target form.
func TestUnavailablePolicyProjectionCoversExactReasons(t *testing.T) {
	for _, reason := range []Reason{ReasonLimitExceeded, ReasonMalformedMessage, ReasonMalformedProtocol, ReasonMissingProtocol, ReasonSequenceInvalid, ReasonInternalContract} {
		projection, err := buildUnavailablePolicyProjection(reason)
		if err != nil || !projection.Valid() || projection.Form() != policy.TargetUnavailable || projection.TargetSequence() != 0 || projection.Protocol() != policy.ProtocolPERMERROR {
			t.Fatalf("unavailable %q = %#v error=%v", reason, projection, err)
		}
	}
	if projection, err := buildUnavailablePolicyProjection(ReasonUnsupportedAlgorithm); err == nil || !projection.IsZero() {
		t.Fatalf("unsupported unavailable = %#v error=%v", projection, err)
	}
}

// TestPolicySignatureFactMappingRejectsMetadataOnIneligibleOutcomes verifies DNS fact coherence.
func TestPolicySignatureFactMappingRejectsMetadataOnIneligibleOutcomes(t *testing.T) {
	valid := []SignatureSetFact{
		{Algorithm: AlgorithmRSASHA256, Status: SignaturePASS, Reason: ReasonNone, KeyPolicy: KeyPolicyMetadata{TestingDeclared: true}},
		{Algorithm: AlgorithmRSASHA256, Status: SignatureFAIL, Reason: ReasonSignatureMismatch, KeyPolicy: KeyPolicyMetadata{StrictIdentityDeclared: true}},
		{Algorithm: AlgorithmRSASHA256, Status: SignaturePERMERROR, Reason: ReasonInvalidKey, KeyPolicy: KeyPolicyMetadata{TestingDeclared: true}},
		{Algorithm: AlgorithmUnknown, Status: SignatureIgnored, Reason: ReasonUnsupportedAlgorithm},
		{Algorithm: AlgorithmRSASHA256, Status: SignatureTEMPERROR, Reason: ReasonProviderTemporary},
	}
	for _, fact := range valid {
		if mapped, err := policySignatureFact(fact); err != nil || !mapped.Valid() {
			t.Fatalf("valid fact %#v mapped=%#v error=%v", fact, mapped, err)
		}
	}
	invalid := []SignatureSetFact{
		{Algorithm: AlgorithmRSASHA256, Status: SignatureTEMPERROR, Reason: ReasonProviderTemporary, KeyPolicy: KeyPolicyMetadata{TestingDeclared: true}},
		{Algorithm: AlgorithmRSASHA256, Status: SignaturePERMERROR, Reason: ReasonMissingKey, KeyPolicy: KeyPolicyMetadata{TestingDeclared: true}},
		{Algorithm: AlgorithmUnknown, Status: SignatureIgnored, Reason: ReasonUnsupportedAlgorithm, KeyPolicy: KeyPolicyMetadata{StrictIdentityDeclared: true}},
	}
	for _, fact := range invalid {
		if mapped, err := policySignatureFact(fact); err == nil || mapped.Valid() {
			t.Fatalf("invalid fact %#v mapped=%#v error=%v", fact, mapped, err)
		}
	}
}
