package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	publicVectorClock                = int64(1700000000)
	goldenVectorRSAPass              = "rsa_pass"
	goldenVectorEd25519Pass          = "ed25519_pass"
	goldenVectorMalformed            = "malformed_message"
	goldenVectorMissingProtocol      = "missing_protocol"
	goldenVectorInconsistentSequence = "inconsistent_sequence"
	testNameAmbiguous                = "ambiguous"
	testNameInvalid                  = "invalid"
	testNameRevoked                  = "revoked"
	testNameUnsupported              = "unsupported"
	testNameMismatch                 = "mismatch"
)

type publicGoldenVector struct {
	Raw     string   `json:"raw_base64"`
	Reverse string   `json:"reverse_path_base64"`
	Forward []string `json:"forward_paths_base64"`
}

type publicGoldenCorpus struct {
	Draft       string                        `json:"draft"`
	RSAModulus  string                        `json:"rsa_modulus_base64"`
	RSAExponent int                           `json:"rsa_exponent"`
	Ed25519     string                        `json:"ed25519_public_base64"`
	Vectors     map[string]publicGoldenVector `json:"vectors"`
}

type goldenProviderMode string

const (
	goldenProviderKeys                 goldenProviderMode = "keys"
	goldenProviderMissing              goldenProviderMode = "missing"
	goldenProviderAmbiguous            goldenProviderMode = "ambiguous"
	goldenProviderTemporary            goldenProviderMode = "temporary"
	goldenProviderTemporaryDeadline    goldenProviderMode = "temporary_deadline"
	goldenProviderUnclassifiedDeadline goldenProviderMode = "unclassified_deadline"
)

type publicGoldenProvider struct {
	mode goldenProviderMode
	rsa  *rsa.PublicKey
	ed   ed25519.PublicKey
}

// LookupPublicKey returns deterministic synthetic key or provider state.
func (p publicGoldenProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	switch p.mode {
	case goldenProviderMissing:
		return MissingPublicKey(query.Algorithm()), nil
	case goldenProviderAmbiguous:
		return AmbiguousPublicKey(query.Algorithm()), nil
	case goldenProviderTemporary:
		return PublicKeyResult{}, NewTemporaryProviderError()
	case goldenProviderTemporaryDeadline:
		return PublicKeyResult{}, temporaryProviderDeadline{}
	case goldenProviderUnclassifiedDeadline:
		return PublicKeyResult{}, context.DeadlineExceeded
	}
	switch query.Algorithm() {
	case AlgorithmRSASHA256:
		return FoundRSAPublicKey(p.rsa), nil
	case AlgorithmEd25519SHA256:
		return FoundEd25519PublicKey(p.ed), nil
	default:
		return MissingPublicKey(query.Algorithm()), nil
	}
}

type publicGoldenCase struct {
	name              string
	vector            string
	mode              goldenProviderMode
	reverse           []byte
	forward           [][]byte
	state             ResultState
	reason            ReasonCode
	class             CheckClass
	custody           CustodyStructure
	sequence          uint64
	instance          uint64
	corruptSignature  bool
	malformedProtocol bool
	checks            []publicGoldenCheckFact
	signatures        []publicGoldenSignatureFact
}

type publicGoldenCheckFact struct {
	class  CheckClass
	reason ReasonCode
}

type publicGoldenSignatureFact struct {
	algorithm Algorithm
	status    SignatureStatus
	reason    ReasonCode
}

// TestPublicDraft05GoldenVectors proves chain-authenticated verification through the root facade.
func TestPublicDraft05GoldenVectors(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	cases := publicGoldenCases(corpus)
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			vector := corpus.Vectors[testCase.vector]
			raw := decodeGoldenBytes(t, vector.Raw)
			if testCase.corruptSignature {
				raw = corruptGoldenSignature(t, raw)
			}
			if testCase.malformedProtocol {
				raw = malformedGoldenProtocol(t, raw)
			}
			reverse := testCase.reverse
			if reverse == nil {
				reverse = decodeGoldenBytes(t, vector.Reverse)
			}
			forward := testCase.forward
			if forward == nil {
				forward = decodeGoldenPaths(t, vector.Forward)
			}
			provider := publicGoldenProvider{mode: testCase.mode, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)}
			verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
			if err != nil {
				t.Fatalf("NewVerifier() failed for %s", testCase.name)
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, reverse, forward))
			if err != nil {
				t.Fatalf("Verify() returned Go error for protocol vector %s", testCase.name)
			}
			assertPublicGoldenResult(t, result, testCase)
		})
	}
}

// TestPublicGoldenVectorBytesAreFrozenCRLF verifies non-malformed fixtures contain no bare line endings.
func TestPublicGoldenVectorBytesAreFrozenCRLF(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	for name, vector := range corpus.Vectors {
		if name == goldenVectorMalformed {
			continue
		}
		raw := decodeGoldenBytes(t, vector.Raw)
		withoutCRLF := bytes.ReplaceAll(raw, []byte("\r\n"), nil)
		if bytes.ContainsAny(withoutCRLF, "\r\n") {
			t.Fatalf("vector %s contains a bare CR or LF", name)
		}
	}
}

// publicGoldenCases returns the binding Draft-05 public result matrix.
func publicGoldenCases(corpus publicGoldenCorpus) []publicGoldenCase {
	pass := func(name, vector string) publicGoldenCase {
		return publicGoldenCase{name: name, vector: vector, mode: goldenProviderKeys, state: ResultStatePASS, reason: ReasonNone, class: CheckClassBodyHash, custody: CustodyStructureNotPresent, sequence: 1, instance: 1}
	}
	cases := []publicGoldenCase{
		pass("rsa_sha256_pass", goldenVectorRSAPass),
		pass("ed25519_sha256_pass", "ed25519_pass"),
		pass("rsa_and_ed25519_both_pass", "both_pass"),
		pass("supported_pass_plus_unknown_signature_pass", "supported_unknown_pass"),
		{name: "sha256_plus_mismatching_sha512_fails", vector: "sha_unknown_hash_pass", mode: goldenProviderKeys, state: ResultStateFAIL, reason: ReasonHashMismatch, class: CheckClassBodyHash, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "mismatching_sha512_only_fails", vector: "unknown_hash_only", mode: goldenProviderKeys, state: ResultStateFAIL, reason: ReasonHashMismatch, class: CheckClassBodyHash, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "unknown_signature_only_permerror", vector: "unknown_signature_only", mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonUnsupportedAlgorithm, class: CheckClassSignature, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "supported_pass_plus_supported_bad_signature_fail", vector: "supported_mixed_fail", mode: goldenProviderKeys, state: ResultStateFAIL, reason: ReasonSignatureMismatch, class: CheckClassSignature, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "body_hash_mismatch_fail", vector: "body_mismatch", mode: goldenProviderKeys, state: ResultStateFAIL, reason: ReasonHashMismatch, class: CheckClassBodyHash, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "header_hash_mismatch_fail", vector: "header_mismatch", mode: goldenProviderKeys, state: ResultStateFAIL, reason: ReasonHashMismatch, class: CheckClassHeaderHash, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "supported_signature_mismatch_fail", vector: goldenVectorRSAPass, mode: goldenProviderKeys, corruptSignature: true, state: ResultStateFAIL, reason: ReasonSignatureMismatch, class: CheckClassSignature, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "missing_protocol_permerror", vector: goldenVectorMissingProtocol, mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonMissingProtocol, class: CheckClassProtocol, custody: CustodyStructureNotPresent},
		{name: "malformed_message_permerror", vector: goldenVectorMalformed, mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonMalformedMessage, class: CheckClassMessage, custody: CustodyStructureNotEvaluated},
		{name: "malformed_dkim2_tag_permerror", vector: goldenVectorRSAPass, mode: goldenProviderKeys, malformedProtocol: true, state: ResultStatePERMERROR, reason: ReasonMalformedProtocol, class: CheckClassProtocol, custody: CustodyStructureNotEvaluated},
		{name: "inconsistent_protocol_permerror", vector: goldenVectorInconsistentSequence, mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonSequenceInvalid, class: CheckClassProtocol, custody: CustodyStructureNotEvaluated},
		{name: "missing_key_permerror", vector: goldenVectorRSAPass, mode: goldenProviderMissing, state: ResultStatePERMERROR, reason: ReasonMissingKey, class: CheckClassKey, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "ambiguous_key_permerror", vector: goldenVectorRSAPass, mode: goldenProviderAmbiguous, state: ResultStatePERMERROR, reason: ReasonAmbiguousKey, class: CheckClassKey, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "typed_temporary_provider_temperror", vector: goldenVectorRSAPass, mode: goldenProviderTemporary, state: ResultStateTEMPERROR, reason: ReasonProviderTemporary, class: CheckClassProvider, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "typed_provider_deadline_temperror", vector: goldenVectorRSAPass, mode: goldenProviderTemporaryDeadline, state: ResultStateTEMPERROR, reason: ReasonProviderTemporary, class: CheckClassProvider, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "unclassified_provider_deadline_permerror", vector: goldenVectorRSAPass, mode: goldenProviderUnclassifiedDeadline, state: ResultStatePERMERROR, reason: ReasonProviderContract, class: CheckClassProvider, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		pass("timestamp_exact_14_days_pass", "age_exact"),
		{name: "timestamp_14_days_plus_one_permerror", vector: "age_over", mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonTimestampInvalid, class: CheckClassTimestamp, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		pass("timestamp_exact_five_minutes_future_pass", "future_exact"),
		{name: "timestamp_five_minutes_plus_one_permerror", vector: "future_over", mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonTimestampInvalid, class: CheckClassTimestamp, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "timestamp_large_parseable_permerror", vector: "timestamp_large", mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonTimestampInvalid, class: CheckClassTimestamp, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		pass("mail_from_exact_pass", "mail_exact"),
		{name: "mail_from_ascii_domain_case_pass", vector: "mail_domain_case", mode: goldenProviderKeys, reverse: []byte("<Sender@example.test>"), state: ResultStatePASS, reason: ReasonNone, class: CheckClassEnvelope, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "mail_from_local_part_case_mismatch", vector: "mail_exact", mode: goldenProviderKeys, reverse: []byte("<sender@example.test>"), state: ResultStatePERMERROR, reason: ReasonEnvelopeMismatch, class: CheckClassEnvelope, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		pass("null_reverse_path_matches_null", "mail_null"),
		{name: "null_reverse_path_nonnull_mismatch", vector: "mail_null", mode: goldenProviderKeys, reverse: []byte("<sender@example.test>"), state: ResultStatePERMERROR, reason: ReasonEnvelopeMismatch, class: CheckClassEnvelope, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "recipient_subset_order_and_signed_extra_pass", vector: "recipient_set", mode: goldenProviderKeys, forward: [][]byte{[]byte("<two@example.test>"), []byte("<one@example.test>")}, state: ResultStatePASS, reason: ReasonNone, class: CheckClassEnvelope, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "recipient_missing_current_permerror", vector: "recipient_set", mode: goldenProviderKeys, forward: [][]byte{[]byte("<one@example.test>"), []byte("<missing@example.test>")}, state: ResultStatePERMERROR, reason: ReasonEnvelopeMismatch, class: CheckClassEnvelope, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "current_envelope_mismatch_permerror", vector: "mail_exact", mode: goldenProviderKeys, reverse: []byte("<Sender@other.test>"), state: ResultStatePERMERROR, reason: ReasonEnvelopeMismatch, class: CheckClassEnvelope, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		pass("relaxed_d_alignment_pass", "alignment_relaxed"),
		{name: "d_alignment_mismatch_permerror", vector: "alignment_mismatch", mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonDomainAlignmentMismatch, class: CheckClassDomainAlignment, custody: CustodyStructureNotPresent, sequence: 1, instance: 1},
		{name: "intermediate_nd_successor_pass", vector: "intermediate_nd", mode: goldenProviderKeys, state: ResultStatePASS, reason: ReasonNone, class: CheckClassNextDomain, custody: CustodyStructureNDLinksEvaluated, sequence: 2, instance: 1},
		{name: "terminal_current_nd_permerror", vector: "terminal_nd", mode: goldenProviderKeys, state: ResultStatePERMERROR, reason: ReasonOutOfBandRequired, class: CheckClassNextDomain, custody: CustodyStructureTerminalNDRequiresOOB, sequence: 1, instance: 1},
	}
	for index := range cases {
		cases[index].signatures = expectedPublicGoldenSignatures(cases[index])
		cases[index].checks = expectedPublicGoldenChecks(cases[index])
	}
	_ = corpus
	return cases
}

// expectedPublicGoldenSignatures returns exact sorted signature facts for one vector case.
func expectedPublicGoldenSignatures(testCase publicGoldenCase) []publicGoldenSignatureFact {
	passRSA := publicGoldenSignatureFact{algorithm: AlgorithmRSASHA256, status: SignatureStatusPASS, reason: ReasonNone}
	switch testCase.vector {
	case goldenVectorMissingProtocol, goldenVectorMalformed, goldenVectorInconsistentSequence:
		return nil
	case goldenVectorEd25519Pass:
		return []publicGoldenSignatureFact{{algorithm: AlgorithmEd25519SHA256, status: SignatureStatusPASS, reason: ReasonNone}}
	case "both_pass":
		return []publicGoldenSignatureFact{passRSA, {algorithm: AlgorithmEd25519SHA256, status: SignatureStatusPASS, reason: ReasonNone}}
	case "supported_unknown_pass":
		return []publicGoldenSignatureFact{passRSA, publicGoldenSignatureFact{algorithm: AlgorithmUnknown, status: SignatureStatusIgnored, reason: ReasonUnsupportedAlgorithm}}
	case "unknown_signature_only":
		return []publicGoldenSignatureFact{{algorithm: AlgorithmUnknown, status: SignatureStatusIgnored, reason: ReasonUnsupportedAlgorithm}}
	case "supported_mixed_fail":
		return []publicGoldenSignatureFact{passRSA, {algorithm: AlgorithmEd25519SHA256, status: SignatureStatusFAIL, reason: ReasonSignatureMismatch}}
	}
	if testCase.malformedProtocol {
		return nil
	}
	if testCase.corruptSignature {
		return []publicGoldenSignatureFact{{algorithm: AlgorithmRSASHA256, status: SignatureStatusFAIL, reason: ReasonSignatureMismatch}}
	}
	switch testCase.mode {
	case goldenProviderMissing:
		return []publicGoldenSignatureFact{{algorithm: AlgorithmRSASHA256, status: SignatureStatusPERMERROR, reason: ReasonMissingKey}}
	case goldenProviderAmbiguous:
		return []publicGoldenSignatureFact{{algorithm: AlgorithmRSASHA256, status: SignatureStatusPERMERROR, reason: ReasonAmbiguousKey}}
	case goldenProviderTemporary, goldenProviderTemporaryDeadline:
		return []publicGoldenSignatureFact{{algorithm: AlgorithmRSASHA256, status: SignatureStatusTEMPERROR, reason: ReasonProviderTemporary}}
	case goldenProviderUnclassifiedDeadline:
		return []publicGoldenSignatureFact{{algorithm: AlgorithmRSASHA256, status: SignatureStatusPERMERROR, reason: ReasonProviderContract}}
	default:
		return []publicGoldenSignatureFact{passRSA}
	}
}

// expectedPublicGoldenChecks returns the exact sorted check-fact multiset for one case.
func expectedPublicGoldenChecks(testCase publicGoldenCase) []publicGoldenCheckFact {
	switch testCase.vector {
	case goldenVectorMissingProtocol, goldenVectorMalformed, goldenVectorInconsistentSequence:
		return []publicGoldenCheckFact{{class: testCase.class, reason: testCase.reason}}
	}
	if testCase.malformedProtocol {
		return []publicGoldenCheckFact{{class: CheckClassProtocol, reason: ReasonMalformedProtocol}}
	}
	facts := []publicGoldenCheckFact{
		{class: CheckClassBodyHash, reason: ReasonNone},
		{class: CheckClassDomainAlignment, reason: ReasonNone},
		{class: CheckClassEnvelope, reason: ReasonNone},
		{class: CheckClassHeaderHash, reason: ReasonNone},
		{class: CheckClassNextDomain, reason: ReasonNone},
		{class: CheckClassTimestamp, reason: ReasonNone},
	}
	if testCase.vector == "unknown_hash_only" || testCase.vector == "sha_unknown_hash_pass" {
		facts[0].reason = ReasonHashMismatch
		facts[3].reason = ReasonHashMismatch
	} else if testCase.reason != ReasonNone {
		for index := range facts {
			if facts[index].class == testCase.class {
				facts[index].reason = testCase.reason
			}
		}
	}
	for _, signature := range testCase.signatures {
		class := CheckClassSignature
		if signature.reason == ReasonMissingKey || signature.reason == ReasonAmbiguousKey || signature.reason == ReasonInvalidKey {
			class = CheckClassKey
		}
		if signature.reason == ReasonProviderTemporary || signature.reason == ReasonProviderPermanent || signature.reason == ReasonProviderContract {
			class = CheckClassProvider
		}
		facts = append(facts, publicGoldenCheckFact{class: class, reason: signature.reason})
	}
	slices.SortFunc(facts, func(left, right publicGoldenCheckFact) int {
		if left.class != right.class {
			return strings.Compare(string(left.class), string(right.class))
		}
		return strings.Compare(string(left.reason), string(right.reason))
	})
	return facts
}

// assertPublicGoldenResult checks bounded state, coverage, target, facts, and immutability.
func assertPublicGoldenResult(t *testing.T, result VerifyResult, expected publicGoldenCase) {
	t.Helper()
	scope, content, signatures := VerificationScopeCurrent, HistoricalStateNotEvaluated, HistoricalStateNotEvaluated
	if expected.state == ResultStatePASS {
		scope, content, signatures = VerificationScopeChain, HistoricalStateComplete, HistoricalStateComplete
	}
	if result.Draft() != DraftIdentifier || result.State() != expected.state || result.PrimaryReason() != expected.reason || result.Scope() != scope || result.HistoricalContent() != content || result.HistoricalSignatures() != signatures || result.CustodyStructure() != expected.custody || result.Target().Sequence() != expected.sequence || result.Target().Instance() != expected.instance {
		t.Fatalf("structured result mismatch for %s: state=%q reason=%q custody=%q target=%d/%d", expected.name, result.State(), result.PrimaryReason(), result.CustodyStructure(), result.Target().Sequence(), result.Target().Instance())
	}
	assertPublicGoldenFacts(t, result, expected)
	assertPublicGoldenFactImmutability(t, result, expected.name)
}

// assertPublicGoldenFacts checks exact bounded check and signature semantics.
func assertPublicGoldenFacts(t *testing.T, result VerifyResult, expected publicGoldenCase) {
	t.Helper()
	checks := result.Checks()
	if len(checks) != len(expected.checks) {
		t.Fatalf("check fact count for %s = %d, want %d", expected.name, len(checks), len(expected.checks))
	}
	for index, fact := range checks {
		if !fact.Class().Known() || !fact.Reason().Known() {
			t.Fatalf("unknown check token for %s", expected.name)
		}
		want := expected.checks[index]
		if fact.Class() != want.class || fact.Reason() != want.reason {
			t.Fatalf("check fact %d for %s = %q/%q, want %q/%q", index, expected.name, fact.Class(), fact.Reason(), want.class, want.reason)
		}
	}
	if len(result.SignatureSets()) != len(expected.signatures) {
		t.Fatalf("signature fact count for %s = %d, want %d", expected.name, len(result.SignatureSets()), len(expected.signatures))
	}
	for index, want := range expected.signatures {
		fact := result.SignatureSets()[index]
		if fact.Algorithm() != want.algorithm || fact.Status() != want.status || fact.Reason() != want.reason {
			t.Fatalf("signature fact %d for %s = %q/%q/%q, want %q/%q/%q", index, expected.name, fact.Algorithm(), fact.Status(), fact.Reason(), want.algorithm, want.status, want.reason)
		}
	}
	for _, fact := range result.SignatureSets() {
		if !fact.Algorithm().Known() || !fact.Status().Known() || !fact.Reason().Known() {
			t.Fatalf("unknown signature token for %s", expected.name)
		}
	}
}

// assertPublicGoldenFactImmutability checks result caps and cloned accessors.
func assertPublicGoldenFactImmutability(t *testing.T, result VerifyResult, name string) {
	t.Helper()
	checks := result.Checks()
	signatures := result.SignatureSets()
	if len(checks) > HardMaxCheckFacts || len(signatures) > HardMaxSignatureFacts {
		t.Fatalf("unbounded facts for %s", name)
	}
	if len(checks) > 0 {
		checks[0] = CheckFact{}
		if result.Checks()[0].Class() == "" {
			t.Fatalf("mutable check facts for %s", name)
		}
	}
	if len(signatures) > 0 {
		signatures[0] = SignatureSetFact{}
		if result.SignatureSets()[0].Status() == "" {
			t.Fatalf("mutable signature facts for %s", name)
		}
	}
}

// loadPublicGoldenCorpus loads the frozen synthetic Draft-05 corpus.
func loadPublicGoldenCorpus(t testing.TB) publicGoldenCorpus {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors/draft-ietf-dkim-dkim2-spec-05/public-golden.json")
	if err != nil {
		t.Fatal("golden corpus unavailable")
	}
	var corpus publicGoldenCorpus
	if json.Unmarshal(raw, &corpus) != nil || corpus.Draft != DraftIdentifier {
		t.Fatal("invalid golden corpus")
	}
	return corpus
}

// rsaKey reconstructs the frozen synthetic public RSA key.
func (c publicGoldenCorpus) rsaKey(t testing.TB) *rsa.PublicKey {
	t.Helper()
	modulus := decodeGoldenBytes(t, c.RSAModulus)
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: c.RSAExponent}
}

// edKey reconstructs the frozen synthetic public Ed25519 key.
func (c publicGoldenCorpus) edKey(t testing.TB) ed25519.PublicKey {
	t.Helper()
	return ed25519.PublicKey(decodeGoldenBytes(t, c.Ed25519))
}

// decodeGoldenBytes decodes one fixed base64 byte container.
func decodeGoldenBytes(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal("invalid golden base64")
	}
	return decoded
}

// decodeGoldenPaths decodes fixed SMTP path containers.
func decodeGoldenPaths(t testing.TB, values []string) [][]byte {
	t.Helper()
	paths := make([][]byte, len(values))
	for i, value := range values {
		paths[i] = decodeGoldenBytes(t, value)
	}
	return paths
}

// corruptGoldenSignature flips one base64 signature byte without changing signed input.
func corruptGoldenSignature(t *testing.T, raw []byte) []byte {
	t.Helper()
	marker := []byte("s=rsa.test:rsa-sha256:")
	start := bytes.Index(raw, marker)
	if start < 0 {
		t.Fatal("RSA signature marker absent")
	}
	mutated := bytes.Clone(raw)
	start += len(marker)
	if mutated[start] == 'A' {
		mutated[start] = 'B'
	} else {
		mutated[start] = 'A'
	}
	return mutated
}

// malformedGoldenProtocol duplicates a required tag without changing RFC 5322 syntax.
func malformedGoldenProtocol(t *testing.T, raw []byte) []byte {
	t.Helper()
	marker := []byte("DKIM2-Signature: i=1; m=1;")
	found := bytes.Contains(raw, marker)
	if !found {
		t.Fatal("DKIM2 signature marker absent")
	}
	return bytes.Replace(raw, marker, []byte("DKIM2-Signature: i=1; m=1; m=1;"), 1)
}
