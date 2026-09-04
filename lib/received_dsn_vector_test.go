package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
)

const (
	receivedDSNVectorPath      = "testdata/vectors/draft-ietf-dkim-dkim2-spec-06/received-dsn-golden.json"
	receivedDSNVectorWriteFlag = "DKIM2_WRITE_RECEIVED_DSN_VECTORS"
)

// receivedDSNVectorKey is one published verification key of the corpus.
type receivedDSNVectorKey struct {
	Selector string `json:"selector"`
	Public   string `json:"ed25519_public_base64"`
}

// receivedDSNVectorExpectation is the frozen projection of one case.
type receivedDSNVectorExpectation struct {
	Structure          string `json:"structure"`
	Embedded           string `json:"embedded"`
	LocalHop           string `json:"local_hop"`
	OuterAlignment     string `json:"outer_alignment"`
	RecipientLinkage   string `json:"recipient_linkage"`
	Propagation        string `json:"propagation"`
	OriginalForm       string `json:"original_form"`
	CompletionSequence uint64 `json:"completion_sequence"`
	RunLength          int    `json:"run_length"`
}

// receivedDSNVectorCase is one frozen received-DSN evaluation case.
type receivedDSNVectorCase struct {
	Name         string                       `json:"name"`
	Raw          string                       `json:"raw_base64"`
	Reverse      string                       `json:"reverse_path_base64"`
	Forward      []string                     `json:"forward_paths_base64"`
	Tenant       bool                         `json:"tenant"`
	LocalDomains []string                     `json:"local_domains"`
	Expected     receivedDSNVectorExpectation `json:"expected"`
}

// receivedDSNVectorCorpus is the versioned received-DSN evaluation corpus.
type receivedDSNVectorCorpus struct {
	Draft string                          `json:"draft"`
	Keys  map[string]receivedDSNVectorKey `json:"keys"`
	Cases []receivedDSNVectorCase         `json:"cases"`
}

// receivedDSNVectorProvider serves only the keys published in the corpus.
type receivedDSNVectorProvider struct {
	keys map[string]receivedDSNVectorKey
}

// LookupPublicKey resolves one corpus key without consulting fixture builders.
func (p receivedDSNVectorProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	key, ok := p.keys[query.SigningDomain()]
	if !ok || key.Selector != query.Selector() || query.Algorithm() != AlgorithmEd25519SHA256 {
		return MissingPublicKey(query.Algorithm()), nil
	}
	material, err := base64.StdEncoding.DecodeString(key.Public)
	if err != nil || len(material) != ed25519.PublicKeySize {
		return InvalidPublicKey(query.Algorithm()), nil
	}
	return FoundEd25519PublicKey(ed25519.PublicKey(material)), nil
}

// receivedDSNVectorSpec pairs one case name with the fixture that regenerates it.
type receivedDSNVectorSpec struct {
	name   string
	spec   receivedDSNSpec
	tenant bool
	local  []string
}

// receivedDSNVectorSpecs lists every frozen case in corpus order.
func receivedDSNVectorSpecs() []receivedDSNVectorSpec {
	corrupt := receivedDSNDefaultHops()
	corrupt[1].CorruptSignature = true
	corruptMember := receivedDSNNextDomainHop(receivedDSNLocalDomain, receivedDSNForwardDomain)
	corruptMember.CorruptSignature = true
	local := []string{receivedDSNLocalDomain}
	both := []string{receivedDSNLocalDomain, receivedDSNForwardDomain}
	delayed := strings.Replace(dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, receivedDSNDestinationRaw, "4.4.1"), "Action: failed", "Action: delayed", 1)
	return []receivedDSNVectorSpec{
		{name: "eligible_complete", spec: receivedDSNSpec{}, tenant: true, local: local},
		{name: "eligible_headers_only", spec: receivedDSNSpec{headersOnly: true}, tenant: true, local: local},
		{name: "structure_malformed", spec: receivedDSNSpec{deliveryStatus: receivedDSNMalformedStatus}, tenant: true, local: local},
		{name: "embedded_absent", spec: receivedDSNSpec{unsigned: true}, tenant: true, local: local},
		{name: "embedded_unverified", spec: receivedDSNSpec{hops: corrupt}, tenant: true, local: local},
		{name: "no_tenant", spec: receivedDSNSpec{}, tenant: false},
		{name: "not_local", spec: receivedDSNSpec{}, tenant: true, local: []string{receivedDSNOtherDomain}},
		{name: "foreign_parent_signer_not_local", spec: receivedDSNSpec{hops: receivedDSNParentSignerHops()}, tenant: true, local: local},
		{name: "completion_window_at_outer_timestamp", spec: receivedDSNSpec{hops: receivedDSNHopsAt(dsntest.DefaultTimestamp - 30*receivedDSNDay), outerTimestamp: dsntest.DefaultTimestamp - 29*receivedDSNDay}, tenant: true, local: local},
		{name: "completion_window_exceeded_at_outer_timestamp", spec: receivedDSNSpec{outerTimestamp: dsntest.DefaultTimestamp + 30*receivedDSNDay}, tenant: true, local: local},
		{name: "mismatch", spec: receivedDSNSpec{outerRecipient: receivedDSNOtherLocal}, tenant: true, local: local},
		{name: "misaligned", spec: receivedDSNSpec{outerSigner: receivedDSNOtherDomain}, tenant: true, local: local},
		{name: "unlinked_recipient", spec: receivedDSNSpec{deliveryStatus: dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, "other@destination.example", "5.1.1")}, tenant: true, local: local},
		{name: "not_failure_delayed", spec: receivedDSNSpec{deliveryStatus: delayed}, tenant: true, local: local},
		{name: "terminal_origin", spec: receivedDSNSpec{hops: []dsntest.Hop{receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination)}}, tenant: true, local: local},
		{name: "next_domain_run_eligible", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
			receivedDSNNextDomainHop(receivedDSNLocalDomain, receivedDSNForwardDomain),
			receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination),
		}, outerRecipient: receivedDSNForwardMailFrom}, tenant: true, local: both},
		{name: "imaginary_hop_run_eligible", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
			receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalRecipient, "<user@forward.local.example>"),
			receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination),
		}, outerRecipient: receivedDSNForwardMailFrom}, tenant: true, local: both},
		{name: "run_member_unverified", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient),
			corruptMember,
			receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination),
		}, outerRecipient: receivedDSNForwardMailFrom}, tenant: true, local: both},
		{name: "previous_hop_next_domain", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNOriginDomain, "<sender@origin.example>", "<relay@remote.example>"),
			receivedDSNNextDomainHop(receivedDSNRemoteDomain, receivedDSNLocalDomain),
			receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination),
		}}, tenant: true, local: local},
		{name: "null_previous_sender", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<>", receivedDSNLocalRecipient),
			receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination),
		}}, tenant: true, local: local},
		{name: "ambiguous_previous_recipient", spec: receivedDSNSpec{hops: []dsntest.Hop{
			receivedDSNHop(receivedDSNRemoteDomain, "<sender@remote.example>", receivedDSNLocalRecipient, "<other@local.example>"),
			receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, receivedDSNDestination),
		}}, tenant: true, local: local},
	}
}

// receivedDSNVectorExpectationOf freezes one evaluation.
func receivedDSNVectorExpectationOf(evaluation ReceivedDSNEvaluation) receivedDSNVectorExpectation {
	return receivedDSNVectorExpectation{
		Structure: string(evaluation.Structure()), Embedded: string(evaluation.Embedded()), LocalHop: string(evaluation.LocalHop()),
		OuterAlignment: string(evaluation.OuterAlignment()), RecipientLinkage: string(evaluation.RecipientLinkage()),
		Propagation: string(evaluation.Propagation()), OriginalForm: string(evaluation.OriginalForm()),
		CompletionSequence: evaluation.CompletionSequence(), RunLength: evaluation.LocalHopRunLength(),
	}
}

// loadReceivedDSNVectorCorpus reads the frozen corpus.
func loadReceivedDSNVectorCorpus(t *testing.T) receivedDSNVectorCorpus {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(receivedDSNVectorPath))
	if err != nil {
		t.Fatalf("ReadFile(received-dsn vectors) error=%v", err)
	}
	var corpus receivedDSNVectorCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("Unmarshal(received-dsn vectors) error=%v", err)
	}
	if corpus.Draft != DraftIdentifier || len(corpus.Cases) == 0 || len(corpus.Keys) == 0 {
		t.Fatalf("corpus draft=%q cases=%d keys=%d", corpus.Draft, len(corpus.Cases), len(corpus.Keys))
	}
	return corpus
}

// TestReceivedDSNGoldenVectorsRegenerate rewrites the corpus from the fixture
// specs when DKIM2_WRITE_RECEIVED_DSN_VECTORS=1 and is skipped otherwise.
func TestReceivedDSNGoldenVectorsRegenerate(t *testing.T) {
	if os.Getenv(receivedDSNVectorWriteFlag) != "1" {
		t.Skip("set " + receivedDSNVectorWriteFlag + "=1 to regenerate the received-DSN corpus")
	}
	corpus := receivedDSNVectorCorpus{Draft: DraftIdentifier, Keys: make(map[string]receivedDSNVectorKey)}
	for domain, key := range receivedDSNKeys() {
		corpus.Keys[domain] = receivedDSNVectorKey{Selector: key.Selector, Public: base64.StdEncoding.EncodeToString(key.Public())}
	}
	for _, entry := range receivedDSNVectorSpecs() {
		var authority LocalAuthority
		if entry.tenant {
			authority = newReceivedDSNAuthority(entry.local...)
		}
		evaluation, err := evaluateReceivedDSN(t, entry.spec, authority)
		if err != nil {
			t.Fatalf("%s: %v", entry.name, err)
		}
		corpus.Cases = append(corpus.Cases, receivedDSNVectorCase{
			Name: entry.name, Raw: base64.StdEncoding.EncodeToString(entry.spec.build(t)),
			Reverse: base64.StdEncoding.EncodeToString([]byte("<>")),
			Forward: []string{base64.StdEncoding.EncodeToString([]byte(entry.spec.recipient()))},
			Tenant:  entry.tenant, LocalDomains: entry.local, Expected: receivedDSNVectorExpectationOf(evaluation),
		})
	}
	encoded, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.FromSlash(receivedDSNVectorPath), append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReceivedDSNDraft06GoldenVectors proves the frozen corpus evaluates to
// its recorded projection using only the keys and inputs the corpus publishes.
func TestReceivedDSNDraft06GoldenVectors(t *testing.T) {
	corpus := loadReceivedDSNVectorCorpus(t)
	evaluator, err := NewVerifier(receivedDSNVectorProvider{keys: corpus.Keys}, receivedDSNClockOption())
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]struct{}, len(corpus.Cases))
	for _, vector := range corpus.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			if _, duplicate := names[vector.Name]; duplicate {
				t.Fatalf("duplicate vector name %q", vector.Name)
			}
			names[vector.Name] = struct{}{}
			raw, err := base64.StdEncoding.DecodeString(vector.Raw)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(bytes.ReplaceAll(raw, []byte("\r\n"), nil), []byte("\n")) {
				t.Fatal("vector contains bare line endings")
			}
			reverse, err := base64.StdEncoding.DecodeString(vector.Reverse)
			if err != nil {
				t.Fatal(err)
			}
			forward := make([][]byte, len(vector.Forward))
			for index, encoded := range vector.Forward {
				forward[index], err = base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			var authority LocalAuthority
			if vector.Tenant {
				authority = newReceivedDSNAuthority(vector.LocalDomains...)
			}
			evaluation, err := evaluator.EvaluateReceivedDSN(context.Background(), NewReceivedDSNRequest(raw, reverse, forward, authority))
			if err != nil {
				t.Fatalf("EvaluateReceivedDSN() error=%v", err)
			}
			if got := receivedDSNVectorExpectationOf(evaluation); got != vector.Expected {
				t.Fatalf("projection=%+v want=%+v", got, vector.Expected)
			}
		})
	}
	want := make([]string, 0, len(receivedDSNVectorSpecs()))
	for _, entry := range receivedDSNVectorSpecs() {
		want = append(want, entry.name)
	}
	got := make([]string, 0, len(corpus.Cases))
	for _, vector := range corpus.Cases {
		got = append(got, vector.Name)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("corpus cases %v do not match fixture specs %v", got, want)
	}
}

// TestReceivedDSNGoldenVectorsMatchFixtureKeys proves the corpus keys are the
// deterministic fixture keys, so regeneration cannot silently change identities.
func TestReceivedDSNGoldenVectorsMatchFixtureKeys(t *testing.T) {
	corpus := loadReceivedDSNVectorCorpus(t)
	for domain, key := range receivedDSNKeys() {
		published, ok := corpus.Keys[domain]
		if !ok || published.Selector != key.Selector || published.Public != base64.StdEncoding.EncodeToString(key.Public()) {
			t.Fatalf("corpus key for %q does not match the fixture key", domain)
		}
	}
}
