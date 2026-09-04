package dkim2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
)

const (
	dsnPropagationVectorPath      = "testdata/vectors/draft-ietf-dkim-dkim2-spec-06/dsn-propagation-golden.json"
	dsnPropagationVectorWriteFlag = "DKIM2_WRITE_DSN_PROPAGATION_VECTORS"
)

// dsnPropagationVectorKey is one published Ed25519 key of the corpus.
type dsnPropagationVectorKey struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	Public   string `json:"ed25519_public_base64"`
}

// dsnPropagationVectorExpectation is the frozen outcome of one case.
type dsnPropagationVectorExpectation struct {
	Outcome         string `json:"outcome"`
	Embedded        string `json:"embedded"`
	Propagation     string `json:"propagation"`
	LocalHop        string `json:"local_hop"`
	SigningDomain   string `json:"signing_domain,omitempty"`
	NextHop         string `json:"next_hop_base64,omitempty"`
	SMTPUTF8        bool   `json:"smtputf8_required"`
	EightBitMIME    bool   `json:"eight_bit_mime_required"`
	OriginalForm    string `json:"original_form,omitempty"`
	SignedRFC5322   string `json:"signed_rfc5322_base64,omitempty"`
	SigningSequence uint64 `json:"signing_sequence,omitempty"`
}

// dsnPropagationVectorCase is one frozen rebuild and signing case.
type dsnPropagationVectorCase struct {
	Name         string                          `json:"name"`
	Raw          string                          `json:"raw_base64"`
	Forward      string                          `json:"forward_path_base64"`
	LocalDomains []string                        `json:"local_domains"`
	ReportingMTA string                          `json:"reporting_mta"`
	Expected     dsnPropagationVectorExpectation `json:"expected"`
}

// dsnPropagationVectorCorpus is the versioned propagation corpus.
type dsnPropagationVectorCorpus struct {
	Draft         string                     `json:"draft"`
	SigningClock  int64                      `json:"signing_clock_unix"`
	Keys          []dsnPropagationVectorKey  `json:"keys"`
	Cases         []dsnPropagationVectorCase `json:"cases"`
	EntropyScheme string                     `json:"entropy_scheme"`
}

// dsnPropagationVectorSpec pairs one case name with the fixture that regenerates it.
type dsnPropagationVectorSpec struct {
	name string
	spec propagationCase
}

// dsnPropagationVectorSpecs lists every frozen case in corpus order.
func dsnPropagationVectorSpecs() []dsnPropagationVectorSpec {
	both := []string{receivedDSNLocalDomain, receivedDSNForwardDomain}
	nextDomainRun := propagationOriginal(propagationFullRecipe)
	member := receivedDSNNextDomainHop(receivedDSNLocalDomain, receivedDSNForwardDomain)
	member.Instance = 2
	completion := receivedDSNHop(receivedDSNForwardDomain, receivedDSNForwardMailFrom, receivedDSNDestination)
	completion.Instance = 2
	nextDomainRun.Hops = []dsntest.Hop{nextDomainRun.Hops[0], member, completion}
	imaginaryRun := propagationOriginal(propagationFullRecipe)
	imaginary := receivedDSNHop(receivedDSNLocalDomain, receivedDSNLocalMailFrom, "<relay@forward.local.example>")
	imaginary.Instance = 2
	imaginaryRun.Hops = []dsntest.Hop{imaginaryRun.Hops[0], imaginary, completion}
	headerRecipe := propagationOriginal(propagationHeaderRecipe)
	headerRecipe.Revisions[0].Body = propagationCurrentBody
	bodyRecipe := propagationOriginal(propagationBodyRecipe)
	bodyRecipe.Revisions[0].Headers = propagationCurrentHeaders
	unsigned := propagationOriginal(propagationFullRecipe)
	unsigned.Headers = "Received: from origin by remote (below-previous)\r\nX-Origin-Trace: below-previous\r\n" + propagationCurrentHeaders
	unsigned.Revisions[0].Headers = "Received: from origin by remote (below-previous)\r\nX-Origin-Trace: below-previous\r\n" + propagationOriginHeaders
	unsigned.Prepend = "Received: from local by destination (above-run)\r\nAuthentication-Results: destination.example; dkim2=pass\r\nDKIM-Signature: v=1; d=destination.example; s=sel; b=above-run\r\n"
	unsigned.Hops[1].UnsignedAbove = "Received: from remote by local (between)\r\nX-Local-Trace: between\r\nReturn-Path: <forwarded@local.example>\r\n"
	unsigned.Hops[0].UnsignedAbove = "X-Remote-Trace: above-previous\r\n"
	corrupt := propagationOriginal(propagationFullRecipe)
	corrupt.Hops[0].CorruptSignature = true
	nullSender := propagationOriginal(propagationFullRecipe)
	nullSender.Hops[0].MailFrom = "<>"
	status := func(code string) string {
		return dsntest.FailedDeliveryStatus(receivedDSNDestinationDomain, receivedDSNDestinationRaw, code)
	}
	sourceRoutedRecipient := propagationOriginal(propagationFullRecipe)
	sourceRoutedRecipient.Hops[0].Recipients = []string{"<@relay.example:user@local.example>"}
	sourceRoutedSender := propagationOriginal(propagationFullRecipe)
	sourceRoutedSender.Hops[0].MailFrom = "<@relay.example:sender@remote.example>"
	utf8Header := propagationOriginal(propagationFullRecipe)
	utf8Header.Headers = "X-Origin-Note: caf\xc3\xa9\r\n" + propagationCurrentHeaders
	utf8Header.Revisions[0].Headers = "X-Origin-Note: caf\xc3\xa9\r\n" + propagationOriginHeaders
	eightBitBody := propagationOriginal(`{"h":{"subject":[{"d":[" origin"]}]},"b":[{"d":["café body"]}]}`)
	eightBitBody.Revisions[0].Body = "caf\xc3\xa9 body\r\n"
	multiMemberHeaderRecipe := propagationOriginal(propagationHeaderRecipe)
	multiMemberHeaderRecipe.Revisions[0].Body = propagationCurrentBody
	multiMemberHeaderRecipe.Headers = "Received: from origin by remote (below-previous)\r\n" + propagationCurrentHeaders + "To: user@local.example\r\n"
	multiMemberHeaderRecipe.Revisions[0].Headers = "Received: from origin by remote (below-previous)\r\n" + propagationOriginHeaders + "To: user@local.example\r\n"
	multiMemberHeaderRecipe.Hops = []dsntest.Hop{multiMemberHeaderRecipe.Hops[0], member, completion}
	betweenMembers := propagationOriginal(propagationFullRecipe)
	betweenMembers.Headers = "Received: from origin by remote (below-previous)\r\nX-Origin-Trace: below-previous\r\n" + propagationCurrentHeaders
	betweenMembers.Revisions[0].Headers = "Received: from origin by remote (below-previous)\r\nX-Origin-Trace: below-previous\r\n" + propagationOriginHeaders
	betweenMember := member
	betweenMember.UnsignedAbove = "Received: from remote by local (between-previous-and-member)\r\nReturn-Path: <forwarded@local.example>\r\n"
	betweenCompletion := completion
	betweenCompletion.UnsignedAbove = "Received: from local by forward (between-members)\r\nX-Forward-Trace: between-members\r\n"
	betweenMembers.Hops = []dsntest.Hop{betweenMembers.Hops[0], betweenMember, betweenCompletion}
	betweenMembers.Prepend = "Received: from forward by destination (above-run)\r\n"
	unsupportedTuple := propagationCase{original: propagationOriginal(propagationFullRecipe), mutate: func(raw []byte) []byte {
		return bytes.Replace(raw, []byte("Message-Instance: m=1; h=sha256:"), []byte("Message-Instance: m=1; h=sha999:"), 1)
	}}
	return []dsnPropagationVectorSpec{
		{"run_of_one", propagationCase{original: propagationOriginal(propagationFullRecipe)}},
		{"next_domain_run", propagationCase{original: nextDomainRun, outerRecipient: receivedDSNForwardMailFrom, local: both}},
		{"imaginary_hop_run", propagationCase{original: imaginaryRun, outerRecipient: receivedDSNForwardMailFrom, local: both}},
		{"header_recipe", propagationCase{original: headerRecipe}},
		{"body_recipe", propagationCase{original: bodyRecipe}},
		{"null_recipe_degrades", propagationCase{original: propagationOriginal(propagationNullRecipe)}},
		{"headers_only_original", propagationCase{original: headerRecipe, headersOnly: true}},
		{"unsigned_field_policy", propagationCase{original: unsigned}},
		{"status_transient_preserved", propagationCase{original: propagationOriginal(propagationFullRecipe), deliveryStatus: status("4.4.7")}},
		{"status_permanent_preserved", propagationCase{original: propagationOriginal(propagationFullRecipe), deliveryStatus: status("5.2.2")}},
		{"status_fallback", propagationCase{original: propagationOriginal(propagationFullRecipe), deliveryStatus: status("2.1.5")}},
		{"envid_copied", propagationCase{original: propagationOriginal(propagationFullRecipe), deliveryStatus: "Original-Envelope-Id: envid-12345\r\n" + status("5.1.1")}},
		{"envid_invalid_dropped", propagationCase{original: propagationOriginal(propagationFullRecipe), deliveryStatus: "Original-Envelope-Id: not xtext\r\n" + status("5.1.1")}},
		{"orcpt_copied", propagationCase{original: propagationOriginal(propagationFullRecipe), deliveryStatus: "Reporting-MTA: dns; destination.example\r\n\r\nOriginal-Recipient: rfc822;user@local.example\r\nFinal-Recipient: rfc822; dest@destination.example\r\nAction: failed\r\nStatus: 5.1.1\r\n"}},
		{"orcpt_foreign_dropped", propagationCase{original: propagationOriginal(propagationFullRecipe), deliveryStatus: "Reporting-MTA: dns; destination.example\r\n\r\nOriginal-Recipient: rfc822;other@local.example\r\nFinal-Recipient: rfc822; dest@destination.example\r\nAction: failed\r\nStatus: 5.1.1\r\n"}},
		{"previous_hop_unverified", propagationCase{original: corrupt}},
		{"null_previous_sender", propagationCase{original: nullSender}},
		{"not_local", propagationCase{original: propagationOriginal(propagationFullRecipe), local: []string{receivedDSNOtherDomain}}},
		{"source_route_previous_recipient", propagationCase{original: sourceRoutedRecipient}},
		{"source_route_previous_sender", propagationCase{original: sourceRoutedSender}},
		{"smtputf8_header_field", propagationCase{original: utf8Header}},
		{"eight_bit_body_only", propagationCase{original: eightBitBody}},
		{"two_hop_linked_chain", propagationCase{original: propagationTwoHopOriginal(propagationFullRecipe, "<user@remote.example>")}},
		{"header_recipe_multi_member_run", propagationCase{original: multiMemberHeaderRecipe, outerRecipient: receivedDSNForwardMailFrom, local: both}},
		{"unsigned_between_run_members", propagationCase{original: betweenMembers, outerRecipient: receivedDSNForwardMailFrom, local: both}},
		{"unsupported_historical_tuple", unsupportedTuple},
	}
}

// dsnPropagationVectorFixture builds the signer for the corpus keys.
func dsnPropagationVectorFixture(t *testing.T) propagationFixture {
	t.Helper()
	return newPropagationFixture(t, newPropagationProvider(receivedDSNLocalDomain, receivedDSNForwardDomain))
}

// dsnPropagationVectorEntropySeed returns the identifier entropy seed of one case.
func dsnPropagationVectorEntropySeed(name string) string { return propagationEntropySeed + ":" + name }

// runDSNPropagationVector rebuilds and, when rebuilt, signs one case.
func runDSNPropagationVector(t *testing.T, name string, spec propagationCase) (DSNPropagationEvidence, PropagatedDSN) {
	t.Helper()
	fixture := dsnPropagationVectorFixture(t)
	evidence, err := fixture.signer.RebuildDSNForPropagation(context.Background(), spec.requestWithEntropy(t, dsnPropagationVectorEntropySeed(name)))
	if err != nil {
		t.Fatalf("%s: RebuildDSNForPropagation() error=%v", name, err)
	}
	if !evidence.Rebuilt() {
		return evidence, PropagatedDSN{}
	}
	return evidence, fixture.mustSign(t, evidence)
}

// dsnPropagationVectorExpectationOf freezes the outcome of one case.
func dsnPropagationVectorExpectationOf(evidence DSNPropagationEvidence, propagated PropagatedDSN) dsnPropagationVectorExpectation {
	expectation := dsnPropagationVectorExpectation{
		Outcome: string(evidence.Outcome()), Embedded: string(evidence.Evaluation().Embedded()), Propagation: string(evidence.Evaluation().Propagation()),
		LocalHop: string(evidence.Evaluation().LocalHop()), SigningDomain: evidence.SigningDomain(),
		SMTPUTF8: evidence.SMTPUTF8Required(), EightBitMIME: evidence.EightBitMIMERequired(), OriginalForm: string(evidence.OriginalForm()),
	}
	if evidence.Rebuilt() {
		expectation.NextHop = base64.StdEncoding.EncodeToString(evidence.NextHopRecipient())
		expectation.SignedRFC5322 = base64.StdEncoding.EncodeToString(propagated.Bytes())
		expectation.SigningSequence = propagated.Facts().Sequence()
	}
	return expectation
}

// dsnPropagationVectorKeys lists every fixture key the corpus publishes.
func dsnPropagationVectorKeys() []dsnPropagationVectorKey {
	keys := make([]dsnPropagationVectorKey, 0)
	for domain, key := range receivedDSNKeys() {
		keys = append(keys, dsnPropagationVectorKey{Domain: domain, Selector: key.Selector, Public: base64.StdEncoding.EncodeToString(key.Public())})
	}
	for _, domain := range []string{receivedDSNLocalDomain, receivedDSNForwardDomain} {
		key := propagationSigningKey(domain)
		keys = append(keys, dsnPropagationVectorKey{Domain: domain, Selector: key.Selector, Public: base64.StdEncoding.EncodeToString(key.Public())})
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Domain != keys[j].Domain {
			return keys[i].Domain < keys[j].Domain
		}
		return keys[i].Selector < keys[j].Selector
	})
	return keys
}

// loadDSNPropagationVectorCorpus reads the frozen corpus.
func loadDSNPropagationVectorCorpus(t *testing.T) dsnPropagationVectorCorpus {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(dsnPropagationVectorPath))
	if err != nil {
		t.Fatalf("ReadFile(dsn-propagation vectors) error=%v", err)
	}
	var corpus dsnPropagationVectorCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("Unmarshal(dsn-propagation vectors) error=%v", err)
	}
	if corpus.Draft != DraftIdentifier || len(corpus.Cases) == 0 || len(corpus.Keys) == 0 || corpus.SigningClock != propagationSigningClock {
		t.Fatalf("corpus draft=%q cases=%d keys=%d clock=%d", corpus.Draft, len(corpus.Cases), len(corpus.Keys), corpus.SigningClock)
	}
	return corpus
}

// TestDSNPropagationGoldenVectorsRegenerate rewrites the corpus from the
// fixture specs when DKIM2_WRITE_DSN_PROPAGATION_VECTORS=1 and is skipped otherwise.
func TestDSNPropagationGoldenVectorsRegenerate(t *testing.T) {
	if os.Getenv(dsnPropagationVectorWriteFlag) != "1" {
		t.Skip("set " + dsnPropagationVectorWriteFlag + "=1 to regenerate the dsn-propagation corpus")
	}
	corpus := dsnPropagationVectorCorpus{
		Draft: DraftIdentifier, SigningClock: propagationSigningClock, Keys: dsnPropagationVectorKeys(),
		EntropyScheme: "seeded reader over " + propagationEntropySeed + ":<case name>",
	}
	for _, entry := range dsnPropagationVectorSpecs() {
		evidence, propagated := runDSNPropagationVector(t, entry.name, entry.spec)
		corpus.Cases = append(corpus.Cases, dsnPropagationVectorCase{
			Name: entry.name, Raw: base64.StdEncoding.EncodeToString(entry.spec.build(t)),
			Forward: base64.StdEncoding.EncodeToString([]byte(entry.spec.recipient())), LocalDomains: entry.spec.localDomains(),
			ReportingMTA: entry.spec.mta(), Expected: dsnPropagationVectorExpectationOf(evidence, propagated),
		})
	}
	encoded, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.FromSlash(dsnPropagationVectorPath), append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDSNPropagationDraft06GoldenVectors proves every frozen case rebuilds
// and signs to its recorded outcome and byte-exact output from the corpus
// input alone, under the published keys and the fixed clock and entropy.
func TestDSNPropagationDraft06GoldenVectors(t *testing.T) {
	corpus := loadDSNPropagationVectorCorpus(t)
	specs := make(map[string]propagationCase)
	for _, entry := range dsnPropagationVectorSpecs() {
		specs[entry.name] = entry.spec
	}
	if len(specs) != len(corpus.Cases) {
		t.Fatalf("corpus cases=%d specs=%d", len(corpus.Cases), len(specs))
	}
	for _, testCase := range corpus.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			raw, err := base64.StdEncoding.DecodeString(testCase.Raw)
			if err != nil {
				t.Fatal(err)
			}
			forward, err := base64.StdEncoding.DecodeString(testCase.Forward)
			if err != nil {
				t.Fatal(err)
			}
			fixture := dsnPropagationVectorFixture(t)
			request := NewDSNPropagationRequest(raw, []byte("<>"), [][]byte{forward}, newReceivedDSNAuthority(testCase.LocalDomains...), testCase.ReportingMTA)
			request.state.entropy = deterministicEntropy(dsnPropagationVectorEntropySeed(testCase.Name))
			evidence, err := fixture.signer.RebuildDSNForPropagation(context.Background(), request)
			if err != nil {
				t.Fatalf("RebuildDSNForPropagation() error=%v", err)
			}
			var propagated PropagatedDSN
			if evidence.Rebuilt() {
				propagated = fixture.mustSign(t, evidence)
			}
			got := dsnPropagationVectorExpectationOf(evidence, propagated)
			if got != testCase.Expected {
				t.Fatalf("expectation mismatch:\n got=%+v\nwant=%+v", got, testCase.Expected)
			}
			spec, ok := specs[testCase.Name]
			if !ok || !bytes.Equal(spec.build(t), raw) {
				t.Fatal("corpus input drifted from the regenerating fixture")
			}
		})
	}
}

// TestDSNPropagationGoldenVectorsMatchFixtureKeys proves the published keys
// equal the deterministic fixture keys so the corpus stays self-describing.
func TestDSNPropagationGoldenVectorsMatchFixtureKeys(t *testing.T) {
	corpus := loadDSNPropagationVectorCorpus(t)
	expected := dsnPropagationVectorKeys()
	if len(corpus.Keys) != len(expected) {
		t.Fatalf("corpus keys=%d fixture keys=%d", len(corpus.Keys), len(expected))
	}
	for index := range expected {
		if corpus.Keys[index] != expected[index] {
			t.Fatalf("key %d drifted", index)
		}
	}
}
