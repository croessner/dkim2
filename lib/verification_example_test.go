package dkim2_test

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

//go:embed testdata/vectors/draft-ietf-dkim-dkim2-spec-04/public-golden.json
var publicExampleCorpus []byte

type syntheticMissingProvider struct{}

type syntheticTemporaryProvider struct{}

// LookupPublicKey returns deterministic key absence without network access.
func (syntheticMissingProvider) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	return dkim2.MissingPublicKey(query.Algorithm()), nil
}

// LookupPublicKey returns typed temporary state without exposing a provider cause.
func (syntheticTemporaryProvider) LookupPublicKey(context.Context, dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	return dkim2.PublicKeyResult{}, dkim2.NewTemporaryProviderError()
}

// ExampleVerifier demonstrates secret-safe structured result handling.
func ExampleVerifier() {
	verifier, err := dkim2.NewVerifier(
		syntheticMissingProvider{},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }),
	)
	if err != nil {
		fmt.Println("construction error")
		return
	}
	result, err := verifier.Verify(context.Background(), syntheticExampleRequest())
	if err != nil {
		fmt.Println("caller or API error")
		return
	}

	switch result.State() {
	case dkim2.ResultStatePASS:
		fmt.Println("PASS")
	case dkim2.ResultStateFAIL:
		fmt.Println("FAIL")
	case dkim2.ResultStatePERMERROR:
		fmt.Println("PERMERROR")
	case dkim2.ResultStateTEMPERROR:
		fmt.Println("TEMPERROR")
	}
	fmt.Println(result.PrimaryReason())
	fmt.Println(result.Scope(), result.HistoricalContent(), result.HistoricalSignatures(), result.CustodyStructure())
	fmt.Println(result.CheckCount(), result.SignatureSetCount())
	for _, check := range result.Checks() {
		fmt.Println(check.Class(), check.Reason())
	}
	for _, signature := range result.SignatureSets() {
		fmt.Println(signature.Algorithm(), signature.Status(), signature.Reason())
	}

	// Output:
	// PERMERROR
	// missing_key
	// current not_evaluated not_evaluated not_present
	// 7 1
	// body_hash none
	// domain_alignment none
	// envelope none
	// header_hash none
	// key missing_key
	// next_domain none
	// timestamp none
	// rsa-sha256 permerror missing_key
}

// ExampleVerifier_temporaryProvider demonstrates bounded provider-failure inspection.
func ExampleVerifier_temporaryProvider() {
	verifier, err := dkim2.NewVerifier(syntheticTemporaryProvider{}, dkim2.WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		fmt.Println("construction error")
		return
	}
	result, err := verifier.Verify(context.Background(), syntheticExampleRequest())
	if err != nil {
		fmt.Println("caller or API error")
		return
	}
	fact := result.SignatureSets()[0]
	fmt.Println(result.State(), result.PrimaryReason())
	fmt.Println(fact.Algorithm(), fact.Status(), fact.Reason())

	// Output:
	// TEMPERROR provider_temporary
	// rsa-sha256 temperror provider_temporary
}

// syntheticExampleRequest decodes the frozen synthetic current-message fixture.
func syntheticExampleRequest() dkim2.VerifyRequest {
	type vector struct {
		Raw     string   `json:"raw_base64"`
		Reverse string   `json:"reverse_path_base64"`
		Forward []string `json:"forward_paths_base64"`
	}
	var corpus struct {
		Vectors map[string]vector `json:"vectors"`
	}
	_ = json.Unmarshal(publicExampleCorpus, &corpus)
	fixture := corpus.Vectors["rsa_pass"]
	raw, _ := base64.StdEncoding.DecodeString(fixture.Raw)
	reverse, _ := base64.StdEncoding.DecodeString(fixture.Reverse)
	forward := make([][]byte, len(fixture.Forward))
	for index, encoded := range fixture.Forward {
		forward[index], _ = base64.StdEncoding.DecodeString(encoded)
	}
	return dkim2.NewVerifyRequest(raw, reverse, forward)
}
