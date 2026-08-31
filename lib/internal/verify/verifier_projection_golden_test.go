package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/croessner/dkim2/internal/recipe"
)

type verifierProjectionGolden struct {
	Schema           string `json:"schema"`
	Draft            string `json:"draft"`
	BindingAlgorithm string `json:"binding_algorithm"`
	Hop              struct {
		Sequence               uint64   `json:"sequence"`
		MessageInstance        uint64   `json:"message_instance"`
		SignerDomain           string   `json:"signer_domain"`
		SignatureAlgorithms    []string `json:"signature_algorithms"`
		SignatureState         string   `json:"signature_state"`
		CustodyTransition      string   `json:"custody_transition"`
		DoNotModify            bool     `json:"do_not_modify"`
		DoNotExplode           bool     `json:"do_not_explode"`
		Feedback               bool     `json:"feedback"`
		FeedHere               bool     `json:"feed_here"`
		Exploded               bool     `json:"exploded"`
		RecipeMode             string   `json:"recipe_mode"`
		RecipeHasHeaderChanges bool     `json:"recipe_has_header_changes"`
		RecipeBodyMode         string   `json:"recipe_body_mode"`
		ChangeClasses          []string `json:"change_classes"`
		AffectedHeaders        []string `json:"affected_headers"`
		ChangeCount            int      `json:"change_count"`
		AffectedHeaderCount    int      `json:"affected_header_count"`
		HistoryHeaderState     string   `json:"history_header_state"`
		HistoryBodyState       string   `json:"history_body_state"`
		BodyAvailability       string   `json:"body_availability"`
	} `json:"hop"`
	Expected struct {
		RecipeDescriptorDigest string `json:"recipe_descriptor_digest_base64"`
		HopContentDigest       string `json:"hop_content_digest_base64"`
		ProjectionBinding      string `json:"projection_binding_base64"`
		HopBinding             string `json:"hop_binding_base64"`
	} `json:"expected"`
}

// TestVerifierProjectionBindingGolden locks the cross-repository canonical byte contract.
func TestVerifierProjectionBindingGolden(t *testing.T) {
	fixture := loadVerifierProjectionGolden(t)
	parser, err := recipe.NewParser(recipe.DefaultLimits())
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	plan, _, err := parser.Parse([]byte(`{"h":{"subject":[],"x-trace":[]},"b":[]}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	descriptor := plan.Descriptor()
	assertGoldenDigest(t, "recipe descriptor", descriptor.Digest(), fixture.Expected.RecipeDescriptorDigest)
	hop := VerifierHop{
		domain: fixture.Hop.SignerDomain, algorithms: []Algorithm{AlgorithmEd25519SHA256, AlgorithmRSASHA256},
		recipe: descriptor, sequence: fixture.Hop.Sequence, instance: fixture.Hop.MessageInstance,
		custody: VerifierCustodyTransition(fixture.Hop.CustodyTransition), recipeMode: VerifierRecipeMode(fixture.Hop.RecipeMode),
		headerState: HistoryDimensionState(fixture.Hop.HistoryHeaderState), bodyState: HistoryDimensionState(fixture.Hop.HistoryBodyState),
		bodyAvailable: recipe.BodyAvailability(fixture.Hop.BodyAvailability),
		flags:         RevisionFlagFacts{doNotModify: fixture.Hop.DoNotModify, doNotExplode: fixture.Hop.DoNotExplode, feedback: fixture.Hop.Feedback, feedHere: fixture.Hop.FeedHere, exploded: fixture.Hop.Exploded},
		sealed:        true,
	}
	contentDigest := verifierHopContentDigest(hop)
	assertGoldenDigest(t, "hop content", contentDigest, fixture.Expected.HopContentDigest)
	projectionBinding := verifierProjectionBinding([]VerifierHop{hop})
	assertGoldenDigest(t, "projection", projectionBinding, fixture.Expected.ProjectionBinding)
	hop.binding = verifierBoundHopBinding(projectionBinding, hop)
	assertGoldenDigest(t, "bound hop", hop.binding, fixture.Expected.HopBinding)
	projection := VerifierProjection{hops: []VerifierHop{hop}, binding: projectionBinding, draft: fixture.Draft, schema: fixture.Schema, sealed: true}
	if !projection.Valid() || fixture.Hop.SignatureState != "pass" || fixture.Hop.RecipeHasHeaderChanges != descriptor.HasHeaderChanges() ||
		fixture.BindingAlgorithm != "sha-256" ||
		fixture.Hop.ChangeCount != descriptor.ChangeCount() || fixture.Hop.AffectedHeaderCount != descriptor.AffectedHeaderCount() {
		t.Fatal("golden projection is not coherent with the producer model")
	}
}

// loadVerifierProjectionGolden decodes the shared reference vector strictly.
func loadVerifierProjectionGolden(t *testing.T) verifierProjectionGolden {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/reference/verifier-projection-v1-binding.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var fixture verifierProjectionGolden
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&fixture); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return fixture
}

// assertGoldenDigest compares one fixed-size digest with its canonical base64 expectation.
func assertGoldenDigest(t *testing.T, name string, got [32]byte, encoded string) {
	t.Helper()
	want, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(want) != 32 {
		t.Fatalf("%s expectation is invalid", name)
	}
	if string(got[:]) != string(want) {
		t.Fatalf("%s digest = %s, want %s", name, base64.StdEncoding.EncodeToString(got[:]), encoded)
	}
}
