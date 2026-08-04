package dkim2

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const turscarDKIM2TestsRoot = "testdata/vectors/external/turscar-dkim2tests/9c48edf1b19bd4db69cd5f27e8732a5a61826739"

type turscarDKIM2TestsManifest struct {
	UpstreamDraft string                  `json:"upstream_draft"`
	LocalDraft    string                  `json:"local_draft"`
	Cases         []turscarDKIM2TestsCase `json:"cases"`
}

type turscarDKIM2TestsCase struct {
	ID          string `json:"id"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
	Execution   string `json:"execution"`
	LocalReason string `json:"local_expected_reason"`
	SignedPath  string `json:"signed_path"`
}

type turscarDKIM2TestsProvider struct{}

// LookupPublicKey fails the test if structural protocol rejection reaches DNS resolution.
func (turscarDKIM2TestsProvider) LookupPublicKey(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
	return PublicKeyResult{}, newAPIError(APIErrorCodeInvalidProvider)
}

// TestTurscarDKIM2TestsParserRefusal proves imported Draft-02-labelled fixtures remain classified as nonconformant bytes.
func TestTurscarDKIM2TestsParserRefusal(t *testing.T) {
	manifest := loadTurscarDKIM2TestsManifest(t)
	verifier, err := NewVerifier(turscarDKIM2TestsProvider{}, WithVerificationClock(func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}))
	if err != nil {
		t.Fatal("NewVerifier() failed")
	}
	for _, testCase := range manifest.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			if testCase.Disposition != "upstream_fixture_nonconformant" ||
				testCase.Reason != "missing_terminal_tag_semicolon" ||
				testCase.Execution != "parser_refusal_expected" ||
				(testCase.LocalReason != "malformed_protocol" && testCase.LocalReason != "limit_exceeded") {
				t.Fatal("unexpected external corpus disposition")
			}
			raw, err := os.ReadFile(filepath.Join(turscarDKIM2TestsRoot, filepath.FromSlash(testCase.SignedPath)))
			if err != nil {
				t.Fatal("ReadFile() failed")
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(
				raw, []byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.test>")},
			))
			if err != nil {
				t.Fatal("Verify() returned API error")
			}
			if result.State() != ResultStatePERMERROR || string(result.PrimaryReason()) != testCase.LocalReason {
				t.Fatalf("state/reason = %q/%q", result.State(), result.PrimaryReason())
			}
		})
	}
}

// loadTurscarDKIM2TestsManifest decodes the narrow test view without retaining upstream private TOML data.
func loadTurscarDKIM2TestsManifest(t *testing.T) turscarDKIM2TestsManifest {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(turscarDKIM2TestsRoot, "manifest.json"))
	if err != nil {
		t.Fatal("ReadFile() failed")
	}
	var manifest turscarDKIM2TestsManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal("manifest JSON is invalid")
	}
	if manifest.UpstreamDraft != "draft-ietf-dkim-dkim2-spec-02" ||
		manifest.LocalDraft != DraftIdentifier || len(manifest.Cases) != 42 {
		t.Fatal("manifest identity is invalid")
	}
	return manifest
}
