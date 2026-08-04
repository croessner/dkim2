// Package externalvectors validates retained public-only external vector corpora.
package externalvectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	// ManifestPath identifies the retained public-only Turscar corpus manifest.
	ManifestPath     = "lib/testdata/vectors/external/turscar-dkim2tests/9c48edf1b19bd4db69cd5f27e8732a5a61826739/manifest.json"
	manifestSchema   = "dkim2.external-vector-corpus.v1"
	maxManifestBytes = 128 << 10
	maxFixtureBytes  = 256 << 10
	maxCases         = 64
)

var (
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	caseIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Manifest records the immutable provenance and local disposition of one external corpus.
type Manifest struct {
	Schema            string `json:"schema"`
	CanonicalLocation string `json:"canonical_location"`
	Revision          string `json:"revision"`
	ArchiveSHA256     string `json:"archive_sha256"`
	LicensePath       string `json:"license_path"`
	LicenseSHA256     string `json:"license_sha256"`
	ProvenancePath    string `json:"provenance_path"`
	ProvenanceSHA256  string `json:"provenance_sha256"`
	UpstreamDraft     string `json:"upstream_draft"`
	LocalDraft        string `json:"local_draft"`
	Cases             []Case `json:"cases"`
}

// Case binds one public upstream message pair to a closed local disposition.
type Case struct {
	ID                 string `json:"id"`
	Disposition        string `json:"disposition"`
	Reason             string `json:"reason"`
	Execution          string `json:"execution"`
	LocalReason        string `json:"local_expected_reason"`
	UpstreamState      string `json:"upstream_expected_state"`
	UpstreamTOMLSHA256 string `json:"upstream_toml_sha256"`
	OriginalPath       string `json:"original_path"`
	OriginalSHA256     string `json:"original_sha256"`
	SignedPath         string `json:"signed_path"`
	SignedSHA256       string `json:"signed_sha256"`
}

// CheckRepository verifies the retained corpus without fetching or executing external code.
func CheckRepository(root string) error {
	content, err := readRepositoryFile(root, ManifestPath, maxManifestBytes)
	if err != nil {
		return err
	}
	manifest, err := LoadManifest(content)
	if err != nil {
		return err
	}
	base := strings.TrimSuffix(ManifestPath, "/manifest.json")
	if err := validateCorpusInventory(root, base, manifest); err != nil {
		return err
	}
	license, err := readRepositoryFile(root, base+"/"+manifest.LicensePath, maxFixtureBytes)
	if err != nil || SHA256(license) != manifest.LicenseSHA256 {
		return errors.New("external_vector_license")
	}
	provenance, err := readRepositoryFile(root, base+"/"+manifest.ProvenancePath, maxFixtureBytes)
	if err != nil || SHA256(provenance) != manifest.ProvenanceSHA256 {
		return errors.New("external_vector_provenance")
	}
	for _, testCase := range manifest.Cases {
		original, err := readRepositoryFile(root, base+"/"+testCase.OriginalPath, maxFixtureBytes)
		if err != nil || SHA256(original) != testCase.OriginalSHA256 || containsPrivateKey(original) {
			return errors.New("external_vector_original")
		}
		signed, err := readRepositoryFile(root, base+"/"+testCase.SignedPath, maxFixtureBytes)
		if err != nil || SHA256(signed) != testCase.SignedSHA256 || containsPrivateKey(signed) {
			return errors.New("external_vector_signed")
		}
		if !missingTerminalTagSemicolon(signed, "message-instance") ||
			!missingTerminalTagSemicolon(signed, "dkim2-signature") {
			return errors.New("external_vector_disposition")
		}
	}
	return nil
}

// LoadManifest strictly decodes and validates one external vector corpus manifest.
func LoadManifest(content []byte) (Manifest, error) {
	if len(content) == 0 || len(content) > maxManifestBytes {
		return Manifest{}, errors.New("external_vector_manifest_size")
	}
	var manifest Manifest
	if err := strictjson.Decode(content, &manifest, 12, 4096); err != nil {
		return Manifest{}, errors.New("external_vector_manifest_json")
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate enforces provenance, draft separation, and public-only fixture identity.
func (m Manifest) Validate() error {
	if m.Schema != manifestSchema ||
		m.CanonicalLocation != "https://forge.turscar.ie/turscar/dkim2tests" ||
		m.Revision != "9c48edf1b19bd4db69cd5f27e8732a5a61826739" ||
		m.ArchiveSHA256 != "fbff809cb8e07df428eba29511366f5f0dc0b983985f955d1aa63fdc10dbd7fb" ||
		m.LicensePath != "LICENSE" || !digestPattern.MatchString(m.LicenseSHA256) ||
		m.ProvenancePath != "UPSTREAM.md" || !digestPattern.MatchString(m.ProvenanceSHA256) ||
		m.UpstreamDraft != "draft-ietf-dkim-dkim2-spec-02" ||
		m.LocalDraft != "draft-ietf-dkim-dkim2-spec-04" || len(m.Cases) != 42 || len(m.Cases) > maxCases {
		return errors.New("external_vector_manifest_identity")
	}
	previous := ""
	seen := make(map[string]struct{}, len(m.Cases))
	for _, testCase := range m.Cases {
		if testCase.ID <= previous || !caseIDPattern.MatchString(testCase.ID) {
			return errors.New("external_vector_case_order")
		}
		previous = testCase.ID
		if _, exists := seen[testCase.ID]; exists {
			return errors.New("external_vector_case_duplicate")
		}
		seen[testCase.ID] = struct{}{}
		if testCase.Disposition != "upstream_fixture_nonconformant" ||
			testCase.Reason != "missing_terminal_tag_semicolon" ||
			testCase.Execution != "parser_refusal_expected" ||
			(testCase.LocalReason != "malformed_protocol" && testCase.LocalReason != "limit_exceeded") ||
			(testCase.UpstreamState != "pass" && testCase.UpstreamState != "fail" && testCase.UpstreamState != "permerror") ||
			!digestPattern.MatchString(testCase.UpstreamTOMLSHA256) ||
			testCase.OriginalPath != "messages/"+testCase.ID+".orig" ||
			testCase.SignedPath != "messages/"+testCase.ID+".signed" ||
			!digestPattern.MatchString(testCase.OriginalSHA256) || !digestPattern.MatchString(testCase.SignedSHA256) {
			return errors.New("external_vector_case_identity")
		}
	}
	return nil
}

// validateCorpusInventory rejects any retained corpus file that is not a single expected regular file.
func validateCorpusInventory(root, base string, manifest Manifest) error {
	expected := map[string]struct{}{
		"manifest.json":         {},
		manifest.LicensePath:    {},
		manifest.ProvenancePath: {},
	}
	for _, testCase := range manifest.Cases {
		expected[testCase.OriginalPath] = struct{}{}
		expected[testCase.SignedPath] = struct{}{}
	}
	corpusRoot := filepath.Join(root, filepath.FromSlash(base))
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(corpusRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(corpusRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			if !entry.IsDir() {
				return errors.New("external_vector_inventory")
			}
			return nil
		}
		if entry.IsDir() {
			if relative != "messages" {
				return errors.New("external_vector_inventory")
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("external_vector_inventory")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || hasMultipleLinks(info) {
			return errors.New("external_vector_inventory")
		}
		if _, ok := expected[relative]; !ok {
			return errors.New("external_vector_inventory")
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil || len(seen) != len(expected) {
		return errors.New("external_vector_inventory")
	}
	return nil
}

// hasMultipleLinks reports whether a regular corpus artifact has additional hard-link names.
func hasMultipleLinks(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink != 1
}

// SHA256 returns the lowercase SHA-256 identity of one bounded artifact.
func SHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// readRepositoryFile opens one descriptor-confined regular repository file with a strict size bound.
func readRepositoryFile(root, relative string, limit int64) ([]byte, error) {
	file, err := artifactpath.OpenFile(root, relative, limit)
	if err != nil {
		return nil, errors.New("external_vector_read")
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, errors.New("external_vector_read")
	}
	return content, nil
}

// containsPrivateKey rejects retained bytes that look like PEM private-key material.
func containsPrivateKey(content []byte) bool {
	return bytes.Contains(content, []byte("PRIVATE KEY"))
}

// missingTerminalTagSemicolon reports whether every named DKIM2 header omits the mandatory terminal semicolon.
func missingTerminalTagSemicolon(message []byte, fieldName string) bool {
	headers, _, found := bytes.Cut(message, []byte("\r\n\r\n"))
	if !found {
		return false
	}
	lines := bytes.Split(headers, []byte("\r\n"))
	matched := false
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		colon := bytes.IndexByte(line, ':')
		if colon < 0 || !strings.EqualFold(string(line[:colon]), fieldName) {
			continue
		}
		matched = true
		value := bytes.TrimSpace(line[colon+1:])
		for index+1 < len(lines) && len(lines[index+1]) > 0 && (lines[index+1][0] == ' ' || lines[index+1][0] == '\t') {
			index++
			value = bytes.TrimSpace(lines[index])
		}
		if len(value) == 0 || value[len(value)-1] == ';' {
			return false
		}
	}
	return matched
}

// SortedCaseIDs returns the manifest case identifiers for deterministic external reporting.
func (m Manifest) SortedCaseIDs() []string {
	identifiers := make([]string, 0, len(m.Cases))
	for _, testCase := range m.Cases {
		identifiers = append(identifiers, testCase.ID)
	}
	slices.Sort(identifiers)
	return identifiers
}
