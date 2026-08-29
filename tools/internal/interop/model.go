// Package interop owns closed external-discovery and comparison evidence.
//
//nolint:goconst // Closed state and claim vocabularies stay explicit at validation sites.
package interop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	// MessageDraft is the exact message-signature behavior baseline.
	MessageDraft = "draft-ietf-dkim-dkim2-spec-06"
	// DNSDraft is the exact historical DNS behavior identifier.
	DNSDraft = "draft-chuang-dkim2-dns-04"
	// RegistrySchema identifies the closed discovery registry.
	RegistrySchema = "dkim2.interop-discovery-registry.v1"
	// EvidenceSchema identifies normalized discovery evidence.
	EvidenceSchema = "dkim2.interop-discovery-evidence.v1"
	// ComparisonSchema identifies normalized external comparison evidence.
	ComparisonSchema = "dkim2.external-comparison.v1"
	// CatalogSchema identifies the reviewed immutable candidate inventory.
	CatalogSchema = "dkim2.interop-candidate-catalog.v1"
	// CandidateSnapshotSchema identifies the existing candidate framing.
	CandidateSnapshotSchema = "dkim2.candidate-snapshot.v1"

	maxRegistryBytes = 256 << 10
	maxJSONDepth     = 20
	maxJSONTokens    = 32768
)

var (
	idPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	licensePattern  = regexp.MustCompile(`^[A-Za-z0-9.+-]{1,64}$`)
	allowedHosts    = stringSet(
		"datatracker.ietf.org",
		"forge.turscar.ie",
		"github.com",
		"mailarchive.ietf.org",
		"raw.githubusercontent.com",
		"www.ietf.org",
	)
	allowedSourceKinds = stringSet(
		"ietf_draft", "ietf_mail_archive", "source_repository",
		"source_forge_search",
	)
	allowedCandidateStates = stringSet(
		"eligible_runnable", "eligible_vectors_only", "ineligible_not_dkim2",
		"ineligible_not_independent", "ineligible_no_immutable_source",
		"ineligible_license_unknown", "ineligible_unsafe_execution",
		"ineligible_no_overlap", "source_unavailable", "malformed_evidence",
	)
	allowedSourceStates = stringSet("observed", "not_found", "unavailable", "invalid")
	allowedAvailability = stringSet(
		"compared", "no_eligible_candidate", "eligible_not_runnable",
		"disagreement", "discovery_unavailable", "evidence_invalid",
	)
	allowedComparisonStates = stringSet(
		"agreement", "disagreement", "unsupported", "not_runnable",
	)
)

// Registry defines the only current discovery sources and fixed queries.
type Registry struct {
	Schema          string            `json:"schema"`
	MessageDraft    string            `json:"message_draft"`
	DNSDraft        string            `json:"dns_draft"`
	MaxAgeHours     int               `json:"max_age_hours"`
	RetrievalPolicy RetrievalPolicy   `json:"retrieval_policy"`
	Sources         []DiscoverySource `json:"sources"`
}

// RetrievalPolicy bounds hostile discovery responses before normalization.
type RetrievalPolicy struct {
	MaxRedirects     int   `json:"max_redirects"`
	MaxResponseBytes int64 `json:"max_response_bytes"`
	MaxFiles         int   `json:"max_files"`
	MaxFileBytes     int64 `json:"max_file_bytes"`
	MaxTotalBytes    int64 `json:"max_total_bytes"`
	MaxPathBytes     int   `json:"max_path_bytes"`
	MaxDepth         int   `json:"max_depth"`
	TimeoutSeconds   int   `json:"timeout_seconds"`
}

// DiscoverySource declares one reviewed primary source or fixed source-forge query.
type DiscoverySource struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	URL           string `json:"url"`
	Query         string `json:"query"`
	Required      bool   `json:"required"`
	CandidateHint string `json:"candidate_hint,omitempty"`
}

// DiscoveryEvidence is the normalized bounded output of one current discovery.
type DiscoveryEvidence struct {
	Schema                  string              `json:"schema"`
	MessageDraft            string              `json:"message_draft"`
	DNSDraft                string              `json:"dns_draft"`
	BaseRevision            string              `json:"base_revision"`
	CandidateSnapshotSHA256 string              `json:"candidate_snapshot_sha256"`
	RegistrySHA256          string              `json:"registry_sha256"`
	ObservationCutoff       string              `json:"observation_cutoff"`
	Sources                 []SourceObservation `json:"sources"`
	Candidates              []Candidate         `json:"candidates"`
	Availability            string              `json:"availability"`
}

// SourceObservation records one content-free primary-source result.
type SourceObservation struct {
	ID               string `json:"id"`
	State            string `json:"state"`
	ResponseSHA256   string `json:"response_sha256,omitempty"`
	NormalizedSHA256 string `json:"normalized_sha256,omitempty"`
}

// Candidate records one independently classified implementation identity.
type Candidate struct {
	ID                string   `json:"id"`
	CanonicalLocation string   `json:"canonical_location"`
	Revision          string   `json:"revision,omitempty"`
	TreeSHA           string   `json:"tree_sha,omitempty"`
	SourceSHA256      string   `json:"source_sha256,omitempty"`
	InventorySHA256   string   `json:"inventory_sha256,omitempty"`
	BuildSHA256       string   `json:"build_sha256,omitempty"`
	DependencySHA256  string   `json:"dependency_sha256,omitempty"`
	License           string   `json:"license,omitempty"`
	ClaimedDraft      string   `json:"claimed_draft,omitempty"`
	Operations        []string `json:"operations"`
	State             string   `json:"state"`
	Reason            string   `json:"reason"`
	EvidenceSources   []string `json:"evidence_sources"`
}

// CandidateCatalog freezes reviewed primary-source classifications for one observation.
type CandidateCatalog struct {
	Schema     string      `json:"schema"`
	Candidates []Candidate `json:"candidates"`
}

// ComparisonReport records deterministic overlap results without hostile output.
type ComparisonReport struct {
	Schema                  string           `json:"schema"`
	MessageDraft            string           `json:"message_draft"`
	DNSDraft                string           `json:"dns_draft"`
	BaseRevision            string           `json:"base_revision"`
	CandidateSnapshotSHA256 string           `json:"candidate_snapshot_sha256"`
	RegistrySHA256          string           `json:"registry_sha256"`
	EvidenceSHA256          string           `json:"evidence_sha256"`
	ObservationCutoff       string           `json:"observation_cutoff"`
	Cases                   []ComparisonCase `json:"cases"`
	Availability            string           `json:"availability"`
}

// ComparisonCase records one exact overlap and its closed result class.
type ComparisonCase struct {
	CandidateID      string `json:"candidate_id"`
	CaseID           string `json:"case_id"`
	Operation        string `json:"operation"`
	ClaimClass       string `json:"claim_class"`
	FixtureSHA256    string `json:"fixture_sha256"`
	LocalProducer    string `json:"local_producer_sha256"`
	ExternalProducer string `json:"external_producer_sha256"`
	State            string `json:"state"`
	Classification   string `json:"classification,omitempty"`
	Limitation       string `json:"limitation,omitempty"`
}

// LoadRegistry decodes and validates one closed registry document.
func LoadRegistry(content []byte) (Registry, error) {
	if len(content) == 0 || len(content) > maxRegistryBytes {
		return Registry{}, errors.New("registry_size")
	}
	var registry Registry
	if err := strictjson.Decode(content, &registry, maxJSONDepth, maxJSONTokens); err != nil {
		return Registry{}, errors.New("registry_json")
	}
	if err := registry.Validate(); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

// Validate enforces the closed registry identity, policy, ordering, and URLs.
func (r Registry) Validate() error {
	if r.Schema != RegistrySchema || r.MessageDraft != MessageDraft || r.DNSDraft != DNSDraft ||
		r.MaxAgeHours < 1 || r.MaxAgeHours > 168 {
		return errors.New("registry_identity")
	}
	if err := r.RetrievalPolicy.Validate(); err != nil {
		return err
	}
	if len(r.Sources) < 5 || len(r.Sources) > 64 {
		return errors.New("registry_sources")
	}
	previous := ""
	seenURL := make(map[string]struct{}, len(r.Sources))
	requiredKinds := stringSet("ietf_draft", "ietf_mail_archive", "source_repository", "source_forge_search")
	for _, source := range r.Sources {
		if source.ID <= previous || !idPattern.MatchString(source.ID) ||
			!allowedSourceKinds[source.Kind] || !source.Required {
			return errors.New("registry_sources")
		}
		previous = source.ID
		if err := validateSourceURL(source); err != nil {
			return err
		}
		if _, exists := seenURL[source.URL]; exists {
			return errors.New("registry_duplicate")
		}
		seenURL[source.URL] = struct{}{}
		delete(requiredKinds, source.Kind)
		if source.CandidateHint != "" && !idPattern.MatchString(source.CandidateHint) {
			return errors.New("registry_candidate_hint")
		}
	}
	if len(requiredKinds) != 0 {
		return errors.New("registry_coverage")
	}
	return nil
}

// Validate enforces finite hostile-input retrieval bounds.
func (p RetrievalPolicy) Validate() error {
	if p.MaxRedirects < 0 || p.MaxRedirects > 4 ||
		p.MaxResponseBytes < 1024 || p.MaxResponseBytes > 16<<20 ||
		p.MaxFiles < 1 || p.MaxFiles > 32768 ||
		p.MaxFileBytes < 1024 || p.MaxFileBytes > 64<<20 ||
		p.MaxTotalBytes < p.MaxFileBytes || p.MaxTotalBytes > 512<<20 ||
		p.MaxPathBytes < 64 || p.MaxPathBytes > 4096 ||
		p.MaxDepth < 1 || p.MaxDepth > 64 ||
		p.TimeoutSeconds < 1 || p.TimeoutSeconds > 120 {
		return errors.New("registry_policy")
	}
	return nil
}

// Validate checks discovery identity, freshness, closure, and availability.
func (e DiscoveryEvidence) Validate(registry Registry, now time.Time) error {
	if err := e.validateIdentity(registry, now); err != nil {
		return err
	}
	unavailable, invalid, err := e.validateSources(registry)
	if err != nil {
		return err
	}
	if err := validateCandidates(e.Candidates, registry); err != nil {
		return err
	}
	return e.validateAvailability(unavailable, invalid)
}

// validateIdentity checks immutable discovery identity and its observation clock.
func (e DiscoveryEvidence) validateIdentity(registry Registry, now time.Time) error {
	if e.Schema != EvidenceSchema || e.MessageDraft != MessageDraft || e.DNSDraft != DNSDraft ||
		!revisionPattern.MatchString(e.BaseRevision) || !digestPattern.MatchString(e.CandidateSnapshotSHA256) ||
		!digestPattern.MatchString(e.RegistrySHA256) || !allowedAvailability[e.Availability] {
		return errors.New("evidence_identity")
	}
	cutoff, err := time.Parse(time.RFC3339, e.ObservationCutoff)
	if err != nil || cutoff.After(now.Add(time.Minute)) ||
		now.Sub(cutoff) > time.Duration(registry.MaxAgeHours)*time.Hour {
		return errors.New("evidence_freshness")
	}
	if len(e.Sources) != len(registry.Sources) {
		return errors.New("evidence_sources")
	}
	return nil
}

// validateSources checks exact source ordering, states, and digest closure.
func (e DiscoveryEvidence) validateSources(registry Registry) (bool, bool, error) {
	unavailable := false
	invalid := false
	for index, observation := range e.Sources {
		if observation.ID != registry.Sources[index].ID || !allowedSourceStates[observation.State] {
			return false, false, errors.New("evidence_sources")
		}
		if observation.State == "observed" {
			if !digestPattern.MatchString(observation.ResponseSHA256) ||
				!digestPattern.MatchString(observation.NormalizedSHA256) {
				return false, false, errors.New("evidence_digest")
			}
		} else if observation.ResponseSHA256 != "" || observation.NormalizedSHA256 != "" {
			return false, false, errors.New("evidence_digest")
		}
		if registry.Sources[index].Required && observation.State == "unavailable" {
			unavailable = true
		}
		if registry.Sources[index].Required && observation.State == "invalid" {
			invalid = true
		}
	}
	return unavailable, invalid, nil
}

// validateAvailability prevents required-source failures from becoming absence claims.
func (e DiscoveryEvidence) validateAvailability(unavailable bool, invalid bool) error {
	if unavailable && e.Availability != "discovery_unavailable" {
		return errors.New("evidence_availability")
	}
	if invalid && e.Availability != "evidence_invalid" {
		return errors.New("evidence_availability")
	}
	if !unavailable && e.Availability == "discovery_unavailable" ||
		!invalid && e.Availability == "evidence_invalid" {
		return errors.New("evidence_availability")
	}
	if e.Availability == "no_eligible_candidate" && hasEligibleCandidate(e.Candidates) {
		return errors.New("evidence_availability")
	}
	if e.Availability == "compared" || e.Availability == "disagreement" {
		return errors.New("evidence_comparison_required")
	}
	return nil
}

// CanonicalJSON returns stable normalized JSON for candidate-bound evidence.
func CanonicalJSON(value any) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, errors.New("evidence_encode")
	}
	content = append(content, '\n')
	return content, nil
}

// SHA256 returns the lowercase content digest for one bounded evidence document.
func SHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// EqualCanonical reports whether two normalized documents are byte-identical.
func EqualCanonical(left, right []byte) bool {
	return bytes.Equal(left, right)
}

// Validate checks comparison identity, ordering, overlap states, and aggregate state.
//
//nolint:gocyclo // The closed comparison state matrix is intentionally audited in one owner.
func (r ComparisonReport) Validate(evidence DiscoveryEvidence) error {
	if r.Schema != ComparisonSchema || r.MessageDraft != MessageDraft || r.DNSDraft != DNSDraft ||
		r.BaseRevision != evidence.BaseRevision ||
		r.CandidateSnapshotSHA256 != evidence.CandidateSnapshotSHA256 ||
		r.RegistrySHA256 != evidence.RegistrySHA256 ||
		!digestPattern.MatchString(r.EvidenceSHA256) ||
		r.ObservationCutoff != evidence.ObservationCutoff ||
		!allowedAvailability[r.Availability] {
		return errors.New("comparison_identity")
	}
	previous := ""
	hasAgreement := false
	hasDisagreement := false
	candidates := make(map[string]Candidate, len(evidence.Candidates))
	seenCandidates := make(map[string]bool)
	for _, candidate := range evidence.Candidates {
		candidates[candidate.ID] = candidate
	}
	for _, result := range r.Cases {
		key := result.CandidateID + "/" + result.CaseID
		if key <= previous || !idPattern.MatchString(result.CandidateID) ||
			!idPattern.MatchString(result.CaseID) || !idPattern.MatchString(result.Operation) ||
			!isClaimClass(result.ClaimClass) ||
			!digestPattern.MatchString(result.FixtureSHA256) ||
			!digestPattern.MatchString(result.LocalProducer) ||
			!digestPattern.MatchString(result.ExternalProducer) ||
			!allowedComparisonStates[result.State] {
			return errors.New("comparison_cases")
		}
		previous = key
		candidate, exists := candidates[result.CandidateID]
		if !exists || !slices.Contains(candidate.Operations, result.Operation) ||
			!strings.HasPrefix(candidate.State, "eligible_") {
			return errors.New("comparison_candidate")
		}
		seenCandidates[result.CandidateID] = true
		if result.State == "agreement" {
			hasAgreement = true
		}
		if result.State == "disagreement" {
			hasDisagreement = true
			if !idPattern.MatchString(result.Classification) {
				return errors.New("comparison_classification")
			}
		} else if result.Classification != "" {
			return errors.New("comparison_classification")
		}
		if len(result.Limitation) > 128 || strings.ContainsAny(result.Limitation, "\r\n") ||
			(result.State == "agreement" && result.Limitation != "") ||
			((result.State == "unsupported" || result.State == "not_runnable") &&
				!idPattern.MatchString(result.Limitation)) ||
			(result.State == "not_runnable" && candidate.State != "eligible_vectors_only") {
			return errors.New("comparison_limitation")
		}
	}
	for _, candidate := range evidence.Candidates {
		if strings.HasPrefix(candidate.State, "eligible_") && !seenCandidates[candidate.ID] {
			return errors.New("comparison_candidate")
		}
	}
	if hasDisagreement != (r.Availability == "disagreement") {
		return errors.New("comparison_availability")
	}
	if r.Availability == "compared" && !hasAgreement {
		return errors.New("comparison_availability")
	}
	if r.Availability == "no_eligible_candidate" && len(r.Cases) != 0 {
		return errors.New("comparison_availability")
	}
	if r.Availability == "eligible_not_runnable" {
		hasNotRunnable := false
		for _, result := range r.Cases {
			hasNotRunnable = hasNotRunnable || result.State == "not_runnable"
		}
		if !hasAgreement || !hasNotRunnable {
			return errors.New("comparison_availability")
		}
	}
	return nil
}

// validateSourceURL rejects credentials, fragments, unsafe query keys, and unknown authorities.
func validateSourceURL(source DiscoverySource) error {
	parsed, err := url.Parse(source.URL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.Fragment != "" || !allowedHosts[strings.ToLower(parsed.Hostname())] ||
		parsed.Port() != "" || parsed.RawQuery != "" || parsed.Path == "" ||
		strings.Contains(parsed.Path, "..") {
		return errors.New("registry_url")
	}
	if source.Query == "" || len(source.Query) > 256 || strings.ContainsAny(source.Query, "\r\n") {
		return errors.New("registry_query")
	}
	lowerQuery := strings.ToLower(source.Query)
	for _, forbidden := range []string{"token", "password", "secret", "command", "image", "environment"} {
		if strings.Contains(lowerQuery, forbidden) {
			return errors.New("registry_query")
		}
	}
	return nil
}

// validateCandidates checks sorted exact identities and source ownership.
//
//nolint:gocyclo // The closed eligibility matrix is intentionally audited in one owner.
func validateCandidates(candidates []Candidate, registry Registry) error {
	sources := make(map[string]struct{}, len(registry.Sources))
	for _, source := range registry.Sources {
		sources[source.ID] = struct{}{}
	}
	previous := ""
	for _, candidate := range candidates {
		if candidate.ID <= previous || !idPattern.MatchString(candidate.ID) ||
			!allowedCandidateStates[candidate.State] {
			return errors.New("evidence_candidates")
		}
		previous = candidate.ID
		if err := validateCanonicalLocation(candidate.CanonicalLocation); err != nil {
			return err
		}
		if candidate.Revision != "" && !revisionPattern.MatchString(candidate.Revision) {
			return errors.New("evidence_candidate_revision")
		}
		if candidate.TreeSHA != "" &&
			!revisionPattern.MatchString(candidate.TreeSHA) &&
			!digestPattern.MatchString(candidate.TreeSHA) {
			return errors.New("evidence_candidate_tree")
		}
		for _, digest := range []string{
			candidate.SourceSHA256, candidate.InventorySHA256,
			candidate.BuildSHA256, candidate.DependencySHA256,
		} {
			if digest != "" && !digestPattern.MatchString(digest) {
				return errors.New("evidence_candidate_digest")
			}
		}
		if candidate.Reason == "" || !idPattern.MatchString(candidate.Reason) {
			return errors.New("evidence_candidate_reason")
		}
		if candidate.License != "" && !licensePattern.MatchString(candidate.License) {
			return errors.New("evidence_candidate_license")
		}
		if len(candidate.Operations) > 32 || !slices.IsSorted(candidate.Operations) ||
			hasDuplicate(candidate.Operations) {
			return errors.New("evidence_candidate_operations")
		}
		if len(candidate.EvidenceSources) == 0 || len(candidate.EvidenceSources) > 16 ||
			!slices.IsSorted(candidate.EvidenceSources) || hasDuplicate(candidate.EvidenceSources) {
			return errors.New("evidence_candidate_sources")
		}
		for _, source := range candidate.EvidenceSources {
			if _, exists := sources[source]; !exists {
				return errors.New("evidence_candidate_sources")
			}
		}
		if strings.HasPrefix(candidate.State, "eligible_") &&
			(candidate.Revision == "" || candidate.SourceSHA256 == "" || candidate.License == "" ||
				len(candidate.Operations) == 0) {
			return errors.New("evidence_candidate_eligibility")
		}
		if candidate.State == "eligible_runnable" && candidate.BuildSHA256 == "" {
			return errors.New("evidence_candidate_eligibility")
		}
	}
	return nil
}

// validateCanonicalLocation accepts only reviewed source authorities without secrets.
func validateCanonicalLocation(location string) error {
	source := DiscoverySource{URL: location, Query: "canonical"}
	if err := validateSourceURL(source); err != nil {
		return errors.New("evidence_candidate_location")
	}
	return nil
}

// hasEligibleCandidate reports whether the inventory contains an eligible peer.
func hasEligibleCandidate(candidates []Candidate) bool {
	for _, candidate := range candidates {
		if candidate.State == "eligible_runnable" || candidate.State == "eligible_vectors_only" {
			return true
		}
	}
	return false
}

// isClaimClass recognizes the exact public claim taxonomy.
func isClaimClass(value string) bool {
	switch value {
	case "draft_normative", "rfc_normative", "documented_interpretation",
		"local_security_policy", "openapi_contract", "adapter_contract",
		"external_observation", "release_policy":
		return true
	default:
		return false
	}
}

// hasDuplicate reports adjacent duplicates in one sorted string list.
func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

// stringSet constructs one immutable membership map.
func stringSet(values ...string) map[string]bool {
	sort.Strings(values)
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
