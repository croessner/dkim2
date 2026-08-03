package domainadmin

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/provider"
	"gopkg.in/yaml.v3"
)

const intentVersion = "dkim2-domain-intent-v1"

// Intent is one immutable-by-construction canonical operator intent.
type Intent struct {
	version       string
	domain        string
	tenantID      string
	profileUse    provider.ProfileUse
	algorithms    []provider.Algorithm
	rollout       provider.Rollout
	compatibility provider.Compatibility
}

type intentDocument struct {
	Version       string   `yaml:"version"`
	Domain        string   `yaml:"domain"`
	TenantID      string   `yaml:"tenant_id"`
	ProfileUse    string   `yaml:"profile_use"`
	Algorithms    []string `yaml:"algorithms"`
	Rollout       string   `yaml:"rollout"`
	Compatibility string   `yaml:"compatibility"`
}

// LoadIntent reads and validates one protected closed YAML document.
func LoadIntent(path string) (Intent, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Intent{}, newError(CodeProtectedInput)
	}
	document, err := config.ReadProtectedDocument(path, int(DefaultLimits().MaxDocumentBytes))
	if err != nil {
		return Intent{}, newError(CodeProtectedInput)
	}
	defer clear(document)
	if validateIntentYAML(document) != nil {
		return Intent{}, newError(CodeInvalidIntent)
	}
	var decoded intentDocument
	decoder := yaml.NewDecoder(bytes.NewReader(document))
	decoder.KnownFields(true)
	if decoder.Decode(&decoded) != nil {
		return Intent{}, newError(CodeInvalidIntent)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return Intent{}, newError(CodeInvalidIntent)
	}
	return newIntent(decoded)
}

// newIntent validates every value through authoritative datasource owners.
func newIntent(document intentDocument) (Intent, error) {
	if document.Version != intentVersion || len(document.Algorithms) == 0 || len(document.Algorithms) > 2 {
		return Intent{}, newError(CodeInvalidIntent)
	}
	use, err := provider.ParseProfileUse(document.ProfileUse)
	if err != nil || use != provider.ProfileUseOriginator {
		return Intent{}, newError(CodeInvalidIntent)
	}
	rollout, err := provider.ParseRollout(document.Rollout)
	if err != nil || rollout != provider.RolloutEnforce {
		return Intent{}, newError(CodeInvalidIntent)
	}
	compatibility, err := provider.ParseCompatibility(document.Compatibility)
	if err != nil || compatibility != provider.CompatibilityStrict {
		return Intent{}, newError(CodeInvalidIntent)
	}
	algorithms := make([]provider.Algorithm, 0, len(document.Algorithms))
	for _, value := range document.Algorithms {
		algorithm := provider.Algorithm(value)
		if algorithm != provider.AlgorithmRSASHA256 && algorithm != provider.AlgorithmEd25519SHA256 {
			return Intent{}, newError(CodeInvalidIntent)
		}
		if slices.Contains(algorithms, algorithm) {
			return Intent{}, newError(CodeInvalidIntent)
		}
		algorithms = append(algorithms, algorithm)
	}
	slices.SortFunc(algorithms, func(left, right provider.Algorithm) int { return bytes.Compare([]byte(left), []byte(right)) })
	for _, algorithm := range algorithms {
		if provider.ValidateDomainSelector(document.Domain, "onboarding", algorithm) != nil {
			return Intent{}, newError(CodeInvalidIntent)
		}
	}
	if _, err := provider.NewPolicy(document.TenantID, document.Domain, use, "onboarding-profile",
		provider.RecordStatusActive, rollout, compatibility, "", provider.DefaultLimits()); err != nil {
		return Intent{}, newError(CodeInvalidIntent)
	}
	return Intent{version: document.Version, domain: document.Domain, tenantID: document.TenantID,
		profileUse: use, algorithms: algorithms, rollout: rollout, compatibility: compatibility}, nil
}

// validateIntentYAML rejects aliases, anchors, merge keys, and excessive trees.
func validateIntentYAML(document []byte) error {
	return validateProtectedYAMLTree(document, 128, CodeInvalidIntent)
}

// validateProtectedYAMLTree owns shared alias, depth, node-count, and scalar bounds.
func validateProtectedYAMLTree(document []byte, maximumNodes int, failure ErrorCode) error {
	var root yaml.Node
	if yaml.Unmarshal(document, &root) != nil {
		return newError(failure)
	}
	count := 0
	var walk func(*yaml.Node, int) bool
	walk = func(node *yaml.Node, depth int) bool {
		if node == nil || depth > 16 || count >= maximumNodes || node.Kind == yaml.AliasNode || node.Anchor != "" || node.Value == "<<" || len(node.Value) > 4096 {
			return false
		}
		count++
		for _, child := range node.Content {
			if !walk(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(&root, 0) {
		return newError(failure)
	}
	return nil
}

// Version returns the closed intent schema version.
func (i Intent) Version() string { return i.version }

// Domain returns the canonical signing domain.
func (i Intent) Domain() string { return i.domain }

// TenantID returns the canonical tenant identifier.
func (i Intent) TenantID() string { return i.tenantID }

// ProfileUse returns the exact policy use.
func (i Intent) ProfileUse() provider.ProfileUse { return i.profileUse }

// Algorithms returns the detached canonical algorithm order.
func (i Intent) Algorithms() []provider.Algorithm { return slices.Clone(i.algorithms) }

// Rollout returns the authoritative rollout policy.
func (i Intent) Rollout() provider.Rollout { return i.rollout }

// Compatibility returns the strict compatibility policy.
func (i Intent) Compatibility() provider.Compatibility { return i.compatibility }

// clone detaches the only slice-backed canonical intent field.
func (i Intent) clone() Intent {
	i.algorithms = slices.Clone(i.algorithms)
	return i
}

// document projects the canonical intent into its closed validation shape.
func (i Intent) document() intentDocument {
	algorithms := make([]string, len(i.algorithms))
	for index, algorithm := range i.algorithms {
		algorithms[index] = string(algorithm)
	}
	return intentDocument{
		Version: i.version, Domain: i.domain, TenantID: i.tenantID,
		ProfileUse: i.profileUse.String(), Algorithms: algorithms,
		Rollout: i.rollout.String(), Compatibility: i.compatibility.String(),
	}
}

// equal reports exact canonical intent equality without exposing protected values.
func (i Intent) equal(other Intent) bool {
	return i.version == other.version && i.domain == other.domain && i.tenantID == other.tenantID &&
		i.profileUse == other.profileUse && slices.Equal(i.algorithms, other.algorithms) &&
		i.rollout == other.rollout && i.compatibility == other.compatibility
}

// valid reports whether every retained field is exactly canonical and authoritative.
func (i Intent) valid() bool {
	canonical, err := newIntent(i.document())
	return err == nil && i.equal(canonical)
}

// String returns a constant protected intent summary.
func (Intent) String() string { return redacted }

// GoString returns a constant protected intent representation.
func (Intent) GoString() string { return redacted }

// Format prevents formatting verbs from exposing domain intent.
func (Intent) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic intent serialization.
func (Intent) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
