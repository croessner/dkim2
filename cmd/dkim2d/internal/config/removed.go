package config

import (
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// removedDraft06FlagGuidance is the fixed migration sentence for the
// signing-policy keys that requested the Draft-06 donotmodify and donotexplode
// flags. Draft-07 Section 10.10 removed both flags.
const removedDraft06FlagGuidance = "was removed in Draft-07 because the donotmodify and donotexplode flags " +
	"no longer exist and have no effect; delete this setting"

// removedField is one configuration key that a protocol revision removed. The
// YAML path and environment variable stay reserved so stale deployments fail
// closed with migration guidance instead of silently losing behavior.
type removedField struct {
	path string
	env  string
}

// removedFields returns the closed, ordered set of removed configuration keys.
func removedFields() []removedField {
	return []removedField{
		{path: "signing.policy.originator.donotmodify", env: "DKIM2D_SIGNING_POLICY_ORIGINATOR_DONOTMODIFY"},
		{path: "signing.policy.originator.donotexplode", env: "DKIM2D_SIGNING_POLICY_ORIGINATOR_DONOTEXPLODE"},
		{path: "signing.policy.ordinary_transit.donotmodify", env: "DKIM2D_SIGNING_POLICY_ORDINARY_TRANSIT_DONOTMODIFY"},
		{path: "signing.policy.ordinary_transit.donotexplode", env: "DKIM2D_SIGNING_POLICY_ORDINARY_TRANSIT_DONOTEXPLODE"},
		{path: "signing.policy.delivery_status.donotmodify", env: "DKIM2D_SIGNING_POLICY_DELIVERY_STATUS_DONOTMODIFY"},
		{path: "signing.policy.delivery_status.donotexplode", env: "DKIM2D_SIGNING_POLICY_DELIVERY_STATUS_DONOTEXPLODE"},
	}
}

// removedYAMLKey reports the removed key declared by one YAML mapping entry
// that the stable schema does not know. It descends only through mappings on
// the way to a removed key; depth and size were already bounded by the
// preflight walk.
func removedYAMLKey(path string, node *yaml.Node) (string, bool) {
	leadsToRemoved := false
	for _, field := range removedFields() {
		if field.path == path {
			return field.path, true
		}
		leadsToRemoved = leadsToRemoved || strings.HasPrefix(field.path, path+".")
	}
	if !leadsToRemoved || node == nil || node.Kind != yaml.MappingNode {
		return "", false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		if removed, ok := removedYAMLKey(path+"."+key.Value, node.Content[index+1]); ok {
			return removed, true
		}
	}
	return "", false
}

// newRemovedYAMLKeyError constructs the removed-key failure for a YAML path.
// The error names only the schema-owned key, never the configured value.
func newRemovedYAMLKeyError(path string) error {
	return newRemovedFieldError("configuration key " + path + " " + removedDraft06FlagGuidance)
}

// rejectRemovedEnvironment fails closed when any removed key's environment
// variable is present, regardless of its value. The error names only the
// schema-owned variable, never the configured value.
func rejectRemovedEnvironment() error {
	for _, field := range removedFields() {
		if _, present := os.LookupEnv(field.env); present {
			return newRemovedFieldError("environment variable " + field.env + " " + removedDraft06FlagGuidance)
		}
	}
	return nil
}
