package config

import (
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// removedDraft06FlagGuidance is the fixed migration sentence for the
// signing-policy keys that requested the Draft-06 donotmodify and donotexplode
// flags. Draft-07 Section 10.10 removed both flags.
const removedDraft06FlagGuidance = "was removed in Draft-07 because the donotmodify and donotexplode flags " +
	"no longer exist and have no effect; delete this setting"

// replayRedisMigrationDocument is the operator guide every removed
// Valkey-provider setting points to.
const replayRedisMigrationDocument = "docs/operator/replay-redis-migration.md"

// removedValkeyGuidance is the fixed migration sentence for the removed
// directly addressed Valkey provider subtree and its attestation keys.
const removedValkeyGuidance = "was removed together with the Valkey replay provider; " +
	"configure replay.backend redis and replay.redis instead as described in " + replayRedisMigrationDocument

// removedRevalidateGuidance is the fixed migration sentence for the removed
// Valkey authority revalidation interval.
const removedRevalidateGuidance = "was removed together with the Valkey authority revalidation; " +
	"the Redis replay store probes health through replay.redis.health instead as described in " +
	replayRedisMigrationDocument

// removedValkeyBackendGuidance is the fixed migration sentence for the
// removed replay.backend value valkey.
const removedValkeyBackendGuidance = "was removed; select replay.backend redis and configure replay.redis " +
	"as described in " + replayRedisMigrationDocument

// removedField is one configuration key or subtree that a revision removed.
// The YAML path and environment variable stay reserved so stale deployments
// fail closed with migration guidance instead of silently losing behavior.
// A subtree entry reserves its YAML path and every key below it, and env is
// then the reserved environment-variable prefix.
type removedField struct {
	path     string
	env      string
	subtree  bool
	guidance string
}

// removedValue is one formerly valid scalar value of a still-declared key.
// Only the exact schema-owned spelling is matched, so the failure never
// echoes an operator-supplied value.
type removedValue struct {
	path     string
	value    string
	guidance string
}

// removedFields returns the closed, ordered set of removed configuration keys.
func removedFields() []removedField {
	return []removedField{
		{path: "signing.policy.originator.donotmodify", env: "DKIM2D_SIGNING_POLICY_ORIGINATOR_DONOTMODIFY", guidance: removedDraft06FlagGuidance},
		{path: "signing.policy.originator.donotexplode", env: "DKIM2D_SIGNING_POLICY_ORIGINATOR_DONOTEXPLODE", guidance: removedDraft06FlagGuidance},
		{path: "signing.policy.ordinary_transit.donotmodify", env: "DKIM2D_SIGNING_POLICY_ORDINARY_TRANSIT_DONOTMODIFY", guidance: removedDraft06FlagGuidance},
		{path: "signing.policy.ordinary_transit.donotexplode", env: "DKIM2D_SIGNING_POLICY_ORDINARY_TRANSIT_DONOTEXPLODE", guidance: removedDraft06FlagGuidance},
		{path: "signing.policy.delivery_status.donotmodify", env: "DKIM2D_SIGNING_POLICY_DELIVERY_STATUS_DONOTMODIFY", guidance: removedDraft06FlagGuidance},
		{path: "signing.policy.delivery_status.donotexplode", env: "DKIM2D_SIGNING_POLICY_DELIVERY_STATUS_DONOTEXPLODE", guidance: removedDraft06FlagGuidance},
		{path: "replay.valkey", env: "DKIM2D_REPLAY_VALKEY_", subtree: true, guidance: removedValkeyGuidance},
		{path: "replay.revalidate_interval", env: "DKIM2D_REPLAY_REVALIDATE_INTERVAL", guidance: removedRevalidateGuidance},
	}
}

// removedValues returns the closed set of removed values of declared keys.
func removedValues() []removedValue {
	return []removedValue{
		{path: pathReplayBackend, value: "valkey", guidance: removedValkeyBackendGuidance},
	}
}

// matchesPath reports whether one YAML path is the removed key or, for a
// removed subtree, the subtree root or any key below it.
func (f removedField) matchesPath(path string) bool {
	return f.path == path || f.subtree && strings.HasPrefix(path, f.path+".")
}

// environmentName returns the schema-owned environment spelling named in a
// removed-key failure; a subtree is named by its reserved prefix pattern.
func (f removedField) environmentName() string {
	if f.subtree {
		return f.env + "*"
	}
	return f.env
}

// presentInEnvironment reports whether the removed key's variable, or any
// variable below a removed subtree prefix, is present in the given process
// environment. Values are never inspected.
func (f removedField) presentInEnvironment(environment []string) bool {
	if !f.subtree {
		_, present := os.LookupEnv(f.env)
		return present
	}
	return slices.ContainsFunc(environment, func(entry string) bool {
		name, _, _ := strings.Cut(entry, "=")
		return strings.HasPrefix(name, f.env)
	})
}

// removedYAMLKey reports the removed key declared by one YAML mapping entry
// that the stable schema does not know. It descends only through mappings on
// the way to a removed key; depth and size were already bounded by the
// preflight walk.
func removedYAMLKey(path string, node *yaml.Node) (removedField, bool) {
	leadsToRemoved := false
	for _, field := range removedFields() {
		if field.matchesPath(path) {
			return field, true
		}
		leadsToRemoved = leadsToRemoved || strings.HasPrefix(field.path, path+".")
	}
	if !leadsToRemoved || node == nil || node.Kind != yaml.MappingNode {
		return removedField{}, false
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
	return removedField{}, false
}

// newRemovedYAMLKeyError constructs the removed-key failure for a YAML path.
// The error names only the schema-owned key, never the configured value.
func newRemovedYAMLKeyError(field removedField) error {
	return newRemovedFieldError("configuration key " + field.path + " " + field.guidance)
}

// rejectRemovedEnvironment fails closed when any removed key's environment
// variable is present, regardless of its value. The error names only the
// schema-owned variable or prefix, never the configured value.
func rejectRemovedEnvironment() error {
	environment := os.Environ()
	for _, field := range removedFields() {
		if field.presentInEnvironment(environment) {
			return newRemovedFieldError("environment variable " + field.environmentName() + " " + field.guidance)
		}
	}
	return nil
}

// rejectRemovedValue fails closed when the winning value of a declared key is
// a removed schema-owned spelling, whatever source supplied it. The error
// names only the schema-owned path and removed spelling.
func rejectRemovedValue(path, value string) error {
	for _, removed := range removedValues() {
		if removed.path == path && removed.value == value {
			return newRemovedFieldError("configuration value " + removed.value + " of " + removed.path +
				" " + removed.guidance)
		}
	}
	return nil
}
