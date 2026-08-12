package config

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestExpandYAMLScalarPlaceholdersFreezesTypedValueOnlyBoundary covers the exported config owner.
func TestExpandYAMLScalarPlaceholdersFreezesTypedValueOnlyBoundary(t *testing.T) {
	t.Setenv("DKIM2_TEST_COUNT", "42")
	t.Setenv("DKIM2_TEST_ITEM", expandedAlpha)
	t.Setenv("DKIM2_TEST_RECURSIVE", "${DKIM2_TEST_MISSING}")
	document := []byte("count: ${DKIM2_TEST_COUNT}\nquoted: \"${DKIM2_TEST_COUNT}\"\nitems:\n  - ${DKIM2_TEST_ITEM}\none_pass: ${DKIM2_TEST_RECURSIVE}\n")
	expanded, err := ExpandYAMLScalarPlaceholders(document)
	if err != nil {
		t.Fatal("expand typed scalar document")
	}
	defer clear(expanded)
	var decoded struct {
		Count   uint64   `yaml:"count"`
		Quoted  string   `yaml:"quoted"`
		Items   []string `yaml:"items"`
		OnePass string   `yaml:"one_pass"`
	}
	if yaml.Unmarshal(expanded, &decoded) != nil || decoded.Count != 42 || decoded.Quoted != "42" ||
		len(decoded.Items) != 1 || decoded.Items[0] != expandedAlpha || decoded.OnePass != "${DKIM2_TEST_MISSING}" {
		t.Fatal("typed, quoted, sequence, or one-pass placeholder semantics drifted")
	}

	t.Setenv("DKIM2_TEST_KEY", "value")
	invalid := map[string]string{
		"missing":      "value: ${DKIM2_TEST_ABSENT}\n",
		"map-key":      "${DKIM2_TEST_KEY}: literal\n",
		"anchor-alias": "value: &shared literal\nother: *shared\n",
		"trailing-doc": "value: literal\n---\nvalue: other\n",
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			if value, expandErr := ExpandYAMLScalarPlaceholders([]byte(input)); expandErr == nil || len(value) != 0 {
				t.Fatal("unsafe exported YAML expansion input was accepted")
			}
		})
	}
}

const (
	recursivePlaceholder = "${A}"
	literalScalar        = "literal"
	emptyPlaceholder     = "${}"
	expandedAlpha        = "alpha"
)

// TestPreflightYAMLAcceptsDeclaredScalars proves the node preflight retains
// exact scalar spelling and native YAML kind for the typed decoder.
func TestPreflightYAMLAcceptsDeclaredScalars(t *testing.T) {
	t.Parallel()

	values, err := preflightYAML([]byte(`
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  listen: "127.0.0.1:8080"
  max_in_flight: 2
replay:
  valkey:
    attestation:
      dedicated_deployment: true
`))
	if err != nil {
		t.Fatalf("preflightYAML() error = %v", err)
	}

	want := map[string]rawValue{
		pathConfigVersion:                  {text: configVersion, kind: scalarString, source: SourceYAML},
		pathProtectedGeneration:            {text: "0123456789abcdef0123456789abcdef", kind: scalarString, source: SourceYAML},
		pathServerListen:                   {text: defaultListenAddress, kind: scalarString, source: SourceYAML},
		pathServerMaxInFlight:              {text: "2", kind: scalarUint, source: SourceYAML},
		pathAttestationDedicatedDeployment: {text: canonicalTrue, kind: scalarBool, source: SourceYAML},
	}
	if len(values) != len(want) {
		t.Fatalf("preflightYAML() returned %d values, want %d", len(values), len(want))
	}
	for path, expected := range want {
		if got := values[path]; got != expected {
			t.Errorf("preflightYAML() scalar class mismatch for declared path %q", path)
		}
	}
}

// TestPreflightYAMLRejectsForbiddenStructures covers node forms that Viper
// could otherwise flatten, coerce, merge, or silently accept.
func TestPreflightYAMLRejectsForbiddenStructures(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty stream":             "",
		"sequence root":            "- config",
		"empty root":               "{}",
		"multiple documents":       "config:\n  version: dkim2d-config-v1\n---\nconfig:\n  version: dkim2d-config-v1\n",
		"duplicate decoded key":    "config:\n  version: dkim2d-config-v1\n  \"version\": dkim2d-config-v1\n",
		"dotted alias":             "config:\n  version: dkim2d-config-v1\nserver.listen: 127.0.0.1:8080\n",
		"case variant":             "Config:\n  version: dkim2d-config-v1\n",
		"unknown empty map":        "config:\n  version: dkim2d-config-v1\nunknown: {}\n",
		"known empty map":          "config: {}\n",
		"anchor":                   "config:\n  version: &version dkim2d-config-v1\n",
		"alias":                    "config:\n  version: &version dkim2d-config-v1\nserver:\n  listen: *version\n",
		"merge key":                "config:\n  version: dkim2d-config-v1\nserver:\n  <<: {listen: 127.0.0.1:8080}\n",
		"explicit standard tag":    "config:\n  version: !!str dkim2d-config-v1\n",
		"custom tag":               "config:\n  version: !version dkim2d-config-v1\n",
		"complex key":              "? [config]\n: value\n",
		"sequence leaf":            "config:\n  version: [dkim2d-config-v1]\n",
		"implicit null":            "config:\n  version:\n",
		"null word":                "config:\n  version: null\n",
		"null tilde":               "config:\n  version: ~\n",
		"unsupported float scalar": "server:\n  max_in_flight: 1.0\n",
		"trailing content":         "config:\n  version: dkim2d-config-v1\n...\nnot-yaml\n",
		"version placeholder":      "config:\n  version: ${VERSION}\n",
		"wrong version":            "config:\n  version: dkim2d-config-v2\n",
		"generation placeholder":   "protected:\n  generation: ${GENERATION}\n",
		"wrong generation":         "protected:\n  generation: ABCDEF0123456789abcdef0123456789\n",
	}

	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := preflightYAML([]byte(document)); CodeOf(err) != CodeInvalidYAML {
				t.Fatalf("preflightYAML() code = %q, want %q", CodeOf(err), CodeInvalidYAML)
			}
		})
	}
}

// TestPreflightYAMLReturnsContentFreeErrors proves parser diagnostics never
// retain or format attacker-controlled configuration bytes.
func TestPreflightYAMLReturnsContentFreeErrors(t *testing.T) {
	t.Parallel()

	const marker = "yaml-secret-marker"
	_, err := preflightYAML([]byte("server: [" + marker))
	if err == nil {
		t.Fatal("preflightYAML() error = nil, want failure")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("preflightYAML() error disclosed input marker: %q", err)
	}
}

// TestPreflightYAMLEnforcesResourceBounds proves byte, scalar, depth, and node
// abuse is rejected before typed configuration allocation.
func TestPreflightYAMLEnforcesResourceBounds(t *testing.T) {
	t.Parallel()

	atScalarLimit := "server:\n  listen: \"" + strings.Repeat("x", yamlMaxScalarBytes) + "\"\n"
	if _, err := preflightYAML([]byte(atScalarLimit)); err != nil {
		t.Fatalf("preflightYAML() at scalar limit error = %v", err)
	}

	overScalarLimit := "server:\n  listen: \"" + strings.Repeat("x", yamlMaxScalarBytes+1) + "\"\n"
	if _, err := preflightYAML([]byte(overScalarLimit)); CodeOf(err) != CodeInvalidYAML {
		t.Fatalf("preflightYAML() over scalar limit code = %q, want %q", CodeOf(err), CodeInvalidYAML)
	}

	overFileLimit := strings.Repeat("#", yamlMaxDocumentBytes+1)
	if _, err := preflightYAML([]byte(overFileLimit)); CodeOf(err) != CodeInvalidYAML {
		t.Fatalf("preflightYAML() over document limit code = %q, want %q", CodeOf(err), CodeInvalidYAML)
	}

	deep := strings.Repeat("- ", yamlMaxNodeDepth+1) + "value\n"
	if _, err := preflightYAML([]byte(deep)); CodeOf(err) != CodeInvalidYAML {
		t.Fatalf("preflightYAML() over depth limit code = %q, want %q", CodeOf(err), CodeInvalidYAML)
	}

	var broad strings.Builder
	broad.WriteString("-\n")
	for range yamlMaxNodes {
		broad.WriteString("  - value\n")
	}
	if _, err := preflightYAML([]byte(broad.String())); CodeOf(err) != CodeInvalidYAML {
		t.Fatalf("preflightYAML() over node limit code = %q, want %q", CodeOf(err), CodeInvalidYAML)
	}
}

// TestExpandPlaceholders proves expansion is exact, one-pass, bounded, and
// distinguishes missing variables from present empty values.
func TestExpandPlaceholders(t *testing.T) {
	t.Parallel()

	environment := map[string]string{
		"A":         expandedAlpha,
		"B_2":       "beta",
		"EMPTY":     "",
		"RECURSIVE": recursivePlaceholder,
		"MAX":       strings.Repeat("x", yamlMaxScalarBytes),
	}
	lookup := func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: literalScalar, input: literalScalar, want: literalScalar},
		{name: "one", input: recursivePlaceholder, want: expandedAlpha},
		{name: "multiple", input: "x-${A}-${B_2}-y", want: "x-alpha-beta-y"},
		{name: "adjacent", input: "${A}${B_2}", want: "alphabeta"},
		{name: "present empty", input: "x${EMPTY}y", want: "xy"},
		{name: "replacement not rescanned", input: "${RECURSIVE}", want: recursivePlaceholder},
		{name: "literal dollars", input: "$A $$", want: "$A $$"},
		{name: "maximum result", input: "${MAX}", want: environment["MAX"]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := expandPlaceholders(test.input, lookup)
			if err != nil {
				t.Fatalf("expandPlaceholders() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("expandPlaceholders() = %q, want %q", got, test.want)
			}
		})
	}

	invalid := []string{
		"${MISSING}",
		emptyPlaceholder,
		"${1NAME}",
		"${A-B}",
		"${A:-fallback}",
		"${A",
		"${A${B_2}}",
		"${Å}",
	}
	for _, input := range invalid {
		t.Run("invalid_"+input, func(t *testing.T) {
			t.Parallel()
			if _, err := expandPlaceholders(input, lookup); CodeOf(err) != CodeInvalidPlaceholder {
				t.Fatalf("expandPlaceholders() code = %q, want %q", CodeOf(err), CodeInvalidPlaceholder)
			}
		})
	}

	if _, err := expandPlaceholders("x${MAX}", lookup); CodeOf(err) != CodeInvalidPlaceholder {
		t.Fatalf("expandPlaceholders() over limit code = %q, want %q", CodeOf(err), CodeInvalidPlaceholder)
	}
}

// TestIsWholePlaceholder distinguishes exact whole-scalar references from
// embedded, malformed, and operator-like syntax.
func TestIsWholePlaceholder(t *testing.T) {
	t.Parallel()

	for _, value := range []string{recursivePlaceholder, "${_}", "${A_2}"} {
		if !isWholePlaceholder(value) {
			t.Errorf("isWholePlaceholder(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "x${A}", "${A}x", emptyPlaceholder, "${A:-x}", "${A}${B}"} {
		if isWholePlaceholder(value) {
			t.Errorf("isWholePlaceholder(%q) = true, want false", value)
		}
	}
}

// FuzzPreflightYAML retains bounded malformed-input coverage for the raw YAML
// node boundary.
func FuzzPreflightYAML(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("config:\n  version: dkim2d-config-v1\n"),
		[]byte("server:\n  max_in_flight: 1\n"),
		[]byte("config: &c\n  version: *c\n"),
		[]byte{0xff, 0xfe, 0xfd},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, document []byte) {
		values, err := preflightYAML(document)
		if err != nil && CodeOf(err) != CodeInvalidYAML {
			t.Fatalf("preflightYAML() returned non-YAML code %q", CodeOf(err))
		}
		if err == nil && len(values) > len(stableFieldSpecs()) {
			t.Fatalf("preflightYAML() returned %d values, schema has %d", len(values), len(stableFieldSpecs()))
		}
	})
}

// FuzzExpandPlaceholders retains one-pass grammar and size coverage without
// consulting process-global environment state.
func FuzzExpandPlaceholders(f *testing.F) {
	for _, seed := range []string{literalScalar, recursivePlaceholder, emptyPlaceholder, "${A}${B}", "${A:-x}"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		expanded, err := expandPlaceholders(value, func(name string) (string, bool) {
			if name == "A" {
				return "${B}", true
			}
			if name == "B" {
				return "", true
			}
			return "", false
		})
		if err != nil && CodeOf(err) != CodeInvalidPlaceholder {
			t.Fatalf("expandPlaceholders() returned non-placeholder code %q", CodeOf(err))
		}
		if err == nil && len(expanded) > yamlMaxScalarBytes {
			t.Fatalf("expandPlaceholders() returned %d bytes", len(expanded))
		}
	})
}
