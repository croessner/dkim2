package config

import (
	"bytes"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	yamlMaxDocumentBytes = 262_144
	yamlMaxNodeDepth     = 32
	yamlMaxNodes         = 4_096
	yamlMaxScalarBytes   = 65_536
)

type yamlSchemaNode struct {
	children map[string]*yamlSchemaNode
	leaf     bool
}

type yamlWalkState struct {
	seen      map[*yaml.Node]struct{}
	nodes     int
	scalarSum int
}

// preflightYAML parses one bounded YAML document and returns only scalars from
// the exact stable configuration hierarchy.
func preflightYAML(data []byte) (map[string]rawValue, error) {
	if len(data) == 0 || len(data) > yamlMaxDocumentBytes {
		return nil, newError(CodeInvalidYAML)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, newError(CodeInvalidYAML)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, newError(CodeInvalidYAML)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, newError(CodeInvalidYAML)
	}

	walk := &yamlWalkState{seen: make(map[*yaml.Node]struct{})}
	if err := walkYAMLNode(&document, 0, walk); err != nil {
		return nil, err
	}

	root := document.Content[0]
	if root.Kind != yaml.MappingNode || len(root.Content) == 0 {
		return nil, newError(CodeInvalidYAML)
	}
	schema, err := buildYAMLSchema()
	if err != nil {
		return nil, err
	}

	values := make(map[string]rawValue)
	if err := collectYAMLMapping(root, schema, "", values); err != nil {
		return nil, err
	}
	return values, nil
}

// walkYAMLNode enforces graph, node, depth, tag, anchor, null, and scalar byte
// limits before schema-specific traversal.
func walkYAMLNode(node *yaml.Node, depth int, state *yamlWalkState) error {
	if node == nil || depth > yamlMaxNodeDepth {
		return newError(CodeInvalidYAML)
	}
	if _, exists := state.seen[node]; exists {
		return newError(CodeInvalidYAML)
	}
	state.seen[node] = struct{}{}
	state.nodes++
	if state.nodes > yamlMaxNodes {
		return newError(CodeInvalidYAML)
	}

	if node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return newError(CodeInvalidYAML)
	}
	if node.Style&yaml.TaggedStyle != 0 {
		return newError(CodeInvalidYAML)
	}
	if node.Kind == yaml.ScalarNode {
		if node.Tag == "!!null" || len(node.Value) > yamlMaxScalarBytes {
			return newError(CodeInvalidYAML)
		}
		state.scalarSum += len(node.Value)
		if state.scalarSum > yamlMaxDocumentBytes {
			return newError(CodeInvalidYAML)
		}
	}
	if node.Kind == yaml.MappingNode && len(node.Content)%2 != 0 {
		return newError(CodeInvalidYAML)
	}

	for _, child := range node.Content {
		if err := walkYAMLNode(child, depth+1, state); err != nil {
			return err
		}
	}
	return nil
}

// buildYAMLSchema derives the nested YAML hierarchy from the one authoritative
// stable path list without retaining mutable global schema state.
func buildYAMLSchema() (*yamlSchemaNode, error) {
	root := &yamlSchemaNode{children: make(map[string]*yamlSchemaNode)}
	for _, spec := range stableFieldSpecs() {
		parts := strings.Split(spec.path, ".")
		if len(parts) < 2 {
			return nil, newError(CodeInternal)
		}
		current := root
		for index, part := range parts {
			if part == "" {
				return nil, newError(CodeInternal)
			}
			child := current.children[part]
			if child == nil {
				child = &yamlSchemaNode{children: make(map[string]*yamlSchemaNode)}
				current.children[part] = child
			}
			if current.leaf {
				return nil, newError(CodeInternal)
			}
			current = child
			if index == len(parts)-1 {
				if current.leaf || len(current.children) != 0 {
					return nil, newError(CodeInternal)
				}
				current.leaf = true
			}
		}
	}
	return root, nil
}

// collectYAMLMapping validates one declared mapping and flattens its scalar
// leaves while preserving exact YAML scalar kinds.
func collectYAMLMapping(
	node *yaml.Node,
	schema *yamlSchemaNode,
	prefix string,
	values map[string]rawValue,
) error {
	if node.Kind != yaml.MappingNode || len(node.Content) == 0 {
		return newError(CodeInvalidYAML)
	}

	seenKeys := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		valueNode := node.Content[index+1]
		if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
			return newError(CodeInvalidYAML)
		}
		key := keyNode.Value
		if key == "" || strings.ContainsRune(key, '.') {
			return newError(CodeInvalidYAML)
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return newError(CodeInvalidYAML)
		}
		seenKeys[key] = struct{}{}

		child := schema.children[key]
		if child == nil {
			return newError(CodeInvalidYAML)
		}
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		if child.leaf {
			if valueNode.Kind != yaml.ScalarNode {
				return newError(CodeInvalidYAML)
			}
			kind, err := classifyYAMLScalar(valueNode)
			if err != nil {
				return err
			}
			if path == pathConfigVersion {
				if kind != scalarString || valueNode.Value != configVersion ||
					strings.Contains(valueNode.Value, "${") {
					return newError(CodeInvalidYAML)
				}
			}
			if path == pathProtectedGeneration {
				if kind != scalarString || !validGeneration(valueNode.Value) ||
					strings.Contains(valueNode.Value, "${") {
					return newError(CodeInvalidYAML)
				}
			}
			values[path] = rawValue{
				text:   valueNode.Value,
				kind:   kind,
				source: SourceYAML,
			}
			continue
		}

		if valueNode.Kind != yaml.MappingNode || len(valueNode.Content) == 0 {
			return newError(CodeInvalidYAML)
		}
		if err := collectYAMLMapping(valueNode, child, path, values); err != nil {
			return err
		}
	}
	return nil
}

// classifyYAMLScalar preserves the three admitted native scalar classes and
// rejects every YAML coercion outside the typed configuration contract.
func classifyYAMLScalar(node *yaml.Node) (scalarKind, error) {
	switch node.Tag {
	case "!!str":
		return scalarString, nil
	case "!!bool":
		return scalarBool, nil
	case "!!int":
		return scalarUint, nil
	default:
		return 0, newError(CodeInvalidYAML)
	}
}

// validGeneration checks the YAML-only lowercase 128-bit generation spelling.
func validGeneration(value string) bool {
	if len(value) != 32 {
		return false
	}
	for index := range len(value) {
		if (value[index] < '0' || value[index] > '9') &&
			(value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

// expandPlaceholders performs one non-recursive expansion pass over a scalar
// and fails closed on malformed, missing, or oversized substitutions.
func expandPlaceholders(
	value string,
	lookup func(string) (string, bool),
) (string, error) {
	if len(value) > yamlMaxScalarBytes || lookup == nil {
		return "", newError(CodeInvalidPlaceholder)
	}
	first := strings.Index(value, "${")
	if first < 0 {
		return value, nil
	}

	var output strings.Builder
	output.Grow(len(value))
	position := 0
	for first >= 0 {
		start := position + first
		if !writeBoundedPlaceholderPart(&output, value[position:start]) {
			return "", newError(CodeInvalidPlaceholder)
		}
		end, ok := placeholderEnd(value, start)
		if !ok {
			return "", newError(CodeInvalidPlaceholder)
		}
		name := value[start+2 : end-1]
		replacement, present := lookup(name)
		if !present || !writeBoundedPlaceholderPart(&output, replacement) {
			return "", newError(CodeInvalidPlaceholder)
		}
		position = end
		first = strings.Index(value[position:], "${")
	}
	if !writeBoundedPlaceholderPart(&output, value[position:]) {
		return "", newError(CodeInvalidPlaceholder)
	}
	return output.String(), nil
}

// writeBoundedPlaceholderPart appends one already-measured expansion segment
// without letting a scalar exceed its post-expansion byte cap.
func writeBoundedPlaceholderPart(output *strings.Builder, part string) bool {
	if len(part) > yamlMaxScalarBytes-output.Len() {
		return false
	}
	_, _ = output.WriteString(part)
	return true
}

// isWholePlaceholder reports whether a scalar is exactly one valid variable
// reference with no adjacent literal or second placeholder.
func isWholePlaceholder(value string) bool {
	if !strings.HasPrefix(value, "${") {
		return false
	}
	end, ok := placeholderEnd(value, 0)
	return ok && end == len(value)
}

// placeholderEnd validates one placeholder at start and returns the first byte
// after its closing brace.
func placeholderEnd(value string, start int) (int, bool) {
	if start < 0 || start+3 > len(value) || value[start:start+2] != "${" {
		return 0, false
	}
	relativeEnd := strings.IndexByte(value[start+2:], '}')
	if relativeEnd < 0 {
		return 0, false
	}
	end := start + 2 + relativeEnd
	name := value[start+2 : end]
	if !validPlaceholderName(name) {
		return 0, false
	}
	return end + 1, true
}

// validPlaceholderName enforces the exact ASCII environment-variable grammar.
func validPlaceholderName(name string) bool {
	if name == "" || !placeholderNameStart(name[0]) {
		return false
	}
	for index := 1; index < len(name); index++ {
		if !placeholderNameContinue(name[index]) {
			return false
		}
	}
	return true
}

// placeholderNameStart reports whether a byte can start a placeholder name.
func placeholderNameStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

// placeholderNameContinue reports whether a byte can continue a placeholder
// name.
func placeholderNameContinue(value byte) bool {
	return placeholderNameStart(value) || value >= '0' && value <= '9'
}
