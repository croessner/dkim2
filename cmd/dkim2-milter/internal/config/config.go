// Package config owns strict typed configuration for the DKIM2 Milter.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/endpoint"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/resource"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

const (
	configVersion          = "dkim2-milter-config-v1"
	redacted               = "dkim2_milter_config{redacted}"
	maxConfigurationBytes  = 262_144
	maxConfigurationNodes  = 4_096
	maxConfigurationDepth  = 32
	maxConfigurationScalar = 65_536
	canonicalFalse         = "false"
	defaultLogLevel        = "info"
)

// Error is one content-free configuration failure.
type Error struct{}

// Error returns a constant secret-safe diagnostic.
func (*Error) Error() string { return "dkim2-milter configuration failure" }

// Is recognizes the bounded configuration error.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}

// Mode selects exactly one daemon operation.
type Mode string

const (
	// ModeInbound selects inbound processing.
	ModeInbound Mode = "inbound"
	// ModeOriginator selects originator signing.
	ModeOriginator Mode = "originator"
	// ModeOrdinaryTransit selects ordinary-transit revision.
	ModeOrdinaryTransit Mode = "ordinary_transit"
)

// FailureMode selects the explicit local dependency-failure policy.
type FailureMode string

const (
	// FailureTempfail preserves the secure default.
	FailureTempfail FailureMode = "tempfail"
	// FailureOpen permits only the narrow pre-mutation allowlist.
	FailureOpen FailureMode = "fail_open"
)

// valueKind records the exact source scalar kind before typed validation.
type valueKind uint8

const (
	valueString valueKind = iota + 1
	valueUint
	valueBool
)

// valueSource records the winning source without retaining its name or path.
type valueSource uint8

const (
	sourceYAML valueSource = iota + 1
	sourceEnvironment
	sourceDefault
	sourceExpanded
)

// fieldSpec is one authoritative stable configuration path.
type fieldSpec struct {
	path         string
	kind         valueKind
	defaultValue string
}

// rawValue preserves source text and scalar type through placeholder expansion.
type rawValue struct {
	text     string
	kind     valueKind
	source   valueSource
	explicit bool
}

// yamlSchemaNode is one immutable node in the derived strict YAML hierarchy.
type yamlSchemaNode struct {
	children map[string]*yamlSchemaNode
	leaf     bool
}

// yamlWalkState bounds the preflight parse graph.
type yamlWalkState struct {
	seen      map[*yaml.Node]struct{}
	nodes     int
	scalarSum int
}

// parsedValues contains typed scalar results before cross-field validation.
type parsedValues struct {
	socketMode          os.FileMode
	shutdown            time.Duration
	requestTimeout      time.Duration
	maxConnections      int
	maxInFlight         int
	maxBuffered         int64
	messageBytes        int64
	headerBytes         int64
	headerCount         int
	headerFieldBytes    int
	recipientCount      int
	allowRecipientGroup bool
	authResultsEnabled  bool
}

// Snapshot is one immutable structurally opaque validated configuration.
type Snapshot struct {
	state *snapshotState
}

// snapshotState owns every sensitive scalar behind the opaque public holder.
type snapshotState struct {
	socket              string
	socketMode          os.FileMode
	shutdownTimeout     time.Duration
	maxConnections      int
	maxInFlightMessages int
	maxBufferedBytes    int64
	daemonEndpoint      string
	capabilityFile      string
	requestTimeout      time.Duration
	mode                Mode
	tenant              string
	domain              string
	domainSource        milter.DomainSource
	allowRecipientGroup bool
	authResultsEnabled  bool
	authservID          string
	failureMode         FailureMode
	messageBytes        int64
	headerBytes         int64
	headerCount         int
	headerFieldBytes    int
	recipientCount      int
	logLevel            string
	metricsEndpoint     string
}

// Effective is the bounded non-sensitive operator view of a Snapshot.
type Effective struct {
	Version               string              `json:"version"`
	Mode                  Mode                `json:"mode"`
	FailureMode           FailureMode         `json:"failure_mode"`
	SocketMode            string              `json:"socket_mode"`
	ShutdownTimeout       string              `json:"shutdown_timeout"`
	MaxConnections        int                 `json:"max_connections"`
	MaxInFlightMessages   int                 `json:"max_in_flight_messages"`
	MaxBufferedBytes      int64               `json:"max_buffered_bytes"`
	RequestTimeout        string              `json:"request_timeout"`
	SigningDomainSource   milter.DomainSource `json:"signing_domain_source"`
	AllowRecipientGroup   bool                `json:"allow_recipient_group"`
	AuthenticationResults bool                `json:"authentication_results"`
	MessageBytes          int64               `json:"message_bytes"`
	HeaderBytes           int64               `json:"header_bytes"`
	HeaderCount           int                 `json:"header_count"`
	HeaderFieldBytes      int                 `json:"header_field_bytes"`
	RecipientCount        int                 `json:"recipient_count"`
	LogLevel              string              `json:"log_level"`
	MetricsEnabled        bool                `json:"metrics_enabled"`
}

// Load reads one strict YAML file and validates all stable paths.
func Load(path string) (Snapshot, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Snapshot{}, &Error{}
	}
	data, err := readConfiguration(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer clear(data)
	values, err := preflightYAML(data)
	if err != nil {
		return Snapshot{}, err
	}
	merged, err := mergeViper(data, values)
	if err != nil {
		return Snapshot{}, err
	}
	expanded, err := expandValues(merged)
	if err != nil {
		return Snapshot{}, err
	}
	return validateValues(expanded)
}

// stableFieldSpecs returns the single authoritative stable path registry.
func stableFieldSpecs() []fieldSpec {
	return []fieldSpec{
		{path: "version", kind: valueString},
		{path: "server.socket", kind: valueString},
		{path: "server.socket_mode", kind: valueString, defaultValue: "0660"},
		{path: "server.shutdown_timeout", kind: valueString, defaultValue: "10s"},
		{path: "server.max_connections", kind: valueUint, defaultValue: "128"},
		{path: "server.max_in_flight_messages", kind: valueUint, defaultValue: "64"},
		{path: "server.max_buffered_bytes", kind: valueUint, defaultValue: "268435456"},
		{path: "daemon.endpoint", kind: valueString},
		{path: "daemon.capability_file", kind: valueString},
		{path: "daemon.request_timeout", kind: valueString, defaultValue: "2s"},
		{path: "mode", kind: valueString},
		{path: "signing.tenant", kind: valueString},
		{path: "signing.domain", kind: valueString},
		{
			path: "signing.domain_source", kind: valueString,
			defaultValue: string(milter.DomainSourceStatic),
		},
		{path: "signing.allow_recipient_group", kind: valueBool, defaultValue: canonicalFalse},
		{path: "authentication_results.enabled", kind: valueBool, defaultValue: canonicalFalse},
		{path: "authentication_results.authserv_id", kind: valueString},
		{path: "failure.mode", kind: valueString, defaultValue: "tempfail"},
		{path: "limits.message_bytes", kind: valueUint, defaultValue: "33554432"},
		{path: "limits.header_bytes", kind: valueUint, defaultValue: "1048576"},
		{path: "limits.header_count", kind: valueUint, defaultValue: "2000"},
		{path: "limits.header_field_bytes", kind: valueUint, defaultValue: "65536"},
		{path: "limits.recipient_count", kind: valueUint, defaultValue: "2000"},
		{path: "observability.logging.level", kind: valueString, defaultValue: defaultLogLevel},
		{path: "observability.metrics.endpoint", kind: valueString},
	}
}

// preflightYAML accepts exactly one bounded document with declared scalar paths.
func preflightYAML(data []byte) (map[string]rawValue, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, &Error{}
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, &Error{}
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, &Error{}
	}
	state := &yamlWalkState{seen: make(map[*yaml.Node]struct{})}
	if err := walkYAMLNode(&document, 0, state); err != nil {
		return nil, err
	}
	schema, err := buildYAMLSchema()
	if err != nil {
		return nil, err
	}
	values := make(map[string]rawValue)
	if err := collectYAMLMapping(document.Content[0], schema, "", values); err != nil {
		return nil, err
	}
	return values, nil
}

// walkYAMLNode enforces graph, depth, tag, anchor, and aggregate scalar bounds.
func walkYAMLNode(node *yaml.Node, depth int, state *yamlWalkState) error {
	if node == nil || depth > maxConfigurationDepth {
		return &Error{}
	}
	if _, exists := state.seen[node]; exists {
		return &Error{}
	}
	state.seen[node] = struct{}{}
	state.nodes++
	if state.nodes > maxConfigurationNodes || node.Anchor != "" || node.Alias != nil ||
		node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return &Error{}
	}
	if node.Kind == yaml.ScalarNode {
		if node.Tag == "!!null" || len(node.Value) > maxConfigurationScalar {
			return &Error{}
		}
		state.scalarSum += len(node.Value)
		if state.scalarSum > maxConfigurationBytes {
			return &Error{}
		}
	}
	if node.Kind == yaml.MappingNode && len(node.Content)%2 != 0 {
		return &Error{}
	}
	for _, child := range node.Content {
		if err := walkYAMLNode(child, depth+1, state); err != nil {
			return err
		}
	}
	return nil
}

// buildYAMLSchema derives one hierarchy from the stable path registry.
func buildYAMLSchema() (*yamlSchemaNode, error) {
	root := &yamlSchemaNode{children: make(map[string]*yamlSchemaNode)}
	for _, spec := range stableFieldSpecs() {
		current := root
		for index, part := range strings.Split(spec.path, ".") {
			if part == "" || current.leaf {
				return nil, &Error{}
			}
			child := current.children[part]
			if child == nil {
				child = &yamlSchemaNode{children: make(map[string]*yamlSchemaNode)}
				current.children[part] = child
			}
			current = child
			if index == len(strings.Split(spec.path, "."))-1 {
				if current.leaf || len(current.children) != 0 {
					return nil, &Error{}
				}
				current.leaf = true
			}
		}
	}
	return root, nil
}

// collectYAMLMapping validates one declared mapping and records exact scalar kinds.
func collectYAMLMapping(
	node *yaml.Node,
	schema *yamlSchemaNode,
	prefix string,
	values map[string]rawValue,
) error {
	if node.Kind != yaml.MappingNode || len(node.Content) == 0 {
		return &Error{}
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		keyNode, valueNode := node.Content[index], node.Content[index+1]
		if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" ||
			strings.ContainsRune(keyNode.Value, '.') {
			return &Error{}
		}
		if _, duplicate := seen[keyNode.Value]; duplicate {
			return &Error{}
		}
		seen[keyNode.Value] = struct{}{}
		child := schema.children[keyNode.Value]
		if child == nil {
			return &Error{}
		}
		path := keyNode.Value
		if prefix != "" {
			path = prefix + "." + keyNode.Value
		}
		if child.leaf {
			kind, err := classifyYAMLScalar(valueNode)
			if err != nil {
				return err
			}
			values[path] = rawValue{
				text: valueNode.Value, kind: kind, source: sourceYAML, explicit: true,
			}
			continue
		}
		if err := collectYAMLMapping(valueNode, child, path, values); err != nil {
			return err
		}
	}
	return nil
}

// classifyYAMLScalar accepts exact strings, decimal unsigned integers, and booleans.
func classifyYAMLScalar(node *yaml.Node) (valueKind, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return 0, &Error{}
	}
	switch node.Tag {
	case "!!str":
		return valueString, nil
	case "!!int":
		if !canonicalUint(node.Value) {
			return 0, &Error{}
		}
		return valueUint, nil
	case "!!bool":
		if node.Value != "true" && node.Value != "false" {
			return 0, &Error{}
		}
		return valueBool, nil
	default:
		return 0, &Error{}
	}
}

// mergeViper binds only declared environment names and rejects source conflicts.
func mergeViper(data []byte, yamlValues map[string]rawValue) (map[string]rawValue, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	specs := stableFieldSpecs()
	environmentValues := make(map[string]rawValue)
	environmentBytes := 0
	for _, spec := range specs {
		if spec.defaultValue != "" {
			v.SetDefault(spec.path, spec.defaultValue)
		}
		environment := environmentName(spec.path)
		if err := v.BindEnv(spec.path, environment); err != nil {
			return nil, &Error{}
		}
		text, present := os.LookupEnv(environment)
		if present {
			environmentBytes += len(text)
			if len(text) > maxConfigurationScalar ||
				environmentBytes > maxConfigurationBytes {
				return nil, &Error{}
			}
			if yamlValues[spec.path].explicit {
				return nil, &Error{}
			}
			environmentValues[spec.path] = rawValue{
				text: text, kind: valueString, source: sourceEnvironment, explicit: true,
			}
			v.Set(spec.path, text)
		}
	}
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return nil, &Error{}
	}
	merged := make(map[string]rawValue, len(specs))
	for _, spec := range specs {
		value := yamlValues[spec.path]
		if environmentValue, present := environmentValues[spec.path]; present {
			value = environmentValue
		} else if !value.explicit {
			value = rawValue{text: spec.defaultValue, kind: spec.kind, source: sourceDefault}
		}
		if len(value.text) > maxConfigurationScalar ||
			v.GetString(spec.path) != value.text {
			return nil, &Error{}
		}
		merged[spec.path] = value
	}
	return merged, nil
}

// environmentName returns the sole canonical binding for one stable path.
func environmentName(path string) string {
	return "DKIM2_MILTER_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

// expandValues expands scalar placeholders before typed validation.
func expandValues(values map[string]rawValue) (map[string]rawValue, error) {
	expanded := make(map[string]rawValue, len(values))
	aggregateBytes := 0
	placeholderValues := make(map[string]string)
	missingPlaceholders := make(map[string]struct{})
	lookup := func(name string) (string, bool) {
		if value, present := placeholderValues[name]; present {
			return value, true
		}
		if _, missing := missingPlaceholders[name]; missing {
			return "", false
		}
		value, present := os.LookupEnv(name)
		if !present || len(value) > maxConfigurationScalar {
			missingPlaceholders[name] = struct{}{}
			return "", false
		}
		placeholderValues[name] = value
		return value, true
	}
	for _, spec := range stableFieldSpecs() {
		value, present := values[spec.path]
		if !present {
			return nil, &Error{}
		}
		if spec.path == "version" && strings.Contains(value.text, "${") {
			return nil, &Error{}
		}
		if strings.Contains(value.text, "${") {
			if spec.kind != valueString && !isWholePlaceholder(value.text) {
				return nil, &Error{}
			}
			text, err := expandPlaceholders(value.text, lookup)
			if err != nil || len(text) > maxConfigurationScalar {
				return nil, &Error{}
			}
			value.text = text
			value.kind = valueString
			value.source = sourceExpanded
		}
		aggregateBytes += len(spec.path) + len(value.text)
		if aggregateBytes > maxConfigurationBytes {
			return nil, &Error{}
		}
		expanded[spec.path] = value
	}
	return expanded, nil
}

// isWholePlaceholder reports whether one scalar contains exactly one placeholder.
func isWholePlaceholder(value string) bool {
	return len(value) > 3 && strings.HasPrefix(value, "${") &&
		strings.HasSuffix(value, "}") && !strings.Contains(value[2:len(value)-1], "${")
}

// expandPlaceholders expands only braced environment names and rejects missing values.
func expandPlaceholders(
	value string,
	lookup func(string) (string, bool),
) (string, error) {
	if lookup == nil || len(value) > maxConfigurationScalar {
		return "", &Error{}
	}
	var result strings.Builder
	for len(value) > 0 {
		start := strings.Index(value, "${")
		if start < 0 {
			if strings.ContainsRune(value, '$') {
				return "", &Error{}
			}
			if !writeBoundedPlaceholderPart(&result, value) {
				return "", &Error{}
			}
			break
		}
		if !writeBoundedPlaceholderPart(&result, value[:start]) {
			return "", &Error{}
		}
		value = value[start+2:]
		end := strings.IndexByte(value, '}')
		if end <= 0 {
			return "", &Error{}
		}
		name := value[:end]
		if !validEnvironmentPlaceholder(name) {
			return "", &Error{}
		}
		replacement, present := lookup(name)
		if !present || !writeBoundedPlaceholderPart(&result, replacement) {
			return "", &Error{}
		}
		value = value[end+1:]
	}
	return result.String(), nil
}

// writeBoundedPlaceholderPart caps builder growth before every copied segment.
func writeBoundedPlaceholderPart(result *strings.Builder, value string) bool {
	if result == nil || len(value) > maxConfigurationScalar-result.Len() {
		return false
	}
	_, _ = result.WriteString(value)
	return true
}

// validEnvironmentPlaceholder accepts one portable environment variable name.
func validEnvironmentPlaceholder(value string) bool {
	if value == "" || !placeholderStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !placeholderByte(value[index]) {
			return false
		}
	}
	return true
}

// placeholderStart reports whether one byte may begin a placeholder name.
func placeholderStart(value byte) bool {
	return value >= 'A' && value <= 'Z' || value == '_'
}

// placeholderByte reports whether one byte may continue a placeholder name.
func placeholderByte(value byte) bool {
	return placeholderStart(value) || value >= '0' && value <= '9'
}

// validateValues constructs one immutable snapshot from the strict merged shape.
func validateValues(values map[string]rawValue) (Snapshot, error) {
	text := func(path string) string { return values[path].text }
	mode := Mode(text("mode"))
	failure := FailureMode(text("failure.mode"))
	parsed, err := parseValues(values)
	if err != nil {
		return Snapshot{}, err
	}
	if !validScalarMatrix(values, mode, failure) {
		return Snapshot{}, &Error{}
	}
	if !validConditionalMatrix(
		values, mode, parsed.allowRecipientGroup, parsed.authResultsEnabled,
	) {
		return Snapshot{}, &Error{}
	}
	tenant, domain := text("signing.tenant"), text("signing.domain")
	domainSource := milter.DomainSource(text("signing.domain_source"))
	authservID := text("authentication_results.authserv_id")
	return Snapshot{state: &snapshotState{
		socket: text("server.socket"), socketMode: parsed.socketMode,
		shutdownTimeout: parsed.shutdown, maxConnections: parsed.maxConnections,
		maxInFlightMessages: parsed.maxInFlight, maxBufferedBytes: parsed.maxBuffered,
		daemonEndpoint: text("daemon.endpoint"), capabilityFile: text("daemon.capability_file"),
		requestTimeout: parsed.requestTimeout, mode: mode, tenant: tenant, domain: domain,
		domainSource:        domainSource,
		allowRecipientGroup: parsed.allowRecipientGroup,
		authResultsEnabled:  parsed.authResultsEnabled, authservID: authservID,
		failureMode: failure, messageBytes: parsed.messageBytes,
		headerBytes: parsed.headerBytes, headerCount: parsed.headerCount,
		headerFieldBytes: parsed.headerFieldBytes, recipientCount: parsed.recipientCount,
		logLevel:        text("observability.logging.level"),
		metricsEndpoint: text("observability.metrics.endpoint"),
	}}, nil
}

// parseValues converts every non-enum scalar under its stable bounds.
func parseValues(values map[string]rawValue) (parsedValues, error) {
	var parsed parsedValues
	var err error
	if parsed.socketMode, err = parseSocketMode(values["server.socket_mode"]); err != nil {
		return parsedValues{}, err
	}
	if parsed.shutdown, err = parseDuration(
		values["server.shutdown_timeout"], time.Second, 30*time.Second,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.requestTimeout, err = parseDuration(
		values["daemon.request_timeout"], 100*time.Millisecond, 10*time.Second,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.maxConnections, err = parseInt(values["server.max_connections"], 1, 4096); err != nil {
		return parsedValues{}, err
	}
	if parsed.maxInFlight, err = parseInt(values["server.max_in_flight_messages"], 1, 1024); err != nil {
		return parsedValues{}, err
	}
	if parsed.maxBuffered, err = parseInt64(
		values["server.max_buffered_bytes"],
		resource.MinimumBufferedBytes,
		1<<30,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.messageBytes, err = parseInt64(values["limits.message_bytes"], 1, 33_554_432); err != nil {
		return parsedValues{}, err
	}
	if parsed.headerBytes, err = parseInt64(values["limits.header_bytes"], 1, 1_048_576); err != nil {
		return parsedValues{}, err
	}
	if parsed.headerCount, err = parseInt(values["limits.header_count"], 1, 2000); err != nil {
		return parsedValues{}, err
	}
	if parsed.headerFieldBytes, err = parseInt(values["limits.header_field_bytes"], 1, 65_536); err != nil {
		return parsedValues{}, err
	}
	if parsed.recipientCount, err = parseInt(values["limits.recipient_count"], 1, 2000); err != nil {
		return parsedValues{}, err
	}
	if parsed.allowRecipientGroup, err = parseBool(values["signing.allow_recipient_group"]); err != nil {
		return parsedValues{}, err
	}
	if parsed.authResultsEnabled, err = parseBool(values["authentication_results.enabled"]); err != nil {
		return parsedValues{}, err
	}
	maximumWorkingSet, boundedWorkingSet := resource.MaximumEOMWorkingSetBytes(
		parsed.messageBytes,
		parsed.recipientCount,
	)
	if parsed.maxInFlight > parsed.maxConnections ||
		!boundedWorkingSet || maximumWorkingSet > parsed.maxBuffered ||
		parsed.headerBytes > parsed.messageBytes ||
		int64(parsed.headerFieldBytes) > parsed.headerBytes {
		return parsedValues{}, &Error{}
	}
	return parsed, nil
}

// validScalarMatrix validates enums, paths, authorities, and logging vocabulary.
func validScalarMatrix(values map[string]rawValue, mode Mode, failure FailureMode) bool {
	text := func(path string) string { return values[path].text }
	metrics := text("observability.metrics.endpoint")
	return text("version") == configVersion &&
		(mode == ModeInbound || mode == ModeOriginator || mode == ModeOrdinaryTransit) &&
		(failure == FailureTempfail || failure == FailureOpen) &&
		validSocketPath(text("server.socket")) &&
		validLoopbackURL(text("daemon.endpoint")) &&
		validAbsolutePath(text("daemon.capability_file")) &&
		text("daemon.capability_file") != text("server.socket") &&
		validLogLevel(text("observability.logging.level")) &&
		(metrics == "" || validLoopbackAuthority(metrics))
}

// validConditionalMatrix validates mode-owned identity and reporting fields.
func validConditionalMatrix(
	values map[string]rawValue,
	mode Mode,
	allowRecipientGroup bool,
	authResultsEnabled bool,
) bool {
	tenantValue := values["signing.tenant"]
	domainValue := values["signing.domain"]
	domainSourceValue := values["signing.domain_source"]
	groupValue := values["signing.allow_recipient_group"]
	enabledValue := values["authentication_results.enabled"]
	authservValue := values["authentication_results.authserv_id"]
	tenant, domain, authservID := tenantValue.text, domainValue.text, authservValue.text
	domainSource := milter.DomainSource(domainSourceValue.text)
	signing := mode != ModeInbound
	staticDomain := domainSource == milter.DomainSourceStatic &&
		domainValue.explicit && validDomain(domain)
	envelopeSenderDomain := mode == ModeOriginator &&
		domainSource == milter.DomainSourceEnvelopeSender &&
		domainSourceValue.explicit && !domainValue.explicit && domain == ""
	signingFields := tenantValue.explicit && validTenant(tenant) &&
		(staticDomain || envelopeSenderDomain)
	inboundFields := !tenantValue.explicit && !domainValue.explicit &&
		!domainSourceValue.explicit && !groupValue.explicit &&
		tenant == "" && domain == "" && domainSource == milter.DomainSourceStatic &&
		!allowRecipientGroup
	reportingMode := mode == ModeInbound ||
		(!enabledValue.explicit && !authservValue.explicit && !authResultsEnabled)
	return ((signing && signingFields) || (!signing && inboundFields)) &&
		!allowRecipientGroup &&
		reportingMode &&
		authservValue.explicit == authResultsEnabled &&
		authResultsEnabled == (authservID != "") &&
		(!authResultsEnabled || (authservValue.explicit && validAuthservID(authservID)))
}

// parseSocketMode accepts only the exact documented safe mode.
func parseSocketMode(value rawValue) (os.FileMode, error) {
	if value.kind != valueString || value.text != "0660" {
		return 0, &Error{}
	}
	return 0o660, nil
}

// parseDuration accepts one canonical single-unit bounded duration.
func parseDuration(value rawValue, minimum, maximum time.Duration) (time.Duration, error) {
	if value.kind != valueString || !canonicalDuration(value.text) {
		return 0, &Error{}
	}
	parsed, err := time.ParseDuration(value.text)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, &Error{}
	}
	return parsed, nil
}

// parseInt accepts one canonical bounded machine-sized integer.
func parseInt(value rawValue, minimum, maximum int) (int, error) {
	parsed, err := parseInt64(value, int64(minimum), int64(maximum))
	if err != nil {
		return 0, err
	}
	return int(parsed), nil
}

// parseInt64 accepts one canonical bounded decimal integer.
func parseInt64(value rawValue, minimum, maximum int64) (int64, error) {
	if value.kind != valueUint && value.kind != valueString {
		return 0, &Error{}
	}
	if value.source == sourceYAML && value.kind != valueUint {
		return 0, &Error{}
	}
	if !canonicalUint(value.text) {
		return 0, &Error{}
	}
	parsed, err := strconv.ParseInt(value.text, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, &Error{}
	}
	return parsed, nil
}

// parseBool accepts canonical lowercase booleans from typed YAML or environment text.
func parseBool(value rawValue) (bool, error) {
	if value.kind != valueBool && value.kind != valueString {
		return false, &Error{}
	}
	if value.source == sourceYAML && value.kind != valueBool {
		return false, &Error{}
	}
	switch value.text {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, &Error{}
	}
}

// canonicalUint reports exact unsigned decimal syntax without signs or leading zeroes.
func canonicalUint(value string) bool {
	if value == "0" {
		return true
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

// canonicalDuration accepts one positive decimal with a single supported unit.
func canonicalDuration(value string) bool {
	unitLength := 1
	if strings.HasSuffix(value, "ms") {
		unitLength = 2
	} else if !strings.HasSuffix(value, "s") &&
		!strings.HasSuffix(value, "m") && !strings.HasSuffix(value, "h") {
		return false
	}
	if len(value) <= unitLength {
		return false
	}
	return canonicalUint(value[:len(value)-unitLength])
}

// validSocketPath accepts one absolute non-root Unix-socket path.
func validSocketPath(value string) bool {
	return filepath.IsAbs(value) && value != "/" && filepath.Clean(value) == value &&
		len(value) <= 103 && !strings.ContainsRune(value, 0)
}

// validAbsolutePath accepts one canonical bounded non-root path.
func validAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && value != "/" && filepath.Clean(value) == value &&
		len(value) <= 4096 && !strings.ContainsRune(value, 0)
}

// validLoopbackURL accepts one canonical literal HTTP authority without extras.
func validLoopbackURL(value string) bool {
	return endpoint.IsCanonicalLoopbackHTTPURL(value)
}

// validLoopbackAuthority accepts a canonical literal host-port.
func validLoopbackAuthority(value string) bool {
	return endpoint.IsCanonicalLoopbackAuthority(value)
}

// validTenant accepts the exact bounded signing-profile tenant grammar.
func validTenant(value string) bool {
	if len(value) == 0 || len(value) > 128 || !identifierEdge(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		char := value[index]
		if !identifierEdge(char) && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

// identifierEdge reports whether one byte is a lowercase ASCII letter or digit.
func identifierEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// validDomain accepts one canonical lower-case ASCII DNS name.
func validDomain(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") ||
		strings.ContainsAny(value, " \t\r\n\x00") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") ||
			strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if !domainByte(char) {
				return false
			}
		}
	}
	return true
}

// domainByte reports whether one rune is allowed in the narrow ASCII label grammar.
func domainByte(value rune) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-'
}

// validAuthservID accepts the intentionally narrow RFC 8601 token form.
func validAuthservID(value string) bool { return validDomain(value) }

// validLogLevel accepts the exact central logger vocabulary.
func validLogLevel(value string) bool {
	return value == "debug" || value == "info" || value == "warn" || value == "error"
}

// Version returns the frozen configuration schema version.
func (Snapshot) Version() string { return configVersion }

// Socket returns the validated Unix-socket path.
func (s Snapshot) Socket() string {
	if s.state == nil {
		return ""
	}
	return s.state.socket
}

// SocketMode returns the exact requested socket mode.
func (s Snapshot) SocketMode() os.FileMode {
	if s.state == nil {
		return 0
	}
	return s.state.socketMode
}

// ShutdownTimeout returns the bounded drain budget.
func (s Snapshot) ShutdownTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.shutdownTimeout
}

// MaxConnections returns the process connection limit.
func (s Snapshot) MaxConnections() int {
	if s.state == nil {
		return 0
	}
	return s.state.maxConnections
}

// MaxInFlightMessages returns the process message limit.
func (s Snapshot) MaxInFlightMessages() int {
	if s.state == nil {
		return 0
	}
	return s.state.maxInFlightMessages
}

// MaxBufferedBytes returns the process byte reservation limit.
func (s Snapshot) MaxBufferedBytes() int64 {
	if s.state == nil {
		return 0
	}
	return s.state.maxBufferedBytes
}

// DaemonEndpoint returns the validated loopback URL.
func (s Snapshot) DaemonEndpoint() string {
	if s.state == nil {
		return ""
	}
	return s.state.daemonEndpoint
}

// CapabilityFile returns the protected direct-child path.
func (s Snapshot) CapabilityFile() string {
	if s.state == nil {
		return ""
	}
	return s.state.capabilityFile
}

// RequestTimeout returns the per-operation deadline.
func (s Snapshot) RequestTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.requestTimeout
}

// Mode returns the fixed adapter operation mode.
func (s Snapshot) Mode() Mode {
	if s.state == nil {
		return ""
	}
	return s.state.mode
}

// Tenant returns the bounded signing tenant.
func (s Snapshot) Tenant() string {
	if s.state == nil {
		return ""
	}
	return s.state.tenant
}

// Domain returns the canonical signing domain.
func (s Snapshot) Domain() string {
	if s.state == nil {
		return ""
	}
	return s.state.domain
}

// DomainSource returns the validated originator signing-domain selection policy.
func (s Snapshot) DomainSource() milter.DomainSource {
	if s.state == nil {
		return ""
	}
	return s.state.domainSource
}

// AllowRecipientGroup reports explicit multi-recipient authorization.
func (s Snapshot) AllowRecipientGroup() bool {
	return s.state != nil && s.state.allowRecipientGroup
}

// AuthenticationResultsEnabled reports local reporting policy.
func (s Snapshot) AuthenticationResultsEnabled() bool {
	return s.state != nil && s.state.authResultsEnabled
}

// AuthservID returns the canonical local authentication service identity.
func (s Snapshot) AuthservID() string {
	if s.state == nil {
		return ""
	}
	return s.state.authservID
}

// FailureMode returns the explicit failure policy.
func (s Snapshot) FailureMode() FailureMode {
	if s.state == nil {
		return ""
	}
	return s.state.failureMode
}

// MessageBytes returns the narrowed message limit.
func (s Snapshot) MessageBytes() int64 {
	if s.state == nil {
		return 0
	}
	return s.state.messageBytes
}

// HeaderBytes returns the narrowed aggregate header limit.
func (s Snapshot) HeaderBytes() int64 {
	if s.state == nil {
		return 0
	}
	return s.state.headerBytes
}

// HeaderCount returns the narrowed header-count limit.
func (s Snapshot) HeaderCount() int {
	if s.state == nil {
		return 0
	}
	return s.state.headerCount
}

// HeaderFieldBytes returns the narrowed field limit.
func (s Snapshot) HeaderFieldBytes() int {
	if s.state == nil {
		return 0
	}
	return s.state.headerFieldBytes
}

// RecipientCount returns the narrowed recipient limit.
func (s Snapshot) RecipientCount() int {
	if s.state == nil {
		return 0
	}
	return s.state.recipientCount
}

// LogLevel returns the closed logging level.
func (s Snapshot) LogLevel() string {
	if s.state == nil {
		return ""
	}
	return s.state.logLevel
}

// MetricsEndpoint returns the optional loopback metrics authority.
func (s Snapshot) MetricsEndpoint() string {
	if s.state == nil {
		return ""
	}
	return s.state.metricsEndpoint
}

// Effective returns only bounded non-sensitive operator-visible settings.
func (s Snapshot) Effective() Effective {
	if s.state == nil {
		return Effective{}
	}
	return Effective{
		Version: configVersion, Mode: s.state.mode, FailureMode: s.state.failureMode,
		SocketMode: "0660", ShutdownTimeout: s.state.shutdownTimeout.String(),
		MaxConnections: s.state.maxConnections, MaxInFlightMessages: s.state.maxInFlightMessages,
		MaxBufferedBytes: s.state.maxBufferedBytes, RequestTimeout: s.state.requestTimeout.String(),
		SigningDomainSource:   s.state.domainSource,
		AllowRecipientGroup:   s.state.allowRecipientGroup,
		AuthenticationResults: s.state.authResultsEnabled,
		MessageBytes:          s.state.messageBytes, HeaderBytes: s.state.headerBytes,
		HeaderCount: s.state.headerCount, HeaderFieldBytes: s.state.headerFieldBytes,
		RecipientCount: s.state.recipientCount, LogLevel: s.state.logLevel,
		MetricsEnabled: s.state.metricsEndpoint != "",
	}
}

// String returns a content-free effective configuration.
func (Snapshot) String() string { return redacted }

// GoString returns a content-free Go representation.
func (Snapshot) GoString() string { return redacted }

// Format prevents formatting from traversing protected settings.
func (Snapshot) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects configuration serialization.
func (Snapshot) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects configuration text serialization.
func (Snapshot) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free internal snapshot-state representation.
func (snapshotState) String() string { return redacted }

// GoString returns a content-free internal snapshot-state representation.
func (s snapshotState) GoString() string { return s.String() }

// Format prevents nested formatting from traversing sensitive scalar state.
func (s snapshotState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// MarshalJSON rejects nested configuration-state serialization.
func (snapshotState) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects nested configuration-state text serialization.
func (snapshotState) MarshalText() ([]byte, error) { return nil, &Error{} }

// IsError reports whether err is a bounded config failure.
func IsError(err error) bool { return errors.Is(err, &Error{}) }
