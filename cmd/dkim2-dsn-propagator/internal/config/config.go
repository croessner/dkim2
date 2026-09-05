// Package config owns strict typed configuration for the DKIM2 delivery-status
// propagation adapter.
//
// The loader accepts exactly one bounded YAML document under a frozen root
// version, binds only declared environment names, expands scalar placeholders
// before typed validation, and returns one immutable, structurally opaque
// snapshot. No accessor exposes a value that could reach a log, metric, or
// error string by accident.
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

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/endpoint"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

const (
	configVersion          = "dkim2-dsn-propagator-config-v1"
	redacted               = "dkim2_dsn_propagator_config{redacted}"
	environmentPrefix      = "DKIM2_DSN_PROPAGATOR_"
	maxConfigurationBytes  = 262_144
	maxConfigurationNodes  = 4_096
	maxConfigurationDepth  = 32
	maxConfigurationScalar = 65_536
	defaultLogLevel        = "info"
)

// Error is one content-free configuration failure.
type Error struct{}

// Error returns a constant secret-safe diagnostic.
func (*Error) Error() string { return "dkim2-dsn-propagator configuration failure" }

// Is recognizes the bounded configuration error.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}

// PermanentFailureReply is the adapter's only policy knob.
//
// It governs every daemon reject, that is a verification failure and the
// misrouting case not_local. It never affects discard, tempfail, or accept.
type PermanentFailureReply string

const (
	// PermanentFailureReject answers a daemon reject with 550 5.7.1.
	PermanentFailureReject PermanentFailureReply = "reject"
	// PermanentFailureDiscard answers a daemon reject with 250 and drops it.
	PermanentFailureDiscard PermanentFailureReply = "discard"
)

// valueKind records the exact source scalar kind before typed validation.
type valueKind uint8

const (
	valueString valueKind = iota + 1
	valueUint
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
	socketMode     os.FileMode
	shutdown       time.Duration
	maxConnections int
	maxInFlight    int
	requestTimeout time.Duration
	commitTimeout  time.Duration
	pendingLease   time.Duration
	connectTimeout time.Duration
	commandTimeout time.Duration
	dataTimeout    time.Duration
	messageBytes   int64
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
	daemonEndpoint      string
	capabilityFile      string
	requestTimeout      time.Duration
	commitTimeout       time.Duration
	pendingLease        time.Duration
	reinjectionEndpoint string
	connectTimeout      time.Duration
	commandTimeout      time.Duration
	dataTimeout         time.Duration
	tenant              string
	reportingMTA        string
	permanentReply      PermanentFailureReply
	messageBytes        int64
	logLevel            string
	metricsEndpoint     string
}

// Effective is the bounded non-sensitive operator view of a Snapshot.
type Effective struct {
	Version               string `json:"version"`
	SocketMode            string `json:"socket_mode"`
	ShutdownTimeout       string `json:"shutdown_timeout"`
	MaxConnections        int    `json:"max_connections"`
	MaxInFlightMessages   int    `json:"max_in_flight_transactions"`
	RequestTimeout        string `json:"request_timeout"`
	CommitTimeout         string `json:"commit_timeout"`
	PendingLease          string `json:"pending_lease"`
	ConnectTimeout        string `json:"reinjection_connect_timeout"`
	CommandTimeout        string `json:"reinjection_command_timeout"`
	DataTimeout           string `json:"reinjection_data_timeout"`
	PermanentFailureReply string `json:"permanent_failure_reply"`
	MessageBytes          int64  `json:"message_bytes"`
	LogLevel              string `json:"log_level"`
	MetricsEnabled        bool   `json:"metrics_enabled"`
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
		{path: "server.max_in_flight_transactions", kind: valueUint, defaultValue: "64"},
		{path: "daemon.endpoint", kind: valueString},
		{path: "daemon.capability_file", kind: valueString},
		{path: "daemon.request_timeout", kind: valueString, defaultValue: "5s"},
		{path: "daemon.commit_timeout", kind: valueString, defaultValue: "2s"},
		{path: "daemon.pending_lease", kind: valueString, defaultValue: "120s"},
		{path: "reinjection.endpoint", kind: valueString},
		{path: "reinjection.connect_timeout", kind: valueString, defaultValue: "5s"},
		{path: "reinjection.command_timeout", kind: valueString, defaultValue: "5s"},
		{path: "reinjection.data_timeout", kind: valueString, defaultValue: "30s"},
		{path: "propagation.tenant", kind: valueString},
		{path: "propagation.reporting_mta", kind: valueString},
		{
			path: "propagation.permanent_failure_reply", kind: valueString,
			defaultValue: string(PermanentFailureReject),
		},
		{path: "limits.message_bytes", kind: valueUint, defaultValue: "33554432"},
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
		parts := strings.Split(spec.path, ".")
		for index, part := range parts {
			if part == "" || current.leaf {
				return nil, &Error{}
			}
			child := current.children[part]
			if child == nil {
				child = &yamlSchemaNode{children: make(map[string]*yamlSchemaNode)}
				current.children[part] = child
			}
			current = child
			if index == len(parts)-1 {
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

// classifyYAMLScalar accepts exact strings and decimal unsigned integers.
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
	return environmentPrefix + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
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
	parsed, err := parseValues(values)
	if err != nil {
		return Snapshot{}, err
	}
	reply := PermanentFailureReply(text("propagation.permanent_failure_reply"))
	if !validScalarMatrix(values, reply) {
		return Snapshot{}, &Error{}
	}
	return Snapshot{state: &snapshotState{
		socket: text("server.socket"), socketMode: parsed.socketMode,
		shutdownTimeout: parsed.shutdown, maxConnections: parsed.maxConnections,
		maxInFlightMessages: parsed.maxInFlight,
		daemonEndpoint:      text("daemon.endpoint"),
		capabilityFile:      text("daemon.capability_file"),
		requestTimeout:      parsed.requestTimeout, commitTimeout: parsed.commitTimeout,
		pendingLease:        parsed.pendingLease,
		reinjectionEndpoint: text("reinjection.endpoint"),
		connectTimeout:      parsed.connectTimeout, commandTimeout: parsed.commandTimeout,
		dataTimeout: parsed.dataTimeout, tenant: text("propagation.tenant"),
		reportingMTA: text("propagation.reporting_mta"), permanentReply: reply,
		messageBytes:    parsed.messageBytes,
		logLevel:        text("observability.logging.level"),
		metricsEndpoint: text("observability.metrics.endpoint"),
	}}, nil
}

// parseValues converts every non-enum scalar under its stable bounds and proves
// that one complete transaction budget stays inside the daemon lease.
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
		values["daemon.request_timeout"], 100*time.Millisecond, 30*time.Second,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.commitTimeout, err = parseDuration(
		values["daemon.commit_timeout"], 100*time.Millisecond, 30*time.Second,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.pendingLease, err = parseDuration(
		values["daemon.pending_lease"], time.Second, time.Hour,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.connectTimeout, err = parseDuration(
		values["reinjection.connect_timeout"], 100*time.Millisecond, 30*time.Second,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.commandTimeout, err = parseDuration(
		values["reinjection.command_timeout"], 100*time.Millisecond, 30*time.Second,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.dataTimeout, err = parseDuration(
		values["reinjection.data_timeout"], time.Second, 300*time.Second,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.maxConnections, err = parseInt(values["server.max_connections"], 1, 4096); err != nil {
		return parsedValues{}, err
	}
	if parsed.maxInFlight, err = parseInt(
		values["server.max_in_flight_transactions"], 1, 1024,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.messageBytes, err = parseInt64(
		values["limits.message_bytes"], 1024, 33_554_432,
	); err != nil {
		return parsedValues{}, err
	}
	if parsed.maxInFlight > parsed.maxConnections ||
		TransactionBudget(
			parsed.requestTimeout, parsed.connectTimeout, parsed.commandTimeout,
			parsed.dataTimeout, parsed.commitTimeout,
		) >= parsed.pendingLease {
		return parsedValues{}, &Error{}
	}
	return parsed, nil
}

// TransactionBudget sums every bound one propagation transaction may consume.
//
// The daemon serves a retry inside a live lease with tempfail, so a complete
// adapter attempt must finish before the lease expires.
func TransactionBudget(
	request, connect, command, data, commit time.Duration,
) time.Duration {
	return request + connect + command + data + commit
}

// validScalarMatrix validates enums, paths, authorities, and identity fields.
func validScalarMatrix(values map[string]rawValue, reply PermanentFailureReply) bool {
	text := func(path string) string { return values[path].text }
	metrics := text("observability.metrics.endpoint")
	return text("version") == configVersion &&
		(reply == PermanentFailureReject || reply == PermanentFailureDiscard) &&
		validSocketPath(text("server.socket")) &&
		endpoint.IsCanonicalLoopbackHTTPURL(text("daemon.endpoint")) &&
		endpoint.IsCanonicalLoopbackSMTPURL(text("reinjection.endpoint")) &&
		validAbsolutePath(text("daemon.capability_file")) &&
		text("daemon.capability_file") != text("server.socket") &&
		values["propagation.tenant"].explicit && validTenant(text("propagation.tenant")) &&
		values["propagation.reporting_mta"].explicit &&
		validDomain(text("propagation.reporting_mta")) &&
		validLogLevel(text("observability.logging.level")) &&
		(metrics == "" || endpoint.IsCanonicalLoopbackAuthority(metrics))
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
	if len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!identifierEdge(label[0]) || !identifierEdge(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !identifierEdge(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

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

// MaxInFlightTransactions returns the process transaction limit.
func (s Snapshot) MaxInFlightTransactions() int {
	if s.state == nil {
		return 0
	}
	return s.state.maxInFlightMessages
}

// DaemonEndpoint returns the validated loopback daemon URL.
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

// RequestTimeout returns the propagation-call deadline.
func (s Snapshot) RequestTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.requestTimeout
}

// CommitTimeout returns the commit-call deadline.
func (s Snapshot) CommitTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.commitTimeout
}

// PendingLease returns the operator-declared daemon reservation lease.
func (s Snapshot) PendingLease() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.pendingLease
}

// ReinjectionEndpoint returns the validated loopback submission URL.
func (s Snapshot) ReinjectionEndpoint() string {
	if s.state == nil {
		return ""
	}
	return s.state.reinjectionEndpoint
}

// ConnectTimeout returns the re-injection dial deadline.
func (s Snapshot) ConnectTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.connectTimeout
}

// CommandTimeout returns the re-injection per-command deadline.
func (s Snapshot) CommandTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.commandTimeout
}

// DataTimeout returns the re-injection DATA-transfer deadline.
func (s Snapshot) DataTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.dataTimeout
}

// Tenant returns the bounded locality tenant.
func (s Snapshot) Tenant() string {
	if s.state == nil {
		return ""
	}
	return s.state.tenant
}

// ReportingMTA returns the canonical reporting MTA name.
func (s Snapshot) ReportingMTA() string {
	if s.state == nil {
		return ""
	}
	return s.state.reportingMTA
}

// PermanentFailureReply returns the sole adapter policy knob.
func (s Snapshot) PermanentFailureReply() PermanentFailureReply {
	if s.state == nil {
		return ""
	}
	return s.state.permanentReply
}

// MessageBytes returns the advertised and enforced message limit.
func (s Snapshot) MessageBytes() int64 {
	if s.state == nil {
		return 0
	}
	return s.state.messageBytes
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
		Version: configVersion, SocketMode: "0660",
		ShutdownTimeout:       s.state.shutdownTimeout.String(),
		MaxConnections:        s.state.maxConnections,
		MaxInFlightMessages:   s.state.maxInFlightMessages,
		RequestTimeout:        s.state.requestTimeout.String(),
		CommitTimeout:         s.state.commitTimeout.String(),
		PendingLease:          s.state.pendingLease.String(),
		ConnectTimeout:        s.state.connectTimeout.String(),
		CommandTimeout:        s.state.commandTimeout.String(),
		DataTimeout:           s.state.dataTimeout.String(),
		PermanentFailureReply: string(s.state.permanentReply),
		MessageBytes:          s.state.messageBytes,
		LogLevel:              s.state.logLevel,
		MetricsEnabled:        s.state.metricsEndpoint != "",
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
