// Package config owns the strict, redacted Exim adapter configuration boundary.
//
//nolint:goconst,staticcheck // Schema literals and explicit predicates are security-review anchors.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

const (
	// Version is the only accepted stable configuration version.
	Version  = "dkim2-exim-config-v1"
	maxBytes = 256 << 10
	redacted = "dkim2_exim_config{redacted}"
)

// Error is one content-free configuration failure.
type Error struct{}

// Error returns a secret-safe diagnostic.
func (*Error) Error() string { return "dkim2-exim configuration failure" }

// Is recognizes a bounded configuration failure.
func (*Error) Is(target error) bool { _, ok := target.(*Error); return ok }

// Operation chooses the configuration authority used by one adapter entrypoint.
type Operation string

const (
	// OperationInbound selects the long-lived local-scan service.
	OperationInbound Operation = "inbound"
	// OperationSign selects the one-shot originator signing filter.
	OperationSign Operation = "sign"
	// OperationRevise selects the one-shot revision filter.
	OperationRevise Operation = "revise"
)

// FailureMode controls the explicit reached-service inbound failure policy.
type FailureMode string

const (
	// FailureTempfail keeps the secure default.
	FailureTempfail FailureMode = "tempfail"
	// FailureOpen permits only the separately enforced narrow adapter allowlist.
	FailureOpen FailureMode = "fail_open"
)

// Snapshot is one immutable, intentionally opaque validated configuration.
type Snapshot struct{ state *state }

// state retains validated values and is never serialized or formatted directly.
type state struct {
	operation Operation
	identity  securefile.Identity
	inbound   inbound
	daemon    daemon
	signing   signing
	evidence  evidence
	limits    limits
	logging   logging
	metrics   string
}

type inbound struct {
	socket      string
	mode        os.FileMode
	peerUID     uint32
	buildIDs    []string
	timeout     time.Duration
	connections int
	inFlight    int
	buffered    int64
	authEnabled bool
	authservID  string
	failure     FailureMode
}

type daemon struct {
	endpoint          string
	processCapability string
	signCapability    string
	reviseCapability  string
	timeout           time.Duration
}

type signing struct{ tenant, domain string }

type evidence struct {
	enabled              bool
	root, key, readiness string
	retention            time.Duration
	maxRecords           int
	maxBytes             int64
}

type limits struct {
	message, headers int64
	headerCount      int
	fieldBytes       int64
	recipients       int
}

type logging struct{ level, destination string }

// Effective is the safe operator view of a Snapshot.
type Effective struct {
	Version            string `json:"version"`
	InboundSocketMode  string `json:"inbound_socket_mode"`
	InboundTimeout     string `json:"inbound_request_timeout"`
	MaxConnections     int    `json:"inbound_max_connections"`
	MaxInFlight        int    `json:"inbound_max_in_flight_messages"`
	MaxBufferedBytes   int64  `json:"inbound_max_buffered_bytes"`
	DaemonTimeout      string `json:"daemon_request_timeout"`
	EvidenceEnabled    bool   `json:"evidence_enabled"`
	LoggingLevel       string `json:"logging_level"`
	LoggingDestination string `json:"logging_destination"`
	MetricsEnabled     bool   `json:"metrics_enabled"`
}

// Load reads exactly one strict YAML configuration document from an absolute path.
func Load(path string) (Snapshot, error) {
	return LoadForOperation(path, OperationInbound)
}

// LoadForOperation reads the minimal strict configuration for one adapter entrypoint.
func LoadForOperation(path string, operation Operation) (Snapshot, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Snapshot{}, &Error{}
	}
	data, identity, err := securefile.Read(path, 1, maxBytes)
	if err != nil {
		return Snapshot{}, &Error{}
	}
	defer clear(data)
	snapshot, err := decodeForOperation(data, operation)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.state.identity = identity
	return snapshot, nil
}

// Decode parses a bounded YAML document for test and descriptor-owner callers.
func Decode(data []byte) (Snapshot, error) {
	return DecodeForOperation(data, OperationInbound)
}

// DecodeForOperation parses one minimal operation-owned YAML document.
func DecodeForOperation(data []byte, operation Operation) (Snapshot, error) {
	if len(data) == 0 || len(data) > maxBytes {
		return Snapshot{}, &Error{}
	}
	return decodeForOperation(data, operation)
}

// decode runs the strict YAML preflight before Viper records the same source.
func decodeForOperation(data []byte, operation Operation) (Snapshot, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Snapshot{}, &Error{}
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Snapshot{}, &Error{}
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return Snapshot{}, &Error{}
	}
	if err := preflightNode(document.Content[0], 0); err != nil {
		return Snapshot{}, err
	}
	values := make(map[string]raw)
	if err := collect(document.Content[0], "", values); err != nil {
		return Snapshot{}, err
	}
	if err := applyEnvironment(values); err != nil {
		return Snapshot{}, err
	}
	if err := recordViperSource(data, values); err != nil {
		return Snapshot{}, err
	}
	if err := expand(values); err != nil {
		return Snapshot{}, err
	}
	if err := validateYAMLScalarKinds(values); err != nil {
		return Snapshot{}, err
	}
	return validate(values, operation)
}

// recordViperSource preserves the product's standard configuration-source path.
func recordViperSource(data []byte, values map[string]raw) error {
	v := viper.New()
	v.SetConfigType("yaml")
	for path, fallback := range stableDefaults() {
		v.SetDefault(path, fallback)
	}
	for _, path := range stablePaths() {
		name := "DKIM2_EXIM_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
		if err := v.BindEnv(path, name); err != nil {
			return &Error{}
		}
	}
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil || len(v.AllSettings()) == 0 {
		return &Error{}
	}
	for path, item := range values {
		if path == "inbound.allowed_build_ids" {
			if !v.IsSet(path) || item.sourceEnv &&
				v.GetString(path) != strings.ReplaceAll(item.text, "\x00", ",") {
				return &Error{}
			}
			continue
		}
		if !v.IsSet(path) || v.GetString(path) != item.text {
			return &Error{}
		}
	}
	return nil
}

// applyEnvironment merges only declared scalar bindings and rejects ambiguous sources.
func applyEnvironment(values map[string]raw) error {
	aggregate := 0
	for _, path := range stablePaths() {
		name := "DKIM2_EXIM_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
		value, present := os.LookupEnv(name)
		if !present {
			continue
		}
		aggregate += len(value)
		if len(value) > 4096 || aggregate > maxBytes {
			return &Error{}
		}
		if existing, duplicate := values[path]; duplicate && existing.explicit {
			return &Error{}
		}
		if path == "inbound.allowed_build_ids" {
			parts := strings.Split(value, ",")
			if len(parts) < 1 || len(parts) > 16 {
				return &Error{}
			}
			values[path] = raw{text: strings.Join(parts, "\x00"), explicit: true, kind: "!!seq", sourceEnv: true}
			continue
		}
		values[path] = raw{text: value, explicit: true, kind: "!!str", sourceEnv: true}
	}
	return nil
}

// stableDefaults returns the declared Viper default registry.
func stableDefaults() map[string]string {
	return map[string]string{
		"inbound.socket_mode":            "0600",
		"inbound.request_timeout":        "3s",
		"inbound.max_connections":        "128",
		"inbound.max_in_flight_messages": "64",
		"inbound.max_buffered_bytes":     "268435456",
		"daemon.request_timeout":         "2s",
		"authentication_results.enabled": "false",
		"failure.inbound":                "tempfail",
		"evidence.enabled":               "false",
		"evidence.retention":             "14d",
		"evidence.max_records":           "100000",
		"evidence.max_bytes":             "536870912",
		"limits.message_bytes":           "33554432",
		"limits.header_bytes":            "1048576",
		"limits.header_count":            "2000",
		"limits.header_field_bytes":      "65536",
		"limits.recipient_count":         "2000",
		"observability.logging.level":    "info",
	}
}

// stablePaths returns the declared scalar source vocabulary.
func stablePaths() []string {
	return []string{
		"version", "inbound.socket", "inbound.socket_mode", "inbound.peer_uid", "inbound.allowed_build_ids", "inbound.request_timeout", "inbound.max_connections", "inbound.max_in_flight_messages", "inbound.max_buffered_bytes", "daemon.endpoint", "daemon.process_capability_file", "daemon.sign_capability_file", "daemon.revise_capability_file", "daemon.request_timeout", "signing.tenant", "signing.domain", "authentication_results.enabled", "authentication_results.authserv_id", "failure.inbound", "evidence.enabled", "evidence.root", "evidence.key_file", "evidence.readiness_file", "evidence.retention", "evidence.max_records", "evidence.max_bytes", "limits.message_bytes", "limits.header_bytes", "limits.header_count", "limits.header_field_bytes", "limits.recipient_count", "observability.logging.level", "observability.logging.destination", "observability.metrics.endpoint",
	}
}

// raw retains scalar provenance without retaining a parsed mutable tree.
type raw struct {
	text      string
	explicit  bool
	kind      string
	wholeEnv  bool
	sourceEnv bool
}

// preflightNode rejects aliases, excessive nested documents, and non-scalar leaves.
func preflightNode(node *yaml.Node, depth int) error {
	if node == nil || depth > 16 || node.Alias != nil || node.Anchor != "" || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return &Error{}
	}
	if node.Kind == yaml.MappingNode && len(node.Content)%2 != 0 {
		return &Error{}
	}
	if node.Kind == yaml.ScalarNode && (node.Tag == "!!null" || len(node.Value) > 4096) {
		return &Error{}
	}
	for _, child := range node.Content {
		if err := preflightNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// collect admits only the exact stable hierarchy and exact scalar kinds.
func collect(node *yaml.Node, prefix string, values map[string]raw) error {
	if node.Kind != yaml.MappingNode {
		return &Error{}
	}
	seen := make(map[string]struct{})
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "" {
			return &Error{}
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return &Error{}
		}
		seen[key.Value] = struct{}{}
		path := key.Value
		if prefix != "" {
			path = prefix + "." + path
		}
		if isGroup(path) {
			if err := collect(value, path, values); err != nil {
				return err
			}
			continue
		}
		if path == "inbound.allowed_build_ids" {
			if err := collectBuildIDs(value, values); err != nil {
				return err
			}
			continue
		}
		if !isLeaf(path) || value.Kind != yaml.ScalarNode || value.Tag == "!!null" {
			return &Error{}
		}
		if _, exists := values[path]; exists {
			return &Error{}
		}
		values[path] = raw{text: value.Value, explicit: true, kind: value.Tag}
	}
	return nil
}

// collectBuildIDs preserves each list element in a single canonical scalar.
func collectBuildIDs(node *yaml.Node, values map[string]raw) error {
	if node.Kind != yaml.SequenceNode || len(node.Content) < 1 || len(node.Content) > 16 {
		return &Error{}
	}
	parts := make([]string, 0, len(node.Content))
	for _, value := range node.Content {
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "" {
			return &Error{}
		}
		parts = append(parts, value.Value)
	}
	values["inbound.allowed_build_ids"] = raw{text: strings.Join(parts, "\x00"), explicit: true, kind: "!!seq"}
	return nil
}

// validateYAMLScalarKinds rejects quoted type drift before environment expansion.
func validateYAMLScalarKinds(values map[string]raw) error {
	for path, value := range values {
		want := "!!str"
		switch path {
		case "inbound.peer_uid", "inbound.max_connections", "inbound.max_in_flight_messages", "inbound.max_buffered_bytes", "evidence.max_records", "evidence.max_bytes", "limits.message_bytes", "limits.header_bytes", "limits.header_count", "limits.header_field_bytes", "limits.recipient_count":
			want = "!!int"
		case "authentication_results.enabled", "evidence.enabled":
			want = "!!bool"
		case "inbound.allowed_build_ids":
			want = "!!seq"
		}
		if value.kind != want && !((value.wholeEnv || value.sourceEnv) && value.kind == "!!str" && want != "!!seq") {
			return &Error{}
		}
	}
	return nil
}

// isGroup declares the exact non-leaf stable paths.
func isGroup(path string) bool {
	switch path {
	case "inbound", "daemon", "signing", "authentication_results", "failure", "evidence", "limits", "observability", "observability.logging", "observability.metrics":
		return true
	}
	return false
}

// isLeaf declares the sole accepted scalar configuration paths.
func isLeaf(path string) bool {
	switch path {
	case "version", "inbound.socket", "inbound.socket_mode", "inbound.peer_uid", "inbound.request_timeout", "inbound.max_connections", "inbound.max_in_flight_messages", "inbound.max_buffered_bytes", "daemon.endpoint", "daemon.process_capability_file", "daemon.sign_capability_file", "daemon.revise_capability_file", "daemon.request_timeout", "signing.tenant", "signing.domain", "authentication_results.enabled", "authentication_results.authserv_id", "failure.inbound", "evidence.enabled", "evidence.root", "evidence.key_file", "evidence.readiness_file", "evidence.retention", "evidence.max_records", "evidence.max_bytes", "limits.message_bytes", "limits.header_bytes", "limits.header_count", "limits.header_field_bytes", "limits.recipient_count", "observability.logging.level", "observability.logging.destination", "observability.metrics.endpoint":
		return true
	}
	return false
}

// expand replaces only braced scalar environment placeholders before validation.
func expand(values map[string]raw) error {
	aggregate := 0
	for path, value := range values {
		if path == "inbound.allowed_build_ids" {
			parts := strings.Split(value.text, "\x00")
			for index := range parts {
				expanded, err := expandScalar(parts[index])
				if err != nil {
					return err
				}
				parts[index] = expanded
			}
			value.text = strings.Join(parts, "\x00")
			aggregate += len(value.text)
			if aggregate > maxBytes {
				return &Error{}
			}
			values[path] = value
			continue
		}
		original := value.text
		if path == "version" && strings.Contains(original, "${") {
			return &Error{}
		}
		expanded, err := expandScalar(original)
		if err != nil {
			return err
		}
		value.text = expanded
		value.wholeEnv = isWholePlaceholder(original)
		aggregate += len(expanded)
		if len(expanded) > 4096 || aggregate > maxBytes {
			return &Error{}
		}
		values[path] = value
	}
	return nil
}

// isWholePlaceholder reports whether a typed scalar is exactly one substitution.
func isWholePlaceholder(value string) bool {
	return strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") &&
		strings.Count(value, "${") == 1 && strings.Count(value, "}") == 1
}

// expandScalar rejects missing, malformed, or unbounded environment substitutions.
func expandScalar(value string) (string, error) {
	var out strings.Builder
	for len(value) > 0 {
		start := strings.Index(value, "${")
		if start < 0 {
			out.WriteString(value)
			break
		}
		out.WriteString(value[:start])
		value = value[start+2:]
		end := strings.IndexByte(value, '}')
		if end < 1 {
			return "", &Error{}
		}
		name := value[:end]
		for index, character := range name {
			if !(character == '_' || character >= 'A' && character <= 'Z' || index > 0 && character >= '0' && character <= '9') {
				return "", &Error{}
			}
		}
		replacement, present := os.LookupEnv(name)
		if !present {
			return "", &Error{}
		}
		out.WriteString(replacement)
		if out.Len() > 4096 {
			return "", &Error{}
		}
		value = value[end+1:]
	}
	result := out.String()
	if strings.ContainsRune(result, '$') {
		return "", &Error{}
	}
	return result, nil
}

// value returns one explicitly supplied or defaulted scalar.
func value(values map[string]raw, path, fallback string) string {
	if item, ok := values[path]; ok {
		return item.text
	}
	return fallback
}

// present tells conditional validation whether the operator supplied one path.
func present(values map[string]raw, path string) bool { return values[path].explicit }

// validate converts every accepted scalar and applies the exact mode-independent matrix.
func validate(values map[string]raw, operation Operation) (Snapshot, error) { //nolint:gocyclo // One closed-schema validator keeps cross-field invariants atomic.
	if value(values, "version", "") != Version || !present(values, "version") {
		return Snapshot{}, &Error{}
	}
	mode, err := parseMode(value(values, "inbound.socket_mode", "0600"))
	if err != nil {
		return Snapshot{}, err
	}
	uid, err := parseUint(value(values, "inbound.peer_uid", "0"), 0, int64(^uint32(0)))
	if err != nil {
		return Snapshot{}, err
	}
	var buildIDs []string
	if operation == OperationInbound {
		buildIDs, err = parseBuildIDs(value(values, "inbound.allowed_build_ids", ""))
		if err != nil {
			return Snapshot{}, err
		}
	}
	inboundTimeout, err := parseDuration(value(values, "inbound.request_timeout", "3s"), 100*time.Millisecond, 10*time.Second)
	if err != nil {
		return Snapshot{}, err
	}
	connections, err := parseInt(value(values, "inbound.max_connections", "128"), 1, 4096)
	if err != nil {
		return Snapshot{}, err
	}
	inFlight, err := parseInt(value(values, "inbound.max_in_flight_messages", "64"), 1, 1024)
	if err != nil {
		return Snapshot{}, err
	}
	buffered, err := parseInt64(value(values, "inbound.max_buffered_bytes", "268435456"), 1<<20, 1<<30)
	if err != nil {
		return Snapshot{}, err
	}
	daemonTimeout, err := parseDuration(value(values, "daemon.request_timeout", "2s"), 100*time.Millisecond, 10*time.Second)
	if err != nil {
		return Snapshot{}, err
	}
	authEnabled, err := parseBool(value(values, "authentication_results.enabled", "false"))
	if err != nil {
		return Snapshot{}, err
	}
	retention, err := parseDuration(value(values, "evidence.retention", "14d"), time.Hour, 14*24*time.Hour)
	if err != nil {
		return Snapshot{}, err
	}
	maxRecords, err := parseInt(value(values, "evidence.max_records", "100000"), 1, 1000000)
	if err != nil {
		return Snapshot{}, err
	}
	evidenceBytes, err := parseInt64(value(values, "evidence.max_bytes", "536870912"), 1<<20, 1<<30)
	if err != nil {
		return Snapshot{}, err
	}
	message, err := parseInt64(value(values, "limits.message_bytes", "33554432"), 1, 33554432)
	if err != nil {
		return Snapshot{}, err
	}
	headers, err := parseInt64(value(values, "limits.header_bytes", "1048576"), 1, 1048576)
	if err != nil {
		return Snapshot{}, err
	}
	headerCount, err := parseInt(value(values, "limits.header_count", "2000"), 1, 2000)
	if err != nil {
		return Snapshot{}, err
	}
	field, err := parseInt64(value(values, "limits.header_field_bytes", "65536"), 1, 65536)
	if err != nil {
		return Snapshot{}, err
	}
	recipients, err := parseInt(value(values, "limits.recipient_count", "2000"), 1, 2000)
	if err != nil {
		return Snapshot{}, err
	}
	if operation != OperationInbound && !present(values, "limits.recipient_count") {
		recipients = 1
	}
	evidenceEnabled, err := parseBool(value(values, "evidence.enabled", "false"))
	if err != nil {
		return Snapshot{}, err
	}
	failure := FailureMode(value(values, "failure.inbound", "tempfail"))
	endpoint := value(values, "daemon.endpoint", "")
	destination := value(values, "observability.logging.destination", defaultDestination(operation))
	if !validEndpoint(endpoint) || connections < inFlight || operation == OperationInbound && daemonTimeout >= inboundTimeout || !validFailure(failure) || headers > message || field > headers || !validLevel(value(values, "observability.logging.level", "info")) || !validDestination(destination) || !validMetricEndpoint(value(values, "observability.metrics.endpoint", "")) {
		return Snapshot{}, &Error{}
	}
	if minimum, ok := workingSet(message, recipients); !ok || operation == OperationInbound && buffered < minimum {
		return Snapshot{}, &Error{}
	}
	if authEnabled != present(values, "authentication_results.authserv_id") || (authEnabled && !validAuthserv(value(values, "authentication_results.authserv_id", ""))) || (!authEnabled && present(values, "authentication_results.authserv_id")) {
		return Snapshot{}, &Error{}
	}
	if failure == FailureOpen && (!authEnabled || !present(values, "authentication_results.authserv_id")) {
		return Snapshot{}, &Error{}
	}
	if evidenceEnabled != (present(values, "evidence.root") && present(values, "evidence.key_file") && present(values, "evidence.readiness_file")) {
		return Snapshot{}, &Error{}
	}
	if !evidenceEnabled && (present(values, "evidence.root") || present(values, "evidence.key_file") || present(values, "evidence.readiness_file") || present(values, "evidence.retention") || present(values, "evidence.max_records") || present(values, "evidence.max_bytes")) {
		return Snapshot{}, &Error{}
	}
	if evidenceEnabled && (!validAbsolute(value(values, "evidence.root", "")) || !validAbsolute(value(values, "evidence.key_file", "")) || !validAbsolute(value(values, "evidence.readiness_file", ""))) {
		return Snapshot{}, &Error{}
	}
	if err := validateOperation(values, operation, evidenceEnabled, authEnabled, destination, recipients); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{state: &state{operation: operation, inbound: inbound{socket: value(values, "inbound.socket", ""), mode: mode, peerUID: uint32(uid), buildIDs: buildIDs, timeout: inboundTimeout, connections: connections, inFlight: inFlight, buffered: buffered, authEnabled: authEnabled, authservID: value(values, "authentication_results.authserv_id", ""), failure: failure}, daemon: daemon{endpoint: endpoint, processCapability: value(values, "daemon.process_capability_file", ""), signCapability: value(values, "daemon.sign_capability_file", ""), reviseCapability: value(values, "daemon.revise_capability_file", ""), timeout: daemonTimeout}, signing: signing{tenant: value(values, "signing.tenant", ""), domain: value(values, "signing.domain", "")}, evidence: evidence{enabled: evidenceEnabled, root: value(values, "evidence.root", ""), key: value(values, "evidence.key_file", ""), readiness: value(values, "evidence.readiness_file", ""), retention: retention, maxRecords: maxRecords, maxBytes: evidenceBytes}, limits: limits{message: message, headers: headers, headerCount: headerCount, fieldBytes: field, recipients: recipients}, logging: logging{level: value(values, "observability.logging.level", "info"), destination: destination}, metrics: value(values, "observability.metrics.endpoint", "")}}, nil
}

// validateOperation rejects cross-mode authority before protected material can open.
func validateOperation(values map[string]raw, operation Operation, evidenceEnabled, authEnabled bool, destination string, recipients int) error { //nolint:gocyclo // Operation policy is intentionally centralized.
	commonFilterForbidden := present(values, "inbound.socket") || present(values, "inbound.socket_mode") || present(values, "inbound.peer_uid") || present(values, "inbound.allowed_build_ids") || present(values, "inbound.request_timeout") || present(values, "inbound.max_connections") || present(values, "inbound.max_in_flight_messages") || present(values, "inbound.max_buffered_bytes") || present(values, "authentication_results.enabled") || present(values, "authentication_results.authserv_id") || present(values, "failure.inbound") || present(values, "observability.metrics.endpoint")
	switch operation {
	case OperationInbound:
		if !validSocket(value(values, "inbound.socket", "")) || !present(values, "inbound.peer_uid") || !present(values, "inbound.allowed_build_ids") || !validAbsolute(value(values, "daemon.process_capability_file", "")) || present(values, "daemon.sign_capability_file") || present(values, "daemon.revise_capability_file") || present(values, "signing.tenant") || present(values, "signing.domain") || destination != "stderr" {
			return &Error{}
		}
	case OperationSign:
		if commonFilterForbidden || evidenceEnabled || recipients != 1 || !validAbsolute(value(values, "daemon.sign_capability_file", "")) || present(values, "daemon.process_capability_file") || present(values, "daemon.revise_capability_file") || !validTenant(value(values, "signing.tenant", "")) || !validDomain(value(values, "signing.domain", "")) || destination == "stderr" || authEnabled {
			return &Error{}
		}
	case OperationRevise:
		if commonFilterForbidden || !evidenceEnabled || recipients != 1 || !validAbsolute(value(values, "daemon.revise_capability_file", "")) || present(values, "daemon.process_capability_file") || present(values, "daemon.sign_capability_file") || !validTenant(value(values, "signing.tenant", "")) || !validDomain(value(values, "signing.domain", "")) || destination == "stderr" || authEnabled {
			return &Error{}
		}
	default:
		return &Error{}
	}
	return nil
}

// defaultDestination returns the safe mode-specific logging default.
func defaultDestination(operation Operation) string {
	if operation == OperationInbound {
		return "stderr"
	}
	return "none"
}

// ForOperation validates the capability and conditional authorities needed by one entrypoint.
func (s Snapshot) ForOperation(operation Operation) error {
	if s.state == nil || s.state.operation != operation {
		return &Error{}
	}
	return nil
}

// Endpoint returns the validated canonical loopback daemon URL.
func (s Snapshot) Endpoint() string {
	if s.state == nil {
		return ""
	}
	return s.state.daemon.endpoint
}

// DaemonTimeout returns the bounded daemon request timeout.
func (s Snapshot) DaemonTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.daemon.timeout
}

// CapabilityPath returns only the route-scoped capability path selected by operation.
func (s Snapshot) CapabilityPath(operation Operation) string {
	if s.state == nil {
		return ""
	}
	switch operation {
	case OperationInbound:
		return s.state.daemon.processCapability
	case OperationSign:
		return s.state.daemon.signCapability
	case OperationRevise:
		return s.state.daemon.reviseCapability
	}
	return ""
}

// SigningContext returns the validated daemon signing identity.
func (s Snapshot) SigningContext() (string, string) {
	if s.state == nil {
		return "", ""
	}
	return s.state.signing.tenant, s.state.signing.domain
}

// InboundSocket returns the configured local-scan socket path.
func (s Snapshot) InboundSocket() string {
	if s.state == nil {
		return ""
	}
	return s.state.inbound.socket
}

// InboundSocketMode returns the fixed same-UID socket permission.
func (s Snapshot) InboundSocketMode() os.FileMode {
	if s.state == nil {
		return 0
	}
	return s.state.inbound.mode
}

// InboundPeerUID returns the exact allowed Exim peer UID.
func (s Snapshot) InboundPeerUID() uint32 {
	if s.state == nil {
		return 0
	}
	return s.state.inbound.peerUID
}

// AllowedBuildIDs returns a detached generated-build allowlist.
func (s Snapshot) AllowedBuildIDs() []string {
	if s.state == nil {
		return nil
	}
	return append([]string(nil), s.state.inbound.buildIDs...)
}

// InboundTimeout returns the per-connection deadline.
func (s Snapshot) InboundTimeout() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.inbound.timeout
}

// InboundConnections returns the listener connection ceiling.
func (s Snapshot) InboundConnections() int {
	if s.state == nil {
		return 0
	}
	return s.state.inbound.connections
}

// InboundInFlight returns the listener request ceiling.
func (s Snapshot) InboundInFlight() int {
	if s.state == nil {
		return 0
	}
	return s.state.inbound.inFlight
}

// InboundBufferedBytes returns the aggregate byte reservation cap.
func (s Snapshot) InboundBufferedBytes() int64 {
	if s.state == nil {
		return 0
	}
	return s.state.inbound.buffered
}

// InboundReservation returns the validated conservative per-message working-set bound.
func (s Snapshot) InboundReservation() int64 {
	if s.state == nil {
		return 0
	}
	reservation, ok := workingSet(s.state.limits.message, s.state.limits.recipients)
	if !ok {
		return 0
	}
	return reservation
}

// Limits returns all validated message-structure limits.
func (s Snapshot) Limits() (int64, int64, int, int64, int) {
	if s.state == nil {
		return 0, 0, 0, 0, 0
	}
	l := s.state.limits
	return l.message, l.headers, l.headerCount, l.fieldBytes, l.recipients
}

// InboundAuthentication returns the validated Authentication-Results ownership policy.
func (s Snapshot) InboundAuthentication() (bool, string) {
	if s.state == nil {
		return false, ""
	}
	return s.state.inbound.authEnabled, s.state.inbound.authservID
}

// InboundFailure returns the validated reached-service failure policy.
func (s Snapshot) InboundFailure() FailureMode {
	if s.state == nil {
		return FailureTempfail
	}
	return s.state.inbound.failure
}

// Evidence returns the enabled protected evidence state parameters.
func (s Snapshot) Evidence() (bool, string, string, time.Duration, int, int64) {
	if s.state == nil {
		return false, "", "", 0, 0, 0
	}
	e := s.state.evidence
	return e.enabled, e.root, e.key, e.retention, e.maxRecords, e.maxBytes
}

// EvidenceReadinessPath returns the descriptor-confined DXR1 readiness path.
func (s Snapshot) EvidenceReadinessPath() string {
	if s.state == nil {
		return ""
	}
	return s.state.evidence.readiness
}

// Logging returns the selected bounded logging policy.
func (s Snapshot) Logging() (string, string) {
	if s.state == nil {
		return "", ""
	}
	return s.state.logging.level, s.state.logging.destination
}

// MetricsEndpoint returns the optional loopback metrics authority.
func (s Snapshot) MetricsEndpoint() string {
	if s.state == nil {
		return ""
	}
	return s.state.metrics
}

// Effective returns only non-sensitive bounded operator settings.
func (s Snapshot) Effective() Effective {
	if s.state == nil {
		return Effective{}
	}
	in := s.state.inbound
	return Effective{Version: Version, InboundSocketMode: "0600", InboundTimeout: in.timeout.String(), MaxConnections: in.connections, MaxInFlight: in.inFlight, MaxBufferedBytes: in.buffered, DaemonTimeout: s.state.daemon.timeout.String(), EvidenceEnabled: s.state.evidence.enabled, LoggingLevel: s.state.logging.level, LoggingDestination: destinationClass(s.state.logging.destination), MetricsEnabled: s.state.metrics != ""}
}

// ConfigIdentity returns an opaque descriptor token for protected-resource non-aliasing checks.
func (s Snapshot) ConfigIdentity() securefile.Identity {
	if s.state == nil {
		return securefile.Identity{}
	}
	return s.state.identity
}

// String prevents protected configuration disclosure.
func (Snapshot) String() string { return redacted }

// GoString prevents protected configuration disclosure.
func (Snapshot) GoString() string { return redacted }

// Format prevents formatter traversal into protected configuration.
func (Snapshot) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects protected configuration serialization.
func (Snapshot) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects protected configuration serialization.
func (Snapshot) MarshalText() ([]byte, error) { return nil, &Error{} }

// parseMode accepts exactly the octal fixed socket mode.
func parseMode(value string) (os.FileMode, error) {
	if value != "0600" {
		return 0, &Error{}
	}
	return 0o600, nil
}

// parseDuration accepts canonical bounded durations.
func parseDuration(value string, minimum, maximum time.Duration) (time.Duration, error) {
	parsedText := value
	if value == "14d" {
		parsedText = "336h"
	}
	parsed, err := time.ParseDuration(parsedText)
	if err != nil || parsed < minimum || parsed > maximum ||
		(value != "14d" && parsed.String() != value) {
		return 0, &Error{}
	}
	return parsed, nil
}

// parseInt accepts an exact base-ten bounded integer.
func parseInt(value string, minimum, maximum int) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum || strconv.Itoa(parsed) != value {
		return 0, &Error{}
	}
	return parsed, nil
}

// parseInt64 accepts an exact base-ten bounded integer.
func parseInt64(value string, minimum, maximum int64) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum || strconv.FormatInt(parsed, 10) != value {
		return 0, &Error{}
	}
	return parsed, nil
}

// parseUint accepts one canonical non-negative uint32-compatible integer.
func parseUint(value string, minimum, maximum int64) (int64, error) {
	return parseInt64(value, minimum, maximum)
}

// parseBool accepts one canonical boolean.
func parseBool(value string) (bool, error) {
	if value == "true" {
		return true, nil
	}
	if value == "false" {
		return false, nil
	}
	return false, &Error{}
}

// parseBuildIDs accepts 1..16 unique generated 64-hex build identifiers.
func parseBuildIDs(value string) ([]string, error) {
	parts := strings.Split(value, "\x00")
	if len(parts) < 1 || len(parts) > 16 {
		return nil, &Error{}
	}
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if len(part) != 64 {
			return nil, &Error{}
		}
		for _, c := range part {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return nil, &Error{}
			}
		}
		if _, duplicate := seen[part]; duplicate {
			return nil, &Error{}
		}
		seen[part] = struct{}{}
	}
	return parts, nil
}

// validAbsolute accepts only cleaned absolute protected or socket paths.
func validAbsolute(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsRune(value, 0) && filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/"
}

// validSocket accepts one bounded Unix-domain socket pathname.
func validSocket(value string) bool { return validAbsolute(value) && len(value) <= 103 }

// validEndpoint admits canonical literal loopback HTTP endpoint URLs.
func validEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.String() != value || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	portValue, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && portValue > 0 && portValue <= 65535 && strconv.Itoa(portValue) == port && (host == "127.0.0.1" || host == "::1")
}

// validMetricEndpoint admits a loopback host:port listener without a URL scheme.
func validMetricEndpoint(value string) bool {
	if value == "" {
		return true
	}
	host, port, err := net.SplitHostPort(value)
	portValue, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && portValue > 0 && portValue <= 65535 && strconv.Itoa(portValue) == port && (host == "127.0.0.1" || host == "::1")
}

// validLevel accepts the closed slog level vocabulary.
func validLevel(value string) bool {
	return value == "debug" || value == "info" || value == "warn" || value == "error"
}

// validDestination accepts only service stderr or silent/protected filter destinations.
func validDestination(value string) bool {
	return value == "stderr" || value == "none" ||
		strings.HasPrefix(value, "unixgram:") &&
			validSocket(strings.TrimPrefix(value, "unixgram:"))
}

// validFailure accepts the two documented inbound outcomes.
func validFailure(value FailureMode) bool { return value == FailureTempfail || value == FailureOpen }

// validAuthserv accepts one bounded trust-boundary authserv-id.
func validAuthserv(value string) bool { return validDomain(value) }

// validTenant accepts the adapter's closed tenant grammar.
func validTenant(value string) bool {
	if len(value) < 1 || len(value) > 128 || !(value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9') {
		return false
	}
	for _, c := range value {
		if !(c == '-' || c == '_' || c == '.' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// validDomain accepts a canonical ASCII DNS name without a trailing dot.
func validDomain(value string) bool {
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c == '-' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}

// workingSet returns the conservative seven-message-copy reservation.
func workingSet(message int64, recipients int) (int64, bool) {
	const response = int64(7*(4<<20) + 3*(64<<10))
	if message < 1 || recipients < 1 {
		return 0, false
	}
	envelope, ok := checkedMultiply(int64(recipients)+1, 256)
	if !ok {
		return 0, false
	}
	retained, ok := checkedAdd(2*message, envelope)
	if !ok {
		return 0, false
	}
	requestInput, ok := checkedAdd(message, envelope)
	if !ok {
		return 0, false
	}
	request, ok := checkedMultiply(requestInput, 5)
	if !ok {
		return 0, false
	}
	working, ok := checkedAdd(retained, request)
	if !ok {
		return 0, false
	}
	return checkedAdd(working, response)
}

// checkedAdd prevents signed byte-accounting overflow.
func checkedAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > int64(^uint64(0)>>1)-right {
		return 0, false
	}
	return left + right, true
}

// checkedMultiply prevents signed byte-accounting overflow.
func checkedMultiply(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left != 0 && right > int64(^uint64(0)>>1)/left {
		return 0, false
	}
	return left * right, true
}

// destinationClass redacts protected Unix datagram paths from effective configuration.
func destinationClass(value string) string {
	if strings.HasPrefix(value, "unixgram:") {
		return "unixgram"
	}
	return value
}
