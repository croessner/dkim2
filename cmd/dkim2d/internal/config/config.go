package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/valkey"
)

const (
	maxScalarBytes    = 65_536
	maxAggregateBytes = 262_144
)

// PolicyMode identifies one daemon-owned result policy.
type PolicyMode uint8

const (
	// PolicyStrict applies the restrictive production policy.
	PolicyStrict PolicyMode = iota + 1
	// PolicyPermissive permits the draft-defined non-strict outcomes.
	PolicyPermissive
	// PolicyTesting enables the bounded testing policy.
	PolicyTesting
)

// ReplayBackend identifies one closed replay-store selection.
type ReplayBackend uint8

const (
	// ReplayValkey selects the directly addressed Valkey provider.
	ReplayValkey ReplayBackend = iota + 1
	// ReplayMemory selects the process-local bounded provider.
	ReplayMemory
	// ReplayDisabled selects the explicit disabled provider.
	ReplayDisabled
)

// SigningBackend identifies one closed daemon signing provider selection.
type SigningBackend uint8

const (
	// SigningDisabled keeps sign and revise services unavailable.
	SigningDisabled SigningBackend = iota + 1
	// SigningFlatFile selects one same-generation signing-profile provider.
	SigningFlatFile
	// SigningLDAP selects one verified read-only LDAP provider.
	SigningLDAP
	// SigningPostgreSQL selects one verified read-only PostgreSQL provider.
	SigningPostgreSQL
	// SigningMySQL selects one verified read-only MySQL or MariaDB provider.
	SigningMySQL
)

type snapshotState struct {
	version       string
	generation    string
	server        serverState
	policy        PolicyMode
	dns           dnsState
	replay        replayState
	signing       signingState
	observability observabilityState
	presence      map[string]Presence
}

// LogLevel identifies one closed slog admission threshold.
type LogLevel uint8

const (
	// LogLevelDebug admits debug and higher records.
	LogLevelDebug LogLevel = iota + 1
	// LogLevelInfo admits informational and higher records.
	LogLevelInfo
	// LogLevelWarn admits warning and error records.
	LogLevelWarn
	// LogLevelError admits only error records.
	LogLevelError
)

// TracingExporter identifies one closed tracing mode.
type TracingExporter uint8

const (
	// TracingNone disables the tracing SDK and exporter.
	TracingNone TracingExporter = iota + 1
	// TracingOTLPHTTP selects bounded OTLP over direct HTTPS with strict TLS.
	TracingOTLPHTTP
)

type observabilityState struct {
	logLevel          LogLevel
	debugMessageShape bool
	debugDNS          bool
	debugReplay       bool
	tracing           tracingState
}

type tracingState struct {
	exporter         TracingExporter
	endpoint         string
	caFile           string
	samplePerMillion uint32
	exportTimeout    time.Duration
}

type serverState struct {
	listen                string
	capabilityFile        string
	signCapabilityFile    string
	reviseCapabilityFile  string
	dsnSignCapabilityFile string
	readHeaderTimeout     time.Duration
	readTimeout           time.Duration
	writeTimeout          time.Duration
	requestDeadline       time.Duration
	shutdownTimeout       time.Duration
	maxInFlight           uint8
	maxWaiters            uint16
	admissionWait         time.Duration
}

type signingState struct {
	backend             SigningBackend
	datasourceFile      string
	privateManifestFile string
	reloadInterval      time.Duration
	allowRecipientGroup bool
	limitProfile        string
	maxLoadBytes        uint32
	ldap                ldapSigningState
	postgresql          sqlSigningState
	mysql               sqlSigningState
}

type ldapSigningState struct {
	address, serverName, caFile, transport, bindDN, passwordFile, baseDN string
	pageSize                                                             uint16
	loadDeadline                                                         time.Duration
}

type sqlSigningState struct {
	address, serverName, caFile, database, user, passwordFile string
	pageSize                                                  uint16
	loadDeadline                                              time.Duration
	maxConnections                                            uint8
	idleConnections                                           uint8
}

type dnsState struct {
	lookupTimeout        time.Duration
	maxConcurrentLookups uint16
}

type replayState struct {
	backend             ReplayBackend
	hmacKeyFile         string
	epoch               uint32
	retention           time.Duration
	maxEntries          uint32
	maxWaiters          uint32
	pruneBudget         uint32
	maxInFlight         uint32
	maxAdmissionWaiters uint32
	revalidateInterval  time.Duration
	valkey              valkeyState
	operatorAttestation valkey.OperatorAttestation
	hasReplayConfig     bool
	hasValkeyConfig     bool
}

type valkeyState struct {
	address                 string
	serverName              string
	caFile                  string
	applicationUsername     string
	applicationPasswordFile string
	auditorUsername         string
	auditorPasswordFile     string
	dialTimeout             time.Duration
	tcpKeepalive            time.Duration
	connectionWriteTimeout  time.Duration
}

// Load validates one already-owned YAML document and returns an immutable snapshot.
func Load(data []byte, flags FlagValues) (Snapshot, error) {
	if len(data) == 0 || len(data) > yamlMaxDocumentBytes {
		return Snapshot{}, newError(CodeInvalidYAML)
	}
	ownedData := bytes.Clone(data)
	yamlValues, err := preflightYAML(ownedData)
	if err != nil {
		return Snapshot{}, err
	}
	merged, presence, err := mergeValues(ownedData, yamlValues, flags)
	if err != nil {
		return Snapshot{}, err
	}
	expanded, err := expandMergedValues(merged)
	if err != nil {
		return Snapshot{}, err
	}
	state, err := validateSnapshot(expanded, presence)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{state: state}, nil
}

// Valid reports whether the snapshot was produced by Load.
func (s Snapshot) Valid() bool {
	return s.state != nil
}

// Version returns the frozen configuration schema version.
func (s Snapshot) Version() string {
	if s.state == nil {
		return ""
	}
	return s.state.version
}

// Generation returns the public protected-bundle generation identifier.
func (s Snapshot) Generation() string {
	if s.state == nil {
		return ""
	}
	return s.state.generation
}

// Backend returns the closed replay backend selection.
func (s Snapshot) Backend() ReplayBackend {
	if s.state == nil {
		return 0
	}
	return s.state.replay.backend
}

// PolicyMode returns the closed daemon-owned policy selection.
func (s Snapshot) PolicyMode() PolicyMode {
	if s.state == nil {
		return 0
	}
	return s.state.policy
}

// Presence returns content-free provenance for one declared stable path.
func (s Snapshot) Presence(path string) (Presence, bool) {
	if s.state == nil {
		return Presence{}, false
	}
	value, present := s.state.presence[path]
	return value, present
}

// expandMergedValues performs one nonrecursive pass over winning scalar values.
func expandMergedValues(values map[string]rawValue) (map[string]rawValue, error) {
	specByPath, err := indexFieldSpecs(stableFieldSpecs())
	if err != nil {
		return nil, err
	}
	expanded := make(map[string]rawValue, len(values))
	total := 0
	for path, value := range values {
		spec, present := specByPath[path]
		if !present {
			return nil, newError(CodeInternal)
		}
		total += len(path)
		if total > maxAggregateBytes {
			return nil, newError(CodeInvalidField)
		}
		if path == pathConfigVersion || path == pathProtectedGeneration {
			if strings.Contains(value.text, "${") {
				return nil, newError(CodeInvalidPlaceholder)
			}
			total += len(value.text)
			if total > maxAggregateBytes {
				return nil, newError(CodeInvalidField)
			}
			expanded[path] = value
			continue
		}
		if value.source == SourceDefault || !strings.Contains(value.text, "${") {
			total += len(value.text)
			if len(value.text) > maxScalarBytes || total > maxAggregateBytes {
				return nil, newError(CodeInvalidField)
			}
			expanded[path] = value
			continue
		}
		if spec.kind != valueString && !isWholePlaceholder(value.text) {
			return nil, newError(CodeInvalidPlaceholder)
		}
		text, expandErr := expandPlaceholders(value.text, lookupEnvironment)
		if expandErr != nil || len(text) > maxScalarBytes {
			return nil, newError(CodeInvalidPlaceholder)
		}
		total += len(text)
		if total > maxAggregateBytes {
			return nil, newError(CodeInvalidField)
		}
		value.text = text
		value.kind = scalarExpanded
		expanded[path] = value
	}
	return expanded, nil
}

// lookupEnvironment obtains one placeholder value without adding a config binding.
func lookupEnvironment(name string) (string, bool) {
	return os.LookupEnv(name)
}

// validateSnapshot owns all typed conversion and cross-field invariants.
func validateSnapshot(values map[string]rawValue, presence map[string]Presence) (*snapshotState, error) {
	if text(values, pathConfigVersion) != configVersion {
		return nil, newError(CodeInvalidField)
	}
	generation := text(values, pathProtectedGeneration)
	if !validGeneration(generation) {
		return nil, newError(CodeInvalidField)
	}
	backend, err := parseBackend(text(values, pathReplayBackend))
	if err != nil {
		return nil, err
	}
	if err := validateBackendMatrix(backend, presence, values); err != nil {
		return nil, err
	}
	server, err := parseServer(values)
	if err != nil {
		return nil, err
	}
	policy, err := parsePolicy(text(values, pathPolicyMode))
	if err != nil {
		return nil, err
	}
	dns, err := parseDNS(values)
	if err != nil {
		return nil, err
	}
	replay, err := parseReplay(values, presence, backend, generation, server.capabilityFile)
	if err != nil {
		return nil, err
	}
	signing, err := parseSigning(values, presence, generation, server)
	if err != nil {
		return nil, err
	}
	protectedPaths := append([]string{server.capabilityFile}, replayProtectedPaths(replay)...)
	if signing.backend != SigningDisabled {
		if server.signCapabilityFile != "" {
			protectedPaths = append(protectedPaths, server.signCapabilityFile)
		}
		if server.reviseCapabilityFile != "" {
			protectedPaths = append(protectedPaths, server.reviseCapabilityFile)
		}
		if server.dsnSignCapabilityFile != "" {
			protectedPaths = append(protectedPaths, server.dsnSignCapabilityFile)
		}
	}
	if signing.backend == SigningFlatFile {
		protectedPaths = append(protectedPaths, signing.datasourceFile, signing.privateManifestFile)
	}
	if !sameGenerationPaths(generation, protectedPaths...) || !allDistinct(protectedPaths) {
		return nil, newError(CodeInvalidField)
	}
	observability, err := parseObservability(values, presence, generation, protectedPaths...)
	if err != nil {
		return nil, err
	}
	return &snapshotState{
		version:       configVersion,
		generation:    generation,
		server:        server,
		policy:        policy,
		dns:           dns,
		replay:        replay,
		signing:       signing,
		observability: observability,
		presence:      clonePresence(presence),
	}, nil
}

// parseObservability validates logging, debug, and conditional tracing state.
func parseObservability(values map[string]rawValue, presence map[string]Presence, generation string, protectedPaths ...string) (observabilityState, error) {
	level, ok := map[string]LogLevel{
		"debug": LogLevelDebug, canonicalInfo: LogLevelInfo,
		"warn": LogLevelWarn, "error": LogLevelError,
	}[text(values, pathLoggingLevel)]
	if !ok {
		return observabilityState{}, newError(CodeInvalidField)
	}
	messageShape, err := boolValue(values, pathDebugMessageShape)
	if err != nil {
		return observabilityState{}, err
	}
	dns, err := boolValue(values, pathDebugDNS)
	if err != nil {
		return observabilityState{}, err
	}
	replay, err := boolValue(values, pathDebugReplay)
	if err != nil {
		return observabilityState{}, err
	}
	explicitTracing := func(path string) bool {
		entry, present := presence[path]
		return present && entry.Explicit()
	}
	exporterText := text(values, pathTracingExporter)
	if exporterText == canonicalNone {
		for _, path := range []string{pathTracingEndpoint, pathTracingCAFile, pathTracingSamplePerMillion, pathTracingExportTimeout} {
			if explicitTracing(path) {
				return observabilityState{}, newError(CodeInvalidField)
			}
		}
		return observabilityState{
			logLevel: level, debugMessageShape: messageShape,
			debugDNS: dns, debugReplay: replay,
			tracing: tracingState{exporter: TracingNone},
		}, nil
	}
	if exporterText != "otlp_http" {
		return observabilityState{}, newError(CodeInvalidField)
	}
	endpoint := text(values, pathTracingEndpoint)
	caFile := text(values, pathTracingCAFile)
	if !explicitTracing(pathTracingEndpoint) || !explicitTracing(pathTracingCAFile) ||
		!validOTLPEndpoint(endpoint) || !sameGenerationPath(generation, caFile) {
		return observabilityState{}, newError(CodeInvalidField)
	}
	for _, path := range protectedPaths {
		if path == caFile {
			return observabilityState{}, newError(CodeInvalidField)
		}
	}
	sample := uint64(10_000)
	if explicitTracing(pathTracingSamplePerMillion) {
		sample, err = uintValue(values, pathTracingSamplePerMillion, 1, 1_000_000)
		if err != nil {
			return observabilityState{}, err
		}
	}
	timeout := 5 * time.Second
	if explicitTracing(pathTracingExportTimeout) {
		timeout, err = durationValue(values, pathTracingExportTimeout, 100*time.Millisecond, 10*time.Second, false)
		if err != nil {
			return observabilityState{}, err
		}
	}
	return observabilityState{
		logLevel: level, debugMessageShape: messageShape,
		debugDNS: dns, debugReplay: replay,
		tracing: tracingState{
			exporter: TracingOTLPHTTP, endpoint: endpoint, caFile: caFile,
			samplePerMillion: uint32(sample), exportTimeout: timeout,
		},
	}, nil
}

// replayProtectedPaths returns the selected replay generation paths.
func replayProtectedPaths(replay replayState) []string {
	if !replay.hasReplayConfig {
		return nil
	}
	paths := []string{replay.hmacKeyFile}
	if replay.hasValkeyConfig {
		paths = append(paths, replay.valkey.caFile, replay.valkey.applicationPasswordFile, replay.valkey.auditorPasswordFile)
	}
	return paths
}

// validOTLPEndpoint accepts one canonical HTTPS authority and the exact traces path.
func validOTLPEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" ||
		parsed.Path != "/v1/traces" || parsed.RawPath != "" || parsed.Opaque != "" || parsed.String() != value {
		return false
	}
	host := parsed.Hostname()
	portText := parsed.Port()
	address, err := netip.ParseAddr(host)
	if err == nil {
		if address.IsUnspecified() || address.IsMulticast() || address.Is4In6() ||
			address.Zone() != "" || address.String() != host {
			return false
		}
	} else if !validCanonicalDNSName(host) {
		return false
	}
	if portText == "" {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port != 0 && strconv.FormatUint(port, 10) == portText &&
		net.JoinHostPort(host, portText) == parsed.Host
}

// validCanonicalDNSName proves one lowercase ASCII DNS hostname without a root dot.
func validCanonicalDNSName(name string) bool {
	if len(name) < 1 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 ||
			!lowercaseDNSLetterOrDigit(label[0]) ||
			!lowercaseDNSLetterOrDigit(label[len(label)-1]) {
			return false
		}
		for index := range len(label) {
			value := label[index]
			if !lowercaseDNSLetterOrDigit(value) && value != '-' {
				return false
			}
		}
	}
	return true
}

// lowercaseDNSLetterOrDigit reports the canonical endpoint DNS alphabet.
func lowercaseDNSLetterOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// clonePresence prevents caller-owned maps from mutating snapshot provenance.
func clonePresence(input map[string]Presence) map[string]Presence {
	cloned := make(map[string]Presence, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

// parseServer validates the exact local HTTP resource contract.
func parseServer(values map[string]rawValue) (serverState, error) {
	readHeader, err := durationValue(values, pathServerReadHeader, time.Second, 30*time.Second, false)
	if err != nil {
		return serverState{}, err
	}
	read, err := durationValue(values, pathServerRead, time.Second, 120*time.Second, false)
	if err != nil {
		return serverState{}, err
	}
	deadline, err := durationValue(values, pathServerDeadline, time.Second, 120*time.Second, false)
	if err != nil {
		return serverState{}, err
	}
	write, err := durationValue(values, pathServerWrite, time.Second, 180*time.Second, false)
	if err != nil {
		return serverState{}, err
	}
	shutdown, err := durationValue(values, pathServerShutdown, time.Second, 120*time.Second, false)
	if err != nil || shutdown > time.Duration(1<<63-1)-50*time.Second {
		return serverState{}, newError(CodeInvalidField)
	}
	admission, err := durationValue(values, pathServerAdmissionWait, 0, time.Second, true)
	if err != nil {
		return serverState{}, err
	}
	maxInFlight, err := uintValue(values, pathServerMaxInFlight, 1, 2)
	if err != nil {
		return serverState{}, err
	}
	maxWaiters, err := uintValue(values, pathServerMaxWaiters, 0, 1024)
	if err != nil {
		return serverState{}, err
	}
	listen := text(values, pathServerListen)
	capability := text(values, pathServerCapability)
	signCapability := text(values, pathServerSignCapability)
	reviseCapability := text(values, pathServerReviseCapability)
	dsnSignCapability := text(values, pathServerDSNSignCapability)
	if !validLoopbackListener(listen) || !validProtectedPath(capability) ||
		readHeader > read || read > deadline || deadline > time.Duration(1<<63-1)-time.Second ||
		write < deadline+time.Second {
		return serverState{}, newError(CodeInvalidField)
	}
	return serverState{
		listen:                listen,
		capabilityFile:        capability,
		signCapabilityFile:    signCapability,
		reviseCapabilityFile:  reviseCapability,
		dsnSignCapabilityFile: dsnSignCapability,
		readHeaderTimeout:     readHeader,
		readTimeout:           read,
		writeTimeout:          write,
		requestDeadline:       deadline,
		shutdownTimeout:       shutdown,
		maxInFlight:           uint8(maxInFlight),
		maxWaiters:            uint16(maxWaiters),
		admissionWait:         admission,
	}, nil
}

// parseSigning validates the default-disabled signing conditional matrix.
//
//nolint:gocyclo // The closed backend-conditional configuration matrix is intentionally explicit.
func parseSigning(
	values map[string]rawValue,
	presence map[string]Presence,
	generation string,
	server serverState,
) (signingState, error) {
	backendText := text(values, pathSigningBackend)
	var backend SigningBackend
	switch backendText {
	case valueBackendDisabled:
		if explicitPrefix(presence, "signing.ldap.") ||
			explicitPrefix(presence, "signing.postgresql.") ||
			explicitPrefix(presence, "signing.mysql.") {
			return signingState{}, newError(CodeInvalidMatrix)
		}
		for _, path := range []string{
			pathSigningDatasource,
			pathSigningManifest,
			pathSigningReload,
			pathSigningAllowGroup,
			pathServerSignCapability,
			pathServerReviseCapability,
			pathServerDSNSignCapability,
		} {
			if presence[path].Explicit() {
				return signingState{}, newError(CodeInvalidMatrix)
			}
		}
		return signingState{backend: SigningDisabled}, nil
	case "flat_file":
		backend = SigningFlatFile
	case "ldap":
		backend = SigningLDAP
	case "postgresql":
		backend = SigningPostgreSQL
	case "mysql":
		backend = SigningMySQL
	default:
		return signingState{}, newError(CodeInvalidField)
	}
	required := []string{pathSigningBackend}
	if backend == SigningFlatFile {
		required = append(required, pathSigningDatasource, pathSigningManifest)
	}
	for _, path := range required {
		if !presence[path].Explicit() {
			return signingState{}, newError(CodeInvalidMatrix)
		}
	}
	if backend != SigningFlatFile &&
		(presence[pathSigningDatasource].Explicit() || presence[pathSigningManifest].Explicit()) {
		return signingState{}, newError(CodeInvalidMatrix)
	}
	if backend == SigningFlatFile &&
		(explicitPrefix(presence, "signing.ldap.") ||
			explicitPrefix(presence, "signing.postgresql.") ||
			explicitPrefix(presence, "signing.mysql.")) {
		return signingState{}, newError(CodeInvalidMatrix)
	}
	if backend == SigningLDAP &&
		(explicitPrefix(presence, "signing.postgresql.") ||
			explicitPrefix(presence, "signing.mysql.") ||
			!requiredExplicit(presence,
				pathSigningLDAPAddress, pathSigningLDAPServerName,
				pathSigningLDAPCAFile, pathSigningLDAPTransport,
				pathSigningLDAPBindDN, pathSigningLDAPPassword,
				pathSigningLDAPBaseDN,
			)) {
		return signingState{}, newError(CodeInvalidMatrix)
	}
	if backend == SigningPostgreSQL &&
		(explicitPrefix(presence, "signing.ldap.") ||
			explicitPrefix(presence, "signing.mysql.") ||
			!requiredExplicit(presence,
				pathSigningPGAddress, pathSigningPGServerName,
				pathSigningPGCAFile, pathSigningPGDatabase,
				pathSigningPGUser, pathSigningPGPassword,
			)) {
		return signingState{}, newError(CodeInvalidMatrix)
	}
	if backend == SigningMySQL &&
		(explicitPrefix(presence, "signing.ldap.") ||
			explicitPrefix(presence, "signing.postgresql.") ||
			!requiredExplicit(presence,
				pathSigningMySQLAddress, pathSigningMySQLServerName,
				pathSigningMySQLCAFile, pathSigningMySQLDatabase,
				pathSigningMySQLUser, pathSigningMySQLPassword,
			)) {
		return signingState{}, newError(CodeInvalidMatrix)
	}
	signPresent := presence[pathServerSignCapability].Explicit()
	revisePresent := presence[pathServerReviseCapability].Explicit()
	dsnSignPresent := presence[pathServerDSNSignCapability].Explicit()
	if !signPresent && !revisePresent && !dsnSignPresent {
		return signingState{}, newError(CodeInvalidMatrix)
	}
	reload, err := durationValue(
		values, pathSigningReload, time.Second, time.Hour, false,
	)
	if err != nil {
		return signingState{}, err
	}
	allowGroup, err := boolValue(values, pathSigningAllowGroup)
	if err != nil {
		return signingState{}, err
	}
	if allowGroup {
		return signingState{}, newError(CodeInvalidField)
	}
	limitProfile := text(values, pathSigningLimitProfile)
	if limitProfile != limitProfileSmall && limitProfile != limitProfileProduction {
		return signingState{}, newError(CodeInvalidField)
	}
	maxLoadBytes, err := uintValue(values, pathSigningMaxLoadBytes, 1<<20, 512<<20)
	if err != nil || limitProfile == limitProfileProduction && maxLoadBytes < 64<<20 {
		return signingState{}, newError(CodeInvalidField)
	}
	datasourceFile := text(values, pathSigningDatasource)
	manifestFile := text(values, pathSigningManifest)
	paths := []string{server.capabilityFile}
	if backend == SigningFlatFile {
		paths = append(paths, datasourceFile, manifestFile)
	}
	if signPresent {
		paths = append(paths, server.signCapabilityFile)
	}
	if revisePresent {
		paths = append(paths, server.reviseCapabilityFile)
	}
	if dsnSignPresent {
		paths = append(paths, server.dsnSignCapabilityFile)
	}
	if !sameGenerationPaths(generation, paths...) || !allDistinct(paths) {
		return signingState{}, newError(CodeInvalidField)
	}
	result := signingState{
		backend:             backend,
		datasourceFile:      datasourceFile,
		privateManifestFile: manifestFile,
		reloadInterval:      reload,
		allowRecipientGroup: allowGroup,
		limitProfile:        limitProfile,
		maxLoadBytes:        uint32(maxLoadBytes),
	}
	if backend == SigningLDAP {
		ldapConfig, parseErr := parseLDAPSigning(values, generation, paths)
		if parseErr != nil {
			return signingState{}, parseErr
		}
		result.ldap = ldapConfig
	}
	if backend == SigningPostgreSQL {
		postgresqlConfig, parseErr := parseSQLSigning(
			values, generation, paths,
			sqlSigningPaths{
				address: pathSigningPGAddress, serverName: pathSigningPGServerName,
				caFile: pathSigningPGCAFile, database: pathSigningPGDatabase,
				user: pathSigningPGUser, password: pathSigningPGPassword,
				pageSize: pathSigningPGPageSize, deadline: pathSigningPGDeadline,
				maxConnections: pathSigningPGMaxConns, idleConnections: pathSigningPGIdleConns,
			},
		)
		if parseErr != nil {
			return signingState{}, parseErr
		}
		result.postgresql = postgresqlConfig
	}
	if backend == SigningMySQL {
		mysqlConfig, parseErr := parseSQLSigning(
			values, generation, paths,
			sqlSigningPaths{
				address: pathSigningMySQLAddress, serverName: pathSigningMySQLServerName,
				caFile: pathSigningMySQLCAFile, database: pathSigningMySQLDatabase,
				user: pathSigningMySQLUser, password: pathSigningMySQLPassword,
				pageSize: pathSigningMySQLPageSize, deadline: pathSigningMySQLDeadline,
				maxConnections: pathSigningMySQLMaxConns, idleConnections: pathSigningMySQLIdleConns,
			},
		)
		if parseErr != nil {
			return signingState{}, parseErr
		}
		result.mysql = mysqlConfig
	}
	return result, nil
}

// parseLDAPSigning validates one verified-TLS single-authority LDAP subtree.
func parseLDAPSigning(
	values map[string]rawValue,
	generation string,
	commonPaths []string,
) (ldapSigningState, error) {
	address, serverName := text(values, pathSigningLDAPAddress), text(values, pathSigningLDAPServerName)
	if !validNetworkAuthority(address, serverName) {
		return ldapSigningState{}, newError(CodeInvalidField)
	}
	transport := text(values, pathSigningLDAPTransport)
	if transport != "ldaps" && transport != "starttls" {
		return ldapSigningState{}, newError(CodeInvalidField)
	}
	bindDN, baseDN := text(values, pathSigningLDAPBindDN), text(values, pathSigningLDAPBaseDN)
	if bindDN == "" || baseDN == "" || len(bindDN) > 4096 || len(baseDN) > 4096 {
		return ldapSigningState{}, newError(CodeInvalidField)
	}
	caFile, passwordFile := text(values, pathSigningLDAPCAFile), text(values, pathSigningLDAPPassword)
	paths := append(append([]string(nil), commonPaths...), caFile, passwordFile)
	if !sameGenerationPaths(generation, paths...) || !allDistinct(paths) {
		return ldapSigningState{}, newError(CodeInvalidField)
	}
	pageSize, err := uintValue(values, pathSigningLDAPPageSize, 1, 256)
	if err != nil {
		return ldapSigningState{}, err
	}
	deadline, err := durationValue(values, pathSigningLDAPDeadline, time.Millisecond, 30*time.Second, false)
	if err != nil {
		return ldapSigningState{}, err
	}
	return ldapSigningState{
		address: address, serverName: serverName, caFile: caFile,
		transport: transport, bindDN: bindDN, passwordFile: passwordFile,
		baseDN: baseDN, pageSize: uint16(pageSize), loadDeadline: deadline,
	}, nil
}

type sqlSigningPaths struct {
	address, serverName, caFile, database, user, password string
	pageSize, deadline, maxConnections, idleConnections   string
}

// parseSQLSigning validates one verified-TLS single-authority SQL subtree.
func parseSQLSigning(
	values map[string]rawValue,
	generation string,
	commonPaths []string,
	selected sqlSigningPaths,
) (sqlSigningState, error) {
	address, serverName := text(values, selected.address), text(values, selected.serverName)
	if !validNetworkAuthority(address, serverName) {
		return sqlSigningState{}, newError(CodeInvalidField)
	}
	database, user := text(values, selected.database), text(values, selected.user)
	if !validIdentifier(database, 128) || !validIdentifier(user, 128) {
		return sqlSigningState{}, newError(CodeInvalidField)
	}
	caFile, passwordFile := text(values, selected.caFile), text(values, selected.password)
	paths := append(append([]string(nil), commonPaths...), caFile, passwordFile)
	if !sameGenerationPaths(generation, paths...) || !allDistinct(paths) {
		return sqlSigningState{}, newError(CodeInvalidField)
	}
	pageSize, err := uintValue(values, selected.pageSize, 1, 256)
	if err != nil {
		return sqlSigningState{}, err
	}
	deadline, err := durationValue(values, selected.deadline, time.Millisecond, 30*time.Second, false)
	if err != nil {
		return sqlSigningState{}, err
	}
	maxConnections, err := uintValue(values, selected.maxConnections, 1, 4)
	if err != nil {
		return sqlSigningState{}, err
	}
	idleConnections, err := uintValue(values, selected.idleConnections, 0, 2)
	if err != nil || idleConnections > maxConnections {
		return sqlSigningState{}, newError(CodeInvalidField)
	}
	return sqlSigningState{
		address: address, serverName: serverName, caFile: caFile,
		database: database, user: user, passwordFile: passwordFile,
		pageSize: uint16(pageSize), loadDeadline: deadline,
		maxConnections: uint8(maxConnections), idleConnections: uint8(idleConnections),
	}, nil
}

// explicitPrefix reports whether one backend-specific subtree was supplied.
func explicitPrefix(presence map[string]Presence, prefix string) bool {
	for path, source := range presence {
		if strings.HasPrefix(path, prefix) && source.Explicit() {
			return true
		}
	}
	return false
}

// requiredExplicit reports whether every conditional path has operator authority.
func requiredExplicit(presence map[string]Presence, paths ...string) bool {
	for _, path := range paths {
		if !presence[path].Explicit() {
			return false
		}
	}
	return true
}

// validNetworkAuthority accepts one direct IP endpoint plus separate TLS name.
func validNetworkAuthority(address, serverName string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || serverName == "" || len(serverName) > 253 {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	value, err := strconv.ParseUint(port, 10, 16)
	return err == nil && value != 0
}

// validIdentifier validates one bounded backend account or database identifier.
func validIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// parseDNS validates only the two permitted DNS overrides.
func parseDNS(values map[string]rawValue) (dnsState, error) {
	timeout, err := durationValue(values, pathDNSLookupTimeout, time.Millisecond, 30*time.Second, false)
	if err != nil {
		return dnsState{}, err
	}
	concurrent, err := uintValue(values, pathDNSMaxConcurrent, 1, 1024)
	if err != nil {
		return dnsState{}, err
	}
	return dnsState{lookupTimeout: timeout, maxConcurrentLookups: uint16(concurrent)}, nil
}

// parseReplay validates selected provider-neutral and provider-specific values.
func parseReplay(values map[string]rawValue, presence map[string]Presence, backend ReplayBackend, generation, capabilityPath string) (replayState, error) {
	result := replayState{backend: backend}
	if backend == ReplayDisabled {
		if !sameGenerationPath(generation, capabilityPath) {
			return replayState{}, newError(CodeInvalidField)
		}
		return result, nil
	}
	epoch, err := uintValue(values, pathReplayEpoch, 1, 4_294_967_295)
	if err != nil {
		return replayState{}, err
	}
	retention, err := durationValue(values, pathReplayRetention, time.Second, 720*time.Hour, false)
	if err != nil || retention%time.Millisecond != 0 {
		return replayState{}, newError(CodeInvalidField)
	}
	maxEntries, err := uintValue(values, pathReplayMaxEntries, 1, 1_048_576)
	if err != nil {
		return replayState{}, err
	}
	maxWaiters, err := uintValue(values, pathReplayMaxWaiters, 1, 65_536)
	if err != nil {
		return replayState{}, err
	}
	pruneBudget, err := uintValue(values, pathReplayPruneBudget, 1, 65_536)
	if err != nil {
		return replayState{}, err
	}
	maxInFlight, err := uintValue(values, pathReplayMaxInFlight, 1, 65_536)
	if err != nil {
		return replayState{}, err
	}
	maxAdmissionWaiters, err := uintValue(values, pathReplayMaxAdmission, 1, 65_536)
	if err != nil {
		return replayState{}, err
	}
	hmacPath := text(values, pathReplayHMACFile)
	if !validProtectedPath(hmacPath) ||
		!sameGenerationPaths(generation, capabilityPath, hmacPath) ||
		capabilityPath == hmacPath {
		return replayState{}, newError(CodeInvalidField)
	}
	result.hmacKeyFile = hmacPath
	result.epoch = uint32(epoch)
	result.retention = retention
	result.maxEntries = uint32(maxEntries)
	result.maxWaiters = uint32(maxWaiters)
	result.pruneBudget = uint32(pruneBudget)
	result.maxInFlight = uint32(maxInFlight)
	result.maxAdmissionWaiters = uint32(maxAdmissionWaiters)
	result.hasReplayConfig = true
	if backend == ReplayMemory {
		return result, nil
	}
	revalidate, err := durationValue(values, pathReplayRevalidate, 10*time.Second, 60*time.Second, false)
	if err != nil {
		return replayState{}, err
	}
	valkeyConfig, attestation, err := parseValkey(values, presence, generation, capabilityPath, hmacPath)
	if err != nil {
		return replayState{}, err
	}
	result.revalidateInterval = revalidate
	result.valkey = valkeyConfig
	result.operatorAttestation = attestation
	result.hasValkeyConfig = true
	return result, nil
}

// parseValkey validates direct authority, protected paths, and deployment attestation.
func parseValkey(values map[string]rawValue, presence map[string]Presence, generation string, commonPaths ...string) (valkeyState, valkey.OperatorAttestation, error) {
	address := text(values, pathValkeyAddress)
	serverName := text(values, pathValkeyServerName)
	appUsername := text(values, pathValkeyApplicationUser)
	auditUsername := text(values, pathValkeyAuditorUser)
	if !valkey.ValidAuthority(address, serverName, appUsername, auditUsername) {
		return valkeyState{}, valkey.OperatorAttestation{}, newError(CodeInvalidField)
	}
	protectedPaths := append(append([]string(nil), commonPaths...),
		text(values, pathValkeyCAFile),
		text(values, pathValkeyApplicationPass),
		text(values, pathValkeyAuditorPass),
	)
	if !sameGenerationPaths(generation, protectedPaths...) || !allDistinct(protectedPaths) {
		return valkeyState{}, valkey.OperatorAttestation{}, newError(CodeInvalidField)
	}
	dialTimeout, err := durationValue(values, pathValkeyDialTimeout, 100*time.Millisecond, 30*time.Second, false)
	if err != nil {
		return valkeyState{}, valkey.OperatorAttestation{}, err
	}
	keepalive, err := durationValue(values, pathValkeyTCPKeepalive, time.Second, 5*time.Minute, false)
	if err != nil {
		return valkeyState{}, valkey.OperatorAttestation{}, err
	}
	writeTimeout, err := durationValue(values, pathValkeyWriteTimeout, 100*time.Millisecond, 30*time.Second, false)
	if err != nil {
		return valkeyState{}, valkey.OperatorAttestation{}, err
	}
	attestation, err := parseAttestation(values, presence)
	if err != nil {
		return valkeyState{}, valkey.OperatorAttestation{}, err
	}
	return valkeyState{
		address:                 address,
		serverName:              serverName,
		caFile:                  protectedPaths[len(commonPaths)],
		applicationUsername:     appUsername,
		applicationPasswordFile: protectedPaths[len(commonPaths)+1],
		auditorUsername:         auditUsername,
		auditorPasswordFile:     protectedPaths[len(commonPaths)+2],
		dialTimeout:             dialTimeout,
		tcpKeepalive:            keepalive,
		connectionWriteTimeout:  writeTimeout,
	}, attestation, nil
}

// parseAttestation delegates the complete persistence grammar to the M12 owner.
func parseAttestation(values map[string]rawValue, _ map[string]Presence) (valkey.OperatorAttestation, error) {
	persistence, ok := map[string]valkey.PersistenceMode{
		valuePersistenceRDB: valkey.PersistenceModeRDB,
		"aof":               valkey.PersistenceModeAOF,
		"rdb_aof":           valkey.PersistenceModeRDBAOF,
	}[text(values, pathAttestationPersistence)]
	if !ok {
		return valkey.OperatorAttestation{}, newError(CodeInvalidField)
	}
	fsync, ok := map[string]valkey.AppendFsyncPolicy{
		"inactive": valkey.AppendFsyncInactive,
		"always":   valkey.AppendFsyncAlways,
		"everysec": valkey.AppendFsyncEverySecond,
	}[text(values, pathAttestationFsync)]
	if !ok {
		return valkey.OperatorAttestation{}, newError(CodeInvalidField)
	}
	rotation, ok := map[string]valkey.RotationState{
		"unchanged":       valkey.RotationUnchanged,
		"drain_completed": valkey.RotationDrainCompleted,
	}[text(values, pathAttestationRotation)]
	if !ok || text(values, pathAttestationLossWindow) != "asynchronous_acknowledged" {
		return valkey.OperatorAttestation{}, newError(CodeInvalidField)
	}
	minReplicas, err := uintValue(values, pathAttestationMinReplicas, 0, 3)
	if err != nil {
		return valkey.OperatorAttestation{}, err
	}
	maxLag, err := uintValue(values, pathAttestationMaxLag, 1, 3600)
	if err != nil {
		return valkey.OperatorAttestation{}, err
	}
	booleanPaths := []string{
		pathAttestationNoGlobalExactlyOnce,
		pathAttestationDedicatedDeployment,
		pathAttestationDedicatedDatabase,
		pathAttestationDirectIPAuthority,
		pathAttestationNoSubstitution,
		pathAttestationStandaloneAuthority,
		pathAttestationSharedDraft,
		pathAttestationSharedAlgorithm,
		pathAttestationSharedNamespace,
		pathAttestationSharedEpoch,
		pathAttestationSharedSecretSet,
		pathAttestationSharedRetention,
	}
	for _, path := range booleanPaths {
		if _, booleanErr := boolValue(values, path); booleanErr != nil {
			return valkey.OperatorAttestation{}, booleanErr
		}
		if !boolText(values, path) {
			return valkey.OperatorAttestation{}, newError(CodeInvalidField)
		}
	}
	input := valkey.NewOperatorAttestationInput(
		persistence,
		fsync,
		text(values, pathAttestationSave),
		uint8(minReplicas),
		uint16(maxLag),
		valkey.LossWindowAsynchronousAcknowledged,
		rotation,
		valkey.AssertNoGlobalExactlyOnceClaim,
		valkey.AssertDedicatedDeployment,
		valkey.AssertDedicatedDatabaseZero,
		valkey.AssertDirectIPAuthority,
		valkey.AssertNoEndpointSubstitution,
		valkey.AssertStandaloneAuthority,
		valkey.AssertSharedDraft,
		valkey.AssertSharedAlgorithm,
		valkey.AssertSharedNamespace,
		valkey.AssertSharedEpoch,
		valkey.AssertSharedSecretSet,
		valkey.AssertSharedRetention,
	)
	attestation, err := valkey.NewOperatorAttestation(input)
	if err != nil {
		return valkey.OperatorAttestation{}, newError(CodeInvalidField)
	}
	return attestation, nil
}

// validateBackendMatrix rejects missing and forbidden explicit sources before defaults matter.
func validateBackendMatrix(backend ReplayBackend, presence map[string]Presence, values map[string]rawValue) error {
	require := func(paths ...string) bool {
		for _, path := range paths {
			if !presence[path].Explicit() {
				return false
			}
		}
		return true
	}
	forbidPrefix := func(prefix string, exceptions ...string) bool {
		excluded := make(map[string]struct{}, len(exceptions))
		for _, path := range exceptions {
			excluded[path] = struct{}{}
		}
		for path, source := range presence {
			if strings.HasPrefix(path, prefix) && source.Explicit() {
				if _, allowed := excluded[path]; !allowed {
					return false
				}
			}
		}
		return true
	}
	if !require(pathConfigVersion, pathProtectedGeneration, pathServerCapability) {
		return newError(CodeInvalidMatrix)
	}
	switch backend {
	case ReplayDisabled:
		if !require(pathReplayBackend) || !forbidPrefix("replay.", pathReplayBackend) {
			return newError(CodeInvalidMatrix)
		}
	case ReplayMemory:
		if !require(pathReplayBackend, pathReplayHMACFile, pathReplayEpoch) ||
			presence[pathReplayRevalidate].Explicit() ||
			!forbidPrefix("replay.valkey.") {
			return newError(CodeInvalidMatrix)
		}
	case ReplayValkey:
		required := []string{
			pathReplayHMACFile, pathReplayEpoch,
			pathValkeyAddress, pathValkeyServerName, pathValkeyCAFile,
			pathValkeyApplicationUser, pathValkeyApplicationPass,
			pathValkeyAuditorUser, pathValkeyAuditorPass,
			pathAttestationPersistence, pathAttestationFsync,
			pathAttestationMinReplicas,
			pathAttestationMaxLag,
			pathAttestationLossWindow, pathAttestationRotation,
			pathAttestationNoGlobalExactlyOnce,
			pathAttestationDedicatedDeployment,
			pathAttestationDedicatedDatabase,
			pathAttestationDirectIPAuthority,
			pathAttestationNoSubstitution,
			pathAttestationStandaloneAuthority,
			pathAttestationSharedDraft,
			pathAttestationSharedAlgorithm,
			pathAttestationSharedNamespace,
			pathAttestationSharedEpoch,
			pathAttestationSharedSecretSet,
			pathAttestationSharedRetention,
		}
		if !require(required...) {
			return newError(CodeInvalidMatrix)
		}
		mode := text(values, pathAttestationPersistence)
		savePresent := presence[pathAttestationSave].Explicit()
		if (mode == "aof" && savePresent) || ((mode == valuePersistenceRDB || mode == "rdb_aof") && !savePresent) {
			return newError(CodeInvalidMatrix)
		}
	default:
		return newError(CodeInvalidMatrix)
	}
	return nil
}

// parsePolicy converts one exact policy enum.
func parsePolicy(value string) (PolicyMode, error) {
	switch value {
	case valuePolicyStrict:
		return PolicyStrict, nil
	case "permissive":
		return PolicyPermissive, nil
	case "testing":
		return PolicyTesting, nil
	default:
		return 0, newError(CodeInvalidField)
	}
}

// parseBackend converts one exact replay backend enum.
func parseBackend(value string) (ReplayBackend, error) {
	switch value {
	case valueBackendValkey:
		return ReplayValkey, nil
	case "memory":
		return ReplayMemory, nil
	case valueBackendDisabled:
		return ReplayDisabled, nil
	default:
		return 0, newError(CodeInvalidField)
	}
}

// text returns one merged scalar without formatting it.
func text(values map[string]rawValue, path string) string {
	return values[path].text
}

// boolText converts one already type-checked exact boolean.
func boolText(values map[string]rawValue, path string) bool {
	return values[path].text == canonicalTrue
}

// boolValue enforces exact source typing and lowercase boolean spelling.
func boolValue(values map[string]rawValue, path string) (bool, error) {
	value, present := values[path]
	if !present || !validScalarSourceKind(value, valueBool) ||
		(value.text != canonicalTrue && value.text != canonicalFalse) {
		return false, newError(CodeInvalidField)
	}
	return value.text == canonicalTrue, nil
}

// uintValue enforces exact source typing, canonical decimal, and range.
func uintValue(values map[string]rawValue, path string, minimum, maximum uint64) (uint64, error) {
	value, present := values[path]
	if !present || !validScalarSourceKind(value, valueUint) || !canonicalUint(value.text) {
		return 0, newError(CodeInvalidField)
	}
	parsed, err := strconv.ParseUint(value.text, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, newError(CodeInvalidField)
	}
	return parsed, nil
}

// durationValue enforces exact token grammar and a field-specific range.
func durationValue(values map[string]rawValue, path string, minimum, maximum time.Duration, allowZero bool) (time.Duration, error) {
	value, present := values[path]
	if !present || !validScalarSourceKind(value, valueDuration) || !canonicalDuration(value.text, allowZero) {
		return 0, newError(CodeInvalidField)
	}
	parsed, err := time.ParseDuration(value.text)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, newError(CodeInvalidField)
	}
	return parsed, nil
}

// validScalarSourceKind rejects YAML weak conversion and mixed placeholders.
func validScalarSourceKind(value rawValue, kind valueKind) bool {
	switch kind {
	case valueUint:
		if value.source == SourceYAML {
			return value.kind == scalarUint || value.kind == scalarExpanded
		}
		return value.kind == scalarString || value.kind == scalarUint
	case valueBool:
		if value.source == SourceYAML {
			return value.kind == scalarBool || value.kind == scalarExpanded
		}
		return value.kind == scalarString || value.kind == scalarBool
	case valueDuration:
		return value.kind == scalarString || value.kind == scalarExpanded
	case valueString:
		return value.kind == scalarString || value.kind == scalarExpanded
	default:
		return false
	}
}

// canonicalUint reports exact unsigned decimal syntax.
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

// canonicalDuration reports the single-token duration grammar.
func canonicalDuration(value string, allowZero bool) bool {
	if value == "0s" {
		return allowZero
	}
	unitLength := 1
	if strings.HasSuffix(value, "ms") {
		unitLength = 2
	} else if !strings.HasSuffix(value, "s") && !strings.HasSuffix(value, "m") && !strings.HasSuffix(value, "h") {
		return false
	}
	digits := value[:len(value)-unitLength]
	return digits != "" && digits[0] >= '1' && digits[0] <= '9' && canonicalUint(digits)
}

// validLoopbackListener proves one canonical loopback IP-literal authority.
func validLoopbackListener(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.Contains(host, "%") {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() || address.Is4In6() || address.String() != host {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == portText
}

// validProtectedPath performs bounded lexical checks before descriptor-safe loading.
func validProtectedPath(value string) bool {
	if value == "" || len(value) > 4096 || strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) ||
		!filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	components := strings.Split(strings.TrimPrefix(value, string(filepath.Separator)), string(filepath.Separator))
	if len(components) < 1 || len(components) > 64 {
		return false
	}
	for _, component := range components {
		if component == "" || len(component) > 255 {
			return false
		}
	}
	return true
}

// sameGenerationPath proves one protected path is a direct child of the selected generation.
func sameGenerationPath(generation, path string) bool {
	return validProtectedPath(path) && filepath.Base(filepath.Dir(path)) == generation
}

// sameGenerationPaths proves all protected paths share one selected generation directory.
func sameGenerationPaths(generation string, paths ...string) bool {
	if len(paths) == 0 {
		return false
	}
	directory := filepath.Dir(paths[0])
	if filepath.Base(directory) != generation {
		return false
	}
	for _, path := range paths {
		if !validProtectedPath(path) || filepath.Dir(path) != directory {
			return false
		}
	}
	return true
}

// allDistinct reports whether every protected path spelling is distinct.
func allDistinct(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

// String returns a content-free policy-mode representation.
func (PolicyMode) String() string { return "dkim2d_policy_mode" }

// GoString returns a content-free policy-mode representation.
func (PolicyMode) GoString() string { return "dkim2d_policy_mode" }

// Format prevents formatting verbs from exposing policy state.
func (PolicyMode) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2d_policy_mode")
}

// MarshalJSON rejects serialization of daemon policy configuration.
func (PolicyMode) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects serialization of daemon policy configuration.
func (PolicyMode) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// String returns a content-free replay-backend representation.
func (ReplayBackend) String() string { return "dkim2d_replay_backend" }

// GoString returns a content-free replay-backend representation.
func (ReplayBackend) GoString() string { return "dkim2d_replay_backend" }

// Format prevents formatting verbs from exposing backend state.
func (ReplayBackend) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2d_replay_backend")
}

// MarshalJSON rejects serialization of replay-provider configuration.
func (ReplayBackend) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects serialization of replay-provider configuration.
func (ReplayBackend) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}
