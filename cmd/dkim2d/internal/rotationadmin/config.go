package rotationadmin

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"gopkg.in/yaml.v3"
)

const (
	rotationConfigVersion       = "dkim2-rotation-admin-v1"
	maxTrustBundleBytes         = 262_144
	backendLDAP                 = "ldap"
	profileStatusActive         = "active"
	bindingUseOriginator        = "originator"
	purgeLifecycleNeverActive   = "never_active"
	purgeLifecycleActiveHistory = "active_history"
)

// Config is the protected, closed offline campaign configuration.
type Config struct {
	authorityID string
	backend     string
	deadline    time.Duration
	limits      Limits
	roles       [5]role
	ldap        ldapTransport
	sql         sqlTransport
	dns         dnsProofTransport
	retention   datasourceadmin.RetentionPolicy
	recovery    datasourceadmin.RetentionRecoveryLimits
}

type role struct {
	name       string
	secretPath string
}

// ldapTransport owns the non-secret single-authority LDAP transport descriptor.
type ldapTransport struct {
	address, serverName, baseDN, caFile string
	startTLS                            bool
}

// sqlTransport owns the non-secret single-authority SQL transport descriptor.
type sqlTransport struct {
	address, serverName, database, caFile string
	connectTimeout                        time.Duration
	maxConnections, idleConnections       int
	pageSize                              int
}

// dnsProofTransport contains only resolver-path proof configuration. It has no
// DNS write, TSIG, zone-transfer, or publisher credential material.
type dnsProofTransport struct {
	policy        datasourceadmin.DNSPolicy
	lookupTimeout time.Duration
}

type configDocument struct {
	Version     string `yaml:"version"`
	AuthorityID string `yaml:"authority_id"`
	Backend     string `yaml:"backend"`
	Deadline    string `yaml:"deadline"`
	Limits      struct {
		MaxWorkItems       uint32 `yaml:"max_work_items"`
		MaxDNSBatchRecords uint32 `yaml:"max_dns_batch_records"`
		MaxDNSBatches      uint32 `yaml:"max_dns_batches"`
	} `yaml:"limits"`
	Roles struct {
		Snapshot   roleDocument `yaml:"snapshot"`
		Staging    roleDocument `yaml:"staging"`
		Activation roleDocument `yaml:"activation"`
		Purge      roleDocument `yaml:"purge"`
		Closer     roleDocument `yaml:"closer"`
	} `yaml:"roles"`
	Transport struct {
		LDAP struct {
			Address    string `yaml:"address"`
			ServerName string `yaml:"server_name"`
			BaseDN     string `yaml:"base_dn"`
			CAFile     string `yaml:"ca_file"`
			StartTLS   bool   `yaml:"starttls"`
		} `yaml:"ldap"`
		SQL struct {
			Address         string `yaml:"address"`
			ServerName      string `yaml:"server_name"`
			Database        string `yaml:"database"`
			CAFile          string `yaml:"ca_file"`
			ConnectTimeout  string `yaml:"connect_timeout"`
			MaxConnections  int    `yaml:"max_connections"`
			IdleConnections int    `yaml:"idle_connections"`
			PageSize        int    `yaml:"page_size"`
		} `yaml:"sql"`
	} `yaml:"transport"`
	DNS struct {
		ResolverClass        string   `yaml:"resolver_class"`
		ResolverEndpoints    []string `yaml:"resolver_endpoints"`
		ExportTTLSeconds     uint64   `yaml:"export_ttl_seconds"`
		ProofLifetimeSeconds uint64   `yaml:"proof_lifetime_seconds"`
		LookupTimeout        string   `yaml:"lookup_timeout"`
	} `yaml:"dns"`
	Retention struct {
		MaxTotalGenerations             *uint32 `yaml:"max_total_generations"`
		MinActiveRollbackGenerations    *uint32 `yaml:"min_active_rollback_generations"`
		MaxClosedNeverActiveGenerations *uint32 `yaml:"max_closed_never_active_generations"`
		MaxPurgeBatch                   *uint32 `yaml:"max_purge_batch"`
		MaxRecoveryGenerations          *uint32 `yaml:"max_recovery_generations"`
		RecoveryPageSize                *uint32 `yaml:"recovery_page_size"`
		MaxRecoveryReadBytes            *uint32 `yaml:"max_recovery_read_bytes"`
	} `yaml:"retention"`
}

type roleDocument struct {
	Name       string `yaml:"name"`
	SecretFile string `yaml:"secret_file"`
}

// LoadConfig validates the complete protected configuration and all five role secrets.
func LoadConfig(path string) (*Config, error) {
	if !cleanAbsolute(path) {
		return nil, errInvalid
	}
	document, err := config.ReadProtectedDocument(path, 65536)
	if err != nil {
		return nil, errInvalid
	}
	defer clear(document)
	if err := validateConfigYAML(document); err != nil {
		return nil, errInvalid
	}
	expanded, err := config.ExpandYAMLScalarPlaceholders(document)
	if err != nil {
		return nil, errInvalid
	}
	defer clear(expanded)
	var decoded configDocument
	decoder := yaml.NewDecoder(bytes.NewReader(expanded))
	decoder.KnownFields(true)
	if err := decoder.Decode(&decoded); err != nil {
		return nil, errInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errInvalid
	}
	return decoded.load(path)
}

// load validates finite policy, role separation, and protected secret readability.
func (d configDocument) load(path string) (*Config, error) { //nolint:gocyclo // Strict closed-document validation is intentionally centralized.
	if d.Version != rotationConfigVersion || d.AuthorityID == "" || !knownBackend(d.Backend) {
		return nil, errInvalid
	}
	deadline, err := time.ParseDuration(d.Deadline)
	if err != nil || deadline <= 0 || deadline > 24*time.Hour {
		return nil, errInvalid
	}
	limits := Limits{MaxWorkItems: d.Limits.MaxWorkItems, MaxDNSBatchRecords: d.Limits.MaxDNSBatchRecords, MaxDNSBatches: d.Limits.MaxDNSBatches}
	if limits.Validate() != nil {
		return nil, errInvalid
	}
	entries := []roleDocument{d.Roles.Snapshot, d.Roles.Staging, d.Roles.Activation, d.Roles.Purge, d.Roles.Closer}
	roles := [5]role{}
	seenNames, seenPaths := make(map[string]struct{}, len(entries)), make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		if !validRoleName(entry.Name) || !cleanAbsolute(entry.SecretFile) || filepath.Dir(entry.SecretFile) != filepath.Dir(path) {
			return nil, errInvalid
		}
		if _, duplicate := seenNames[entry.Name]; duplicate {
			return nil, errInvalid
		}
		if _, duplicate := seenPaths[entry.SecretFile]; duplicate {
			return nil, errInvalid
		}
		secret, readErr := config.ReadProtectedDocument(entry.SecretFile, 65536)
		if readErr != nil || len(secret) == 0 {
			clear(secret)
			return nil, errInvalid
		}
		clear(secret)
		seenNames[entry.Name], seenPaths[entry.SecretFile] = struct{}{}, struct{}{}
		roles[index] = role{name: entry.Name, secretPath: entry.SecretFile}
	}
	policy := datasourceadmin.DefaultRetentionPolicy()
	recovery := datasourceadmin.DefaultRetentionRecoveryLimits()
	if d.Retention.MaxTotalGenerations != nil {
		policy.MaxTotalGenerations = *d.Retention.MaxTotalGenerations
	}
	if d.Retention.MinActiveRollbackGenerations != nil {
		policy.MinActiveRollbackGenerations = *d.Retention.MinActiveRollbackGenerations
	}
	if d.Retention.MaxClosedNeverActiveGenerations != nil {
		policy.MaxClosedNeverActiveGenerations = *d.Retention.MaxClosedNeverActiveGenerations
	}
	if d.Retention.MaxPurgeBatch != nil {
		policy.MaxPurgeBatch = *d.Retention.MaxPurgeBatch
	}
	if d.Retention.MaxRecoveryGenerations != nil {
		recovery.MaxGenerations = *d.Retention.MaxRecoveryGenerations
	}
	if d.Retention.RecoveryPageSize != nil {
		recovery.PageSize = *d.Retention.RecoveryPageSize
	}
	if d.Retention.MaxRecoveryReadBytes != nil {
		recovery.MaxReadBytes = *d.Retention.MaxRecoveryReadBytes
	}
	if policy.Validate() != nil || recovery.Validate() != nil {
		return nil, errInvalid
	}
	configuration := &Config{authorityID: d.AuthorityID, backend: d.Backend, deadline: deadline, limits: limits, roles: roles, retention: policy, recovery: recovery}
	if d.DNS.ResolverClass != "" || len(d.DNS.ResolverEndpoints) != 0 || d.DNS.ExportTTLSeconds != 0 || d.DNS.ProofLifetimeSeconds != 0 || d.DNS.LookupTimeout != "" {
		lookupTimeout, parseErr := time.ParseDuration(d.DNS.LookupTimeout)
		policy := datasourceadmin.DNSPolicy{ResolverClass: canonicalRecursiveResolver, ResolverEndpoints: append([]string(nil), d.DNS.ResolverEndpoints...), ExportTTLSeconds: d.DNS.ExportTTLSeconds, ProofLifetimeSeconds: d.DNS.ProofLifetimeSeconds}
		if parseErr != nil || lookupTimeout <= 0 || lookupTimeout > 30*time.Second || d.DNS.ResolverClass != explicitRecursiveResolver || datasourceadmin.ValidateDNSPolicy(policy) != nil {
			return nil, errInvalid
		}
		configuration.dns = dnsProofTransport{policy: policy, lookupTimeout: lookupTimeout}
	}
	if d.Backend == backendLDAP {
		transport := d.Transport.LDAP
		if transport.Address == "" && transport.ServerName == "" && transport.BaseDN == "" && transport.CAFile == "" {
			return configuration, nil
		}
		if transport.Address == "" || transport.ServerName == "" || transport.BaseDN == "" || !cleanAbsolute(transport.CAFile) {
			return nil, errInvalid
		}
		if _, err := loadRoots(transport.CAFile); err != nil {
			return nil, errInvalid
		}
		configuration.ldap = ldapTransport{address: transport.Address, serverName: transport.ServerName, baseDN: transport.BaseDN, caFile: transport.CAFile, startTLS: transport.StartTLS}
		return configuration, nil
	}
	transport := d.Transport.SQL
	if transport.Address == "" && transport.ServerName == "" && transport.Database == "" && transport.CAFile == "" && transport.ConnectTimeout == "" && transport.MaxConnections == 0 && transport.IdleConnections == 0 && transport.PageSize == 0 {
		return configuration, nil
	}
	connectTimeout, timeoutErr := time.ParseDuration(transport.ConnectTimeout)
	if transport.Address == "" || transport.ServerName == "" || transport.Database == "" || !cleanAbsolute(transport.CAFile) || timeoutErr != nil || connectTimeout <= 0 || connectTimeout > 30*time.Second || transport.MaxConnections < 1 || transport.MaxConnections > 4 || transport.IdleConnections < 0 || transport.IdleConnections > 2 || transport.IdleConnections > transport.MaxConnections || transport.PageSize < 1 || transport.PageSize > 256 {
		return nil, errInvalid
	}
	if _, err := loadRoots(transport.CAFile); err != nil {
		return nil, errInvalid
	}
	configuration.sql = sqlTransport{address: transport.Address, serverName: transport.ServerName, database: transport.Database, caFile: transport.CAFile, connectTimeout: connectTimeout, maxConnections: transport.MaxConnections, idleConnections: transport.IdleConnections, pageSize: transport.PageSize}
	return configuration, nil
}

// Backend returns the closed provider class without endpoint or credential material.
func (c *Config) Backend() string {
	if c == nil {
		return ""
	}
	return c.backend
}

// Deadline returns the finite whole-command deadline.
func (c *Config) Deadline() time.Duration {
	if c == nil {
		return 0
	}
	return c.deadline
}

// Limits returns the validated campaign scale bounds.
func (c *Config) Limits() Limits {
	if c == nil {
		return Limits{}
	}
	return c.limits
}

// Retention returns the validated finite purge policy and recovery bounds.
func (c *Config) Retention() (datasourceadmin.RetentionPolicy, datasourceadmin.RetentionRecoveryLimits) {
	if c == nil {
		return datasourceadmin.RetentionPolicy{}, datasourceadmin.RetentionRecoveryLimits{}
	}
	return c.retention, c.recovery
}

// Close clears retained protected configuration references.
func (c *Config) Close() error {
	if c == nil {
		return nil
	}
	c.authorityID, c.backend, c.deadline, c.limits = "", "", 0, Limits{}
	c.roles = [5]role{}
	c.ldap, c.sql, c.dns = ldapTransport{}, sqlTransport{}, dnsProofTransport{}
	c.retention, c.recovery = datasourceadmin.RetentionPolicy{}, datasourceadmin.RetentionRecoveryLimits{}
	return nil
}

// Authority constructs the exact four-role retention authority from one validated transport and live role identities.
func (c *Config) Authority(identities [4]string) (datasourceadmin.BackendClass, datasourceadmin.AuthorityDescriptor, error) {
	if c == nil || c.authorityID == "" || identities[0] == "" || identities[1] == "" || identities[2] == "" || identities[3] == "" {
		return "", datasourceadmin.AuthorityDescriptor{}, errInvalid
	}
	backend := datasourceadmin.BackendClass(c.backend)
	address, serverName, caFile := "", "", ""
	if backend == datasourceadmin.BackendLDAP {
		address, serverName, caFile = c.ldap.address, c.ldap.serverName, c.ldap.caFile
	} else {
		address, serverName, caFile = c.sql.address, c.sql.serverName, c.sql.caFile
	}
	host, portText, splitErr := net.SplitHostPort(address)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	trust, trustErr := authorityTrust(caFile)
	if splitErr != nil || portErr != nil || port == 0 || trustErr != nil {
		return "", datasourceadmin.AuthorityDescriptor{}, errInvalid
	}
	descriptor := datasourceadmin.AuthorityDescriptor{AuthorityID: c.authorityID, Endpoints: []datasourceadmin.AuthorityEndpoint{{Scheme: authorityScheme(backend), Host: host, Port: uint16(port), TLSServerName: serverName}}, TrustFingerprints: trust}
	if backend == datasourceadmin.BackendLDAP {
		descriptor.LDAP = &datasourceadmin.LDAPAuthority{BaseDN: c.ldap.baseDN, SnapshotPrincipal: identities[0], StagingPrincipal: identities[1], ActivationPrincipal: identities[2], PurgePrincipal: identities[3]}
	} else {
		schema := c.sql.database
		if backend == datasourceadmin.BackendPostgreSQL {
			schema = "dkim2_datasource"
		}
		descriptor.SQL = &datasourceadmin.SQLAuthority{Database: c.sql.database, Schema: schema, SnapshotRole: identities[0], StagingRole: identities[1], ActivationRole: identities[2], PurgeRole: identities[3]}
	}
	if datasourceadmin.ValidatePurgeAuthority(backend, descriptor) != nil {
		return "", datasourceadmin.AuthorityDescriptor{}, errInvalid
	}
	return backend, descriptor, nil
}

// authorityTrust derives exact certificate fingerprints rather than accepting a path as authority evidence.
func authorityTrust(path string) ([][sha256.Size]byte, error) {
	document, err := config.ReadProtectedDocument(path, maxTrustBundleBytes)
	if err != nil {
		return nil, errInvalid
	}
	defer clear(document)
	var result [][sha256.Size]byte
	for rest := document; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errInvalid
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, errInvalid
		}
		result = append(result, sha256.Sum256(certificate.Raw))
		rest = next
	}
	if len(result) == 0 {
		return nil, errInvalid
	}
	return result, nil
}

// authorityScheme maps the closed backend selector to its exact authority grammar.
func authorityScheme(backend datasourceadmin.BackendClass) string {
	switch backend {
	case datasourceadmin.BackendLDAP:
		return "ldaps"
	case datasourceadmin.BackendPostgreSQL:
		return "postgresql"
	case datasourceadmin.BackendMySQL:
		return "mysql"
	case datasourceadmin.BackendMariaDB:
		return "mariadb"
	default:
		return ""
	}
}

// DNSProofPolicy returns the explicitly configured proof-only recursive DNS
// authority. A missing policy deliberately leaves campaign mutation unavailable.
func (c *Config) DNSProofPolicy() (datasourceadmin.DNSPolicy, time.Duration, bool) {
	if c == nil || c.dns.lookupTimeout <= 0 || c.dns.policy.ResolverClass != canonicalRecursiveResolver || datasourceadmin.ValidateDNSPolicy(c.dns.policy) != nil {
		return datasourceadmin.DNSPolicy{}, 0, false
	}
	policy := datasourceadmin.DNSPolicy{ResolverClass: c.dns.policy.ResolverClass, ResolverEndpoints: append([]string(nil), c.dns.policy.ResolverEndpoints...), ExportTTLSeconds: c.dns.policy.ExportTTLSeconds, ProofLifetimeSeconds: c.dns.policy.ProofLifetimeSeconds}
	return policy, c.dns.lookupTimeout, true
}

// AuthorityPaths returns the four distinct publication and purge credential paths in fixed role order.
func (c *Config) AuthorityPaths() [4]string {
	if c == nil {
		return [4]string{}
	}
	return [4]string{c.roles[0].secretPath, c.roles[1].secretPath, c.roles[2].secretPath, c.roles[3].secretPath}
}

// ClosurePath returns the fifth distinct protected credential used only for
// immutable terminal campaign records.
func (c *Config) ClosurePath() string {
	if c == nil {
		return ""
	}
	return c.roles[4].secretPath
}

// LDAPTransport returns the validated LDAP descriptor without credential material.
func (c *Config) LDAPTransport() (address, serverName, baseDN, caFile string, startTLS bool, ok bool) {
	if c == nil || c.backend != backendLDAP || c.ldap.address == "" {
		return "", "", "", "", false, false
	}
	return c.ldap.address, c.ldap.serverName, c.ldap.baseDN, c.ldap.caFile, c.ldap.startTLS, true
}

// SQLTransport returns the validated SQL descriptor without credential material.
func (c *Config) SQLTransport() (address, serverName, database, caFile string, timeout time.Duration, maxConnections, idleConnections, pageSize int, ok bool) {
	if c == nil || c.backend == backendLDAP || c.sql.address == "" {
		return "", "", "", "", 0, 0, 0, 0, false
	}
	return c.sql.address, c.sql.serverName, c.sql.database, c.sql.caFile, c.sql.connectTimeout, c.sql.maxConnections, c.sql.idleConnections, c.sql.pageSize, true
}

// LoadTrustRoots reads one strict PEM CA bundle for a real provider constructor.
func LoadTrustRoots(path string) (*x509.CertPool, error) { return loadRoots(path) }

// loadRoots accepts only a protected nonempty CA PEM bundle.
func loadRoots(path string) (*x509.CertPool, error) {
	document, err := config.ReadProtectedDocument(path, maxTrustBundleBytes)
	if err != nil || len(document) == 0 {
		clear(document)
		return nil, errInvalid
	}
	defer clear(document)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(document) {
		return nil, errInvalid
	}
	return roots, nil
}

// validateConfigYAML rejects aliases, duplicate keys, and non-scalar environment expansion inputs.
func validateConfigYAML(document []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(document, &node); err != nil || len(node.Content) != 1 {
		return errInvalid
	}
	return validateNode(node.Content[0])
}

// validateNode recursively rejects YAML features that obscure the protected schema.
func validateNode(node *yaml.Node) error {
	if node.Alias != nil || node.Kind == yaml.AliasNode || node.Tag == "!!map" && len(node.Content)%2 != 0 {
		return errInvalid
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return errInvalid
			}
			if _, exists := seen[key.Value]; exists {
				return errInvalid
			}
			seen[key.Value] = struct{}{}
			if err := validateNode(node.Content[index+1]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateNode(child); err != nil {
			return err
		}
	}
	return nil
}

// cleanAbsolute accepts exactly one canonical absolute local path.
func cleanAbsolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

// knownBackend accepts only the four native v3 backend classes.
func knownBackend(value string) bool {
	return value == backendLDAP || value == "postgresql" || value == "mysql" || value == "mariadb"
}

// validRoleName accepts a bounded nonidentity role class.
func validRoleName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return value == strings.ToLower(value)
}
