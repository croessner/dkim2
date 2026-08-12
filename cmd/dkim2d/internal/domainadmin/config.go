package domainadmin

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"gopkg.in/yaml.v3"
)

const adminConfigVersion = "dkim2-domain-admin-v1"

// adminRoleDocument names one exact least-privilege principal and protected secret file.
type adminRoleDocument struct {
	Principal    string `yaml:"principal,omitempty"`
	Role         string `yaml:"role,omitempty"`
	PasswordFile string `yaml:"password_file"`
}

// adminLDAPDocument owns the three distinct LDAP administrative authorities.
type adminLDAPDocument struct {
	BaseDN     string            `yaml:"base_dn"`
	Snapshot   adminRoleDocument `yaml:"snapshot"`
	Staging    adminRoleDocument `yaml:"staging"`
	Activation adminRoleDocument `yaml:"activation"`
}

// adminSQLDocument owns the three distinct SQL administrative roles.
type adminSQLDocument struct {
	Database   string            `yaml:"database"`
	Schema     string            `yaml:"schema"`
	Snapshot   adminRoleDocument `yaml:"snapshot"`
	Staging    adminRoleDocument `yaml:"staging"`
	Activation adminRoleDocument `yaml:"activation"`
}

// adminEndpointDocument is one direct verified-TLS authority.
type adminEndpointDocument struct {
	Address    string `yaml:"address"`
	ServerName string `yaml:"server_name"`
	CAFile     string `yaml:"ca_file"`
}

// adminDNSDocument binds export and fresh recursive-resolver proof policy.
type adminDNSDocument struct {
	ResolverClass        string   `yaml:"resolver_class"`
	ResolverEndpoints    []string `yaml:"resolver_endpoints"`
	ExportTTLSeconds     uint64   `yaml:"export_ttl_seconds"`
	ProofLifetimeSeconds uint64   `yaml:"proof_lifetime_seconds"`
}

// adminConfigDocument is the closed protected YAML schema.
type adminConfigDocument struct {
	Version      string                `yaml:"version"`
	AuthorityID  string                `yaml:"authority_id"`
	Backend      string                `yaml:"backend"`
	DeadlineText string                `yaml:"deadline"`
	Endpoint     adminEndpointDocument `yaml:"endpoint"`
	DNS          adminDNSDocument      `yaml:"dns"`
	LDAP         *adminLDAPDocument    `yaml:"ldap,omitempty"`
	SQL          *adminSQLDocument     `yaml:"sql,omitempty"`
}

// AdminRoleMaterial owns one detached protected connector authority.
type AdminRoleMaterial struct {
	Identity string
	Password []byte
}

// String returns a constant protected role representation.
func (AdminRoleMaterial) String() string { return redacted }

// GoString returns a constant protected role representation.
func (AdminRoleMaterial) GoString() string { return redacted }

// Format prevents a nested role identity or credential from reaching formatting sinks.
func (AdminRoleMaterial) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic serialization of a nested protected role.
func (AdminRoleMaterial) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// AdminConnectionMaterial is one callback-bounded detached provider construction input.
type AdminConnectionMaterial struct {
	Backend    datasourceadmin.BackendClass
	Address    string
	ServerName string
	BaseDN     string
	Database   string
	Schema     string
	RootCAs    *x509.CertPool
	Deadline   time.Duration
	Snapshot   AdminRoleMaterial
	Staging    AdminRoleMaterial
	Activation AdminRoleMaterial
}

// Close clears every detached credential and releases public construction facts.
func (m *AdminConnectionMaterial) Close() error {
	if m == nil {
		return nil
	}
	clear(m.Snapshot.Password)
	clear(m.Staging.Password)
	clear(m.Activation.Password)
	*m = AdminConnectionMaterial{}
	return nil
}

// String returns a constant protected material representation.
func (AdminConnectionMaterial) String() string { return redacted }

// GoString returns a constant protected material representation.
func (AdminConnectionMaterial) GoString() string { return redacted }

// Format prevents provider identities or credentials from reaching formatting sinks.
func (AdminConnectionMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redacted)
}

// MarshalJSON rejects generic serialization of provider construction material.
func (AdminConnectionMaterial) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeProtectedInput)
}

// AdminConfig owns one immutable protected offline authority generation.
type AdminConfig struct {
	backend    datasourceadmin.BackendClass
	authority  datasourceadmin.AuthorityDescriptor
	dns        datasourceadmin.DNSPolicy
	limits     Limits
	generation datasourceadmin.GenerationLimits
	material   AdminConnectionMaterial
	childPaths []string
}

// LoadAdminConfig reads the complete owner-only configuration and credential generation.
func LoadAdminConfig(path string) (*AdminConfig, error) {
	if !cleanAbsolutePath(path) {
		return nil, newError(CodeProtectedInput)
	}
	document, err := config.ReadProtectedDocument(path, int(DefaultLimits().MaxDocumentBytes))
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	defer clear(document)
	if validateAdminYAML(document) != nil {
		return nil, newError(CodeProtectedInput)
	}
	expanded, err := config.ExpandYAMLScalarPlaceholders(document)
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	defer clear(expanded)
	if validateAdminYAML(expanded) != nil {
		return nil, newError(CodeProtectedInput)
	}
	var decoded adminConfigDocument
	decoder := yaml.NewDecoder(bytes.NewReader(expanded))
	decoder.KnownFields(true)
	if decoder.Decode(&decoded) != nil {
		return nil, newError(CodeProtectedInput)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, newError(CodeProtectedInput)
	}
	return decoded.load(path)
}

// load validates and opens every exact protected child before publishing an immutable owner.
func (d adminConfigDocument) load(configPath string) (*AdminConfig, error) {
	backend := datasourceadmin.BackendClass(d.Backend)
	if d.Version != adminConfigVersion || !validAuthorityID(d.AuthorityID) ||
		!knownAdminBackend(backend) || !validAdminEndpoint(d.Endpoint) {
		return nil, newError(CodeProtectedInput)
	}
	deadline, err := time.ParseDuration(d.DeadlineText)
	if err != nil || deadline <= 0 || deadline > DefaultLimits().BackendDeadline {
		return nil, newError(CodeInvalidLimits)
	}
	dns := datasourceadmin.DNSPolicy{
		ResolverClass: d.DNS.ResolverClass, ResolverEndpoints: slices.Clone(d.DNS.ResolverEndpoints),
		ExportTTLSeconds: d.DNS.ExportTTLSeconds, ProofLifetimeSeconds: d.DNS.ProofLifetimeSeconds,
	}
	if datasourceadmin.ValidateDNSPolicy(dns) != nil ||
		time.Duration(dns.ProofLifetimeSeconds)*time.Second > DefaultLimits().DNSProofLifetime {
		return nil, newError(CodeInvalidLimits)
	}
	roles, ldapAuthority, sqlAuthority, err := d.validateRoles(backend)
	if err != nil {
		return nil, err
	}
	childPaths := []string{d.Endpoint.CAFile, roles[0].PasswordFile, roles[1].PasswordFile, roles[2].PasswordFile}
	if !validAdminChildPaths(configPath, childPaths) {
		return nil, newError(CodeProtectedInput)
	}
	rootCAs, fingerprints, err := loadAdminTrust(d.Endpoint.CAFile)
	if err != nil {
		return nil, err
	}
	passwords := make([][]byte, 3)
	for index, role := range roles {
		passwords[index], err = loadAdminSecret(role.PasswordFile)
		if err != nil {
			clearAdminSecrets(passwords)
			return nil, err
		}
	}
	if equalAdminSecret(passwords[0], passwords[1]) || equalAdminSecret(passwords[0], passwords[2]) ||
		equalAdminSecret(passwords[1], passwords[2]) {
		clearAdminSecrets(passwords)
		return nil, newError(CodeProtectedInput)
	}
	host, portText, _ := net.SplitHostPort(d.Endpoint.Address)
	port, _ := strconv.ParseUint(portText, 10, 16)
	authority := datasourceadmin.AuthorityDescriptor{
		AuthorityID: d.AuthorityID,
		Endpoints: []datasourceadmin.AuthorityEndpoint{{
			Scheme: adminScheme(backend), Host: host, Port: uint16(port), TLSServerName: d.Endpoint.ServerName,
		}},
		LDAP: ldapAuthority, SQL: sqlAuthority, TrustFingerprints: fingerprints,
	}
	if datasourceadmin.ValidateAuthority(backend, authority) != nil {
		clearAdminSecrets(passwords)
		return nil, newError(CodeProtectedInput)
	}
	limits := DefaultLimits()
	limits.BackendDeadline = deadline
	return &AdminConfig{
		backend: backend, authority: authority, dns: dns, limits: limits,
		generation: datasourceadmin.GenerationLimits{
			MaxGenerations: limits.MaxGenerations, MaxOutstandingCandidates: limits.MaxOutstandingCandidates,
			MaxSnapshotRows: limits.MaxSnapshotRows, MaxSnapshotBytes: limits.MaxSnapshotBytes,
			BackendDeadline: deadline,
		},
		material: AdminConnectionMaterial{
			Backend: backend, Address: d.Endpoint.Address, ServerName: d.Endpoint.ServerName,
			BaseDN: ldapBase(d.LDAP), Database: sqlDatabase(d.SQL), Schema: sqlSchema(d.SQL),
			RootCAs: rootCAs, Deadline: deadline,
			Snapshot:   AdminRoleMaterial{Identity: roleIdentity(roles[0]), Password: passwords[0]},
			Staging:    AdminRoleMaterial{Identity: roleIdentity(roles[1]), Password: passwords[1]},
			Activation: AdminRoleMaterial{Identity: roleIdentity(roles[2]), Password: passwords[2]},
		},
		childPaths: slices.Clone(childPaths),
	}, nil
}

// validateRoles enforces one provider-conditioned three-authority schema.
func (d adminConfigDocument) validateRoles(
	backend datasourceadmin.BackendClass,
) ([]adminRoleDocument, *datasourceadmin.LDAPAuthority, *datasourceadmin.SQLAuthority, error) {
	if backend == datasourceadmin.BackendLDAP {
		if d.LDAP == nil || d.SQL != nil || !validLDAPBase(d.LDAP.BaseDN) {
			return nil, nil, nil, newError(CodeProtectedInput)
		}
		roles := []adminRoleDocument{d.LDAP.Snapshot, d.LDAP.Staging, d.LDAP.Activation}
		for _, role := range roles {
			if role.Role != "" || !validLDAPAdminPrincipal(role.Principal) {
				return nil, nil, nil, newError(CodeProtectedInput)
			}
		}
		if !distinctRoleDocuments(roles) {
			return nil, nil, nil, newError(CodeProtectedInput)
		}
		return roles, &datasourceadmin.LDAPAuthority{
			BaseDN: d.LDAP.BaseDN, SnapshotPrincipal: roles[0].Principal,
			StagingPrincipal: roles[1].Principal, ActivationPrincipal: roles[2].Principal,
		}, nil, nil
	}
	if d.SQL == nil || d.LDAP != nil || !validSQLIdentity(d.SQL.Database) || !validSQLIdentity(d.SQL.Schema) {
		return nil, nil, nil, newError(CodeProtectedInput)
	}
	if backend == datasourceadmin.BackendPostgreSQL && d.SQL.Schema != "dkim2_datasource" ||
		(backend == datasourceadmin.BackendMySQL || backend == datasourceadmin.BackendMariaDB) && d.SQL.Schema != d.SQL.Database {
		return nil, nil, nil, newError(CodeProtectedInput)
	}
	roles := []adminRoleDocument{d.SQL.Snapshot, d.SQL.Staging, d.SQL.Activation}
	for _, role := range roles {
		if role.Principal != "" || !validSQLIdentity(role.Role) || strings.EqualFold(role.Role, "dkim2_publisher") {
			return nil, nil, nil, newError(CodeProtectedInput)
		}
	}
	if !distinctRoleDocuments(roles) {
		return nil, nil, nil, newError(CodeProtectedInput)
	}
	return roles, nil, &datasourceadmin.SQLAuthority{
		Database: d.SQL.Database, Schema: d.SQL.Schema, SnapshotRole: roles[0].Role,
		StagingRole: roles[1].Role, ActivationRole: roles[2].Role,
	}, nil
}

// Backend returns the closed provider class without connection facts.
func (c *AdminConfig) Backend() datasourceadmin.BackendClass {
	if c == nil {
		return ""
	}
	return c.backend
}

// Authority returns a detached protected descriptor for exact journal binding.
func (c *AdminConfig) Authority() datasourceadmin.AuthorityDescriptor {
	if c == nil {
		return datasourceadmin.AuthorityDescriptor{}
	}
	return cloneAuthority(c.authority)
}

// DNSPolicy returns one detached fresh recursive-resolver proof policy.
func (c *AdminConfig) DNSPolicy() datasourceadmin.DNSPolicy {
	if c == nil {
		return datasourceadmin.DNSPolicy{}
	}
	return cloneDNSPolicy(c.dns)
}

// Limits returns finite operation bounds derived from the protected document.
func (c *AdminConfig) Limits() Limits {
	if c == nil {
		return Limits{}
	}
	return c.limits
}

// GenerationLimits returns finite provider inventory and snapshot bounds.
func (c *AdminConfig) GenerationLimits() datasourceadmin.GenerationLimits {
	if c == nil {
		return datasourceadmin.GenerationLimits{}
	}
	return c.generation
}

// ValidateCommandRequest rejects command artifacts that overlap protected authority children.
func (c *AdminConfig) ValidateCommandRequest(request CommandRequest) error {
	if c == nil || request.Validate() != nil || len(c.childPaths) != 4 {
		return newError(CodeProtectedInput)
	}
	requestPaths := []string{request.ConfigPath, request.OperationPath}
	if request.IntentPath != "" {
		requestPaths = append(requestPaths, request.IntentPath)
	}
	if request.OutputPath != "" {
		requestPaths = append(requestPaths, request.OutputPath)
	}
	for _, requestPath := range requestPaths {
		for _, childPath := range c.childPaths {
			if pathsOverlap(requestPath, childPath) {
				return newError(CodeProtectedInput)
			}
		}
	}
	return nil
}

// WithConnectionMaterial lends one detached secret owner only for offline provider construction.
func (c *AdminConfig) WithConnectionMaterial(callback func(*AdminConnectionMaterial) error) error {
	if c == nil || callback == nil || c.material.RootCAs == nil {
		return newError(CodeProtectedInput)
	}
	material := c.material
	material.RootCAs = c.material.RootCAs.Clone()
	material.Snapshot.Password = slices.Clone(c.material.Snapshot.Password)
	material.Staging.Password = slices.Clone(c.material.Staging.Password)
	material.Activation.Password = slices.Clone(c.material.Activation.Password)
	defer material.Close() //nolint:errcheck // Clearing callback-owned copies is unconditional.
	return callback(&material)
}

// Close clears every retained credential and descriptor identity.
func (c *AdminConfig) Close() error {
	if c == nil {
		return nil
	}
	_ = c.material.Close()
	c.authority = datasourceadmin.AuthorityDescriptor{}
	c.dns = datasourceadmin.DNSPolicy{}
	c.backend = ""
	c.childPaths = nil
	return nil
}

// String returns a constant protected configuration summary.
func (AdminConfig) String() string { return redacted }

// GoString returns a constant protected configuration representation.
func (AdminConfig) GoString() string { return redacted }

// Format prevents configuration identities and secrets from reaching formatting sinks.
func (AdminConfig) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic serialization of protected administration configuration.
func (AdminConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// validAuthorityID accepts exactly one canonical lower-base32 128-bit identity.
func validAuthorityID(value string) bool {
	if len(value) != 26 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(value))
	combined := byte(0)
	for _, octet := range decoded {
		combined |= octet
	}
	valid := err == nil && len(decoded) == 16 && combined != 0 &&
		strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded)) == value
	clear(decoded)
	return valid
}

// equalAdminSecret compares protected role credentials without content-dependent early exit.
func equalAdminSecret(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

// knownAdminBackend accepts only providers with native v3 administration.
func knownAdminBackend(backend datasourceadmin.BackendClass) bool {
	return backend == datasourceadmin.BackendLDAP || backend == datasourceadmin.BackendPostgreSQL ||
		backend == datasourceadmin.BackendMySQL || backend == datasourceadmin.BackendMariaDB
}

// validAdminEndpoint rejects indirect, noncanonical, or unverifiable endpoint syntax.
func validAdminEndpoint(endpoint adminEndpointDocument) bool {
	host, port, err := net.SplitHostPort(endpoint.Address)
	number, numberErr := strconv.ParseUint(port, 10, 16)
	if err != nil || numberErr != nil || number == 0 || strconv.FormatUint(number, 10) != port ||
		host == "" || host != strings.ToLower(host) || endpoint.ServerName == "" ||
		endpoint.ServerName != strings.ToLower(endpoint.ServerName) || endpoint.CAFile == "" {
		return false
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		return address.String() == host && !address.IsUnspecified() && !address.IsMulticast()
	}
	return validLDHName(host) && validLDHName(endpoint.ServerName)
}

// validAdminChildPaths requires protected siblings and forbids path or inode-role reuse by name.
func validAdminChildPaths(configPath string, paths []string) bool {
	seen := map[string]struct{}{configPath: {}}
	base := filepath.Dir(configPath)
	for _, path := range paths {
		if !cleanAbsolutePath(path) || filepath.Dir(path) != base {
			return false
		}
		if _, duplicate := seen[path]; duplicate {
			return false
		}
		seen[path] = struct{}{}
	}
	return true
}

// loadAdminTrust parses only a bounded protected CA certificate bundle and derives ordered fingerprints.
func loadAdminTrust(path string) (*x509.CertPool, [][sha256.Size]byte, error) {
	document, err := config.ReadProtectedDocument(path, int(DefaultLimits().MaxDocumentBytes))
	if err != nil {
		return nil, nil, newError(CodeProtectedInput)
	}
	defer clear(document)
	pool := x509.NewCertPool()
	fingerprints := make([][sha256.Size]byte, 0, 8)
	remainder := document
	for len(remainder) > 0 {
		block, rest := pem.Decode(remainder)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(fingerprints) >= 128 {
			return nil, nil, newError(CodeProtectedInput)
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !certificate.IsCA {
			return nil, nil, newError(CodeProtectedInput)
		}
		pool.AddCert(certificate)
		fingerprints = append(fingerprints, sha256.Sum256(certificate.Raw))
		remainder = bytes.TrimSpace(rest)
	}
	if len(fingerprints) == 0 {
		return nil, nil, newError(CodeProtectedInput)
	}
	slices.SortFunc(fingerprints, func(left, right [sha256.Size]byte) int {
		return bytes.Compare(left[:], right[:])
	})
	for index := 1; index < len(fingerprints); index++ {
		if fingerprints[index] == fingerprints[index-1] {
			return nil, nil, newError(CodeProtectedInput)
		}
	}
	return pool, fingerprints, nil
}

// loadAdminSecret reads one bounded nonempty credential without retaining line terminators.
func loadAdminSecret(path string) ([]byte, error) {
	secret, err := config.ReadProtectedDocument(path, 16<<10)
	if err != nil {
		return nil, newError(CodeProtectedInput)
	}
	secret = bytes.TrimSuffix(secret, []byte("\n"))
	secret = bytes.TrimSuffix(secret, []byte("\r"))
	if len(secret) == 0 || bytes.ContainsAny(secret, "\x00\r\n") {
		clear(secret)
		return nil, newError(CodeProtectedInput)
	}
	return secret, nil
}

// clearAdminSecrets clears a partially loaded credential set.
func clearAdminSecrets(values [][]byte) {
	for _, value := range values {
		clear(value)
	}
}

// distinctRoleDocuments rejects reused identities and reused protected credentials.
func distinctRoleDocuments(roles []adminRoleDocument) bool {
	identities := make(map[string]struct{}, len(roles))
	passwords := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		identity := roleIdentity(role)
		if identity == "" || role.PasswordFile == "" {
			return false
		}
		if _, exists := identities[identity]; exists {
			return false
		}
		if _, exists := passwords[role.PasswordFile]; exists {
			return false
		}
		identities[identity] = struct{}{}
		passwords[role.PasswordFile] = struct{}{}
	}
	return true
}

// roleIdentity returns the provider-conditioned principal or role.
func roleIdentity(role adminRoleDocument) string {
	if role.Principal != "" {
		return role.Principal
	}
	return role.Role
}

// validLDAPAdminPrincipal enforces the closed canonical service-DN grammar.
func validLDAPAdminPrincipal(value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) < 4 {
		return false
	}
	ouCount, dcCount := 0, 0
	for index, part := range parts {
		attribute, label, present := strings.Cut(part, "=")
		if !present || !validLDHLabel(label) {
			return false
		}
		switch {
		case index == 0 && attribute == "cn":
		case dcCount == 0 && attribute == "ou":
			ouCount++
		case ouCount > 0 && attribute == "dc":
			dcCount++
		default:
			return false
		}
	}
	return ouCount > 0 && dcCount > 0
}

// validLDAPBase accepts one canonical OU followed by one or more DC labels.
func validLDAPBase(value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) < 2 {
		return false
	}
	for index, part := range parts {
		attribute, label, present := strings.Cut(part, "=")
		if !present || !validLDHLabel(label) || index == 0 && attribute != "ou" || index > 0 && attribute != "dc" {
			return false
		}
	}
	return true
}

// validSQLIdentity accepts one bounded ASCII SQL database, schema, or role name.
func validSQLIdentity(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' || index > 0 && character == '_' {
			continue
		}
		return false
	}
	return true
}

// validLDHName accepts one lower-case bounded DNS name.
func validLDHName(value string) bool {
	if len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !validLDHLabel(label) {
			return false
		}
	}
	return true
}

// validLDHLabel accepts one canonical lower-case letter-digit-hyphen label.
func validLDHLabel(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// adminScheme returns the canonical provider descriptor scheme.
func adminScheme(backend datasourceadmin.BackendClass) string {
	switch backend {
	case datasourceadmin.BackendLDAP:
		return "ldaps"
	case datasourceadmin.BackendPostgreSQL:
		return string(datasourceadmin.BackendPostgreSQL)
	case datasourceadmin.BackendMySQL:
		return string(datasourceadmin.BackendMySQL)
	case datasourceadmin.BackendMariaDB:
		return string(datasourceadmin.BackendMariaDB)
	default:
		return ""
	}
}

// ldapBase returns the configured provider base without accepting a mixed provider document.
func ldapBase(document *adminLDAPDocument) string {
	if document == nil {
		return ""
	}
	return document.BaseDN
}

// sqlDatabase returns the configured SQL database without accepting a mixed provider document.
func sqlDatabase(document *adminSQLDocument) string {
	if document == nil {
		return ""
	}
	return document.Database
}

// sqlSchema returns the configured SQL schema without accepting a mixed provider document.
func sqlSchema(document *adminSQLDocument) string {
	if document == nil {
		return ""
	}
	return document.Schema
}

// validateAdminYAML rejects aliases, anchors, merge keys, and excessive configuration trees.
func validateAdminYAML(document []byte) error {
	return validateProtectedYAMLTree(document, 256, CodeProtectedInput)
}
