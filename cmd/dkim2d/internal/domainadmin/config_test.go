package domainadmin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	protectedconfig "github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"gopkg.in/yaml.v3"
)

const (
	testBackendLDAP       = "ldap"
	testBackendPostgreSQL = "postgresql"
	testBackendMySQL      = "mysql"
	testBackendMariaDB    = "mariadb"
	testAuthorityIDLine   = "authority_id: aaaaaaaaaaaaaaaaaaaaaaaaae"
	testSnapshotRoleLine  = "role: dkim2_snapshot"
	testStagingRoleLine   = "role: dkim2_stager"
	testOtherSchemaLine   = "schema: other_schema"
	testLDAPServerName    = "ldap.example.test"
)

// TestLoadAdminConfigAcceptsExactFourBackendMatrix freezes the protected typed authority surface.
func TestLoadAdminConfigAcceptsExactFourBackendMatrix(t *testing.T) {
	if !validAuthorityID("aaaaaaaaaaaaaaaaaaaaaaaaae") {
		t.Fatal("canonical test authority identifier is invalid")
	}
	for _, backend := range []string{testBackendLDAP, testBackendPostgreSQL, testBackendMySQL, testBackendMariaDB} {
		t.Run(backend, func(t *testing.T) {
			path, _ := writeAdminConfigFixture(t, backend)
			loaded, err := LoadAdminConfig(path)
			if err != nil || loaded == nil {
				t.Fatalf("valid protected backend authority was rejected: %s stage=%s", CodeOf(err), diagnoseAdminConfig(path))
			}
			defer loaded.Close() //nolint:errcheck // Test cleanup has no recovery action.
			if string(loaded.Backend()) != backend || loaded.Authority().AuthorityID != "aaaaaaaaaaaaaaaaaaaaaaaaae" {
				t.Fatal("typed backend authority was not retained")
			}
		})
	}
}

// TestAdminRoleMaterialRejectsNestedFormattingAndJSON proves protected nested values stay opaque.
func TestAdminRoleMaterialRejectsNestedFormattingAndJSON(t *testing.T) {
	role := AdminRoleMaterial{Identity: "toxic-principal", Password: []byte("toxic-password")}
	for _, rendered := range []string{fmt.Sprint(role), fmt.Sprintf("%+v", role), fmt.Sprintf("%#v", role)} {
		if strings.Contains(rendered, "toxic") || rendered != redacted {
			t.Fatal("nested administration role reached a formatting sink")
		}
	}
	if encoded, err := json.Marshal(role); err == nil || len(encoded) != 0 {
		t.Fatal("nested administration role reached JSON")
	}
}

// diagnoseAdminConfig returns a test-only bounded validation stage without protected values.
func diagnoseAdminConfig(path string) string {
	document, err := protectedconfig.ReadProtectedDocument(path, int(DefaultLimits().MaxDocumentBytes))
	if err != nil {
		return "read"
	}
	defer clear(document)
	if validateAdminYAML(document) != nil {
		return "yaml-tree"
	}
	var decoded adminConfigDocument
	decoder := yaml.NewDecoder(bytes.NewReader(document))
	decoder.KnownFields(true)
	if decoder.Decode(&decoded) != nil {
		return "decode"
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return "trailing"
	}
	backend := datasourceadmin.BackendClass(decoded.Backend)
	if decoded.Version != adminConfigVersion || !validAuthorityID(decoded.AuthorityID) || !knownAdminBackend(backend) || !validAdminEndpoint(decoded.Endpoint) {
		return "header"
	}
	if _, err := time.ParseDuration(decoded.DeadlineText); err != nil {
		return "deadline"
	}
	if datasourceadmin.ValidateDNSPolicy(datasourceadmin.DNSPolicy{ResolverClass: decoded.DNS.ResolverClass, ResolverEndpoints: decoded.DNS.ResolverEndpoints, ExportTTLSeconds: decoded.DNS.ExportTTLSeconds, ProofLifetimeSeconds: decoded.DNS.ProofLifetimeSeconds}) != nil {
		return "dns"
	}
	roles, _, _, err := decoded.validateRoles(backend)
	if err != nil {
		return "roles"
	}
	paths := []string{decoded.Endpoint.CAFile, roles[0].PasswordFile, roles[1].PasswordFile, roles[2].PasswordFile}
	if !validAdminChildPaths(path, paths) {
		return "paths"
	}
	if _, _, err := loadAdminTrust(decoded.Endpoint.CAFile); err != nil {
		return "trust"
	}
	for _, role := range roles {
		value, err := loadAdminSecret(role.PasswordFile)
		if err != nil {
			return "secret"
		}
		clear(value)
	}
	return "authority"
}

// TestLoadAdminConfigRejectsOneFieldAuthorityViolations proves closed identity and least privilege.
func TestLoadAdminConfigRejectsOneFieldAuthorityViolations(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		old     string
		new     string
	}{
		{"authority-id-case", testBackendLDAP, testAuthorityIDLine, "authority_id: AAAAAAAAAAAAAAAAAAAAAAAAAE"},
		{"authority-id-zero", testBackendLDAP, testAuthorityIDLine, "authority_id: aaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"ldap-role-reuse", testBackendLDAP, "cn=stager,ou=services,dc=example,dc=test", "cn=snapshot,ou=services,dc=example,dc=test"},
		{"ldap-overbroad", testBackendLDAP, "cn=activator,ou=services,dc=example,dc=test", "cn=admin,dc=example,dc=test"},
		{"postgres-role-reuse", testBackendPostgreSQL, testStagingRoleLine, testSnapshotRoleLine},
		{"mysql-role-reuse", testBackendMySQL, testStagingRoleLine, testSnapshotRoleLine},
		{"mariadb-role-reuse", testBackendMariaDB, testStagingRoleLine, testSnapshotRoleLine},
		{"legacy-publisher", testBackendPostgreSQL, "role: dkim2_activator", "role: dkim2_publisher"},
		{"postgres-schema", testBackendPostgreSQL, "schema: dkim2_datasource", testOtherSchemaLine},
		{"mysql-schema", testBackendMySQL, "schema: dkim2", testOtherSchemaLine},
		{"mariadb-schema", testBackendMariaDB, "schema: dkim2", testOtherSchemaLine},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, document := writeAdminConfigFixture(t, test.backend)
			changed := strings.Replace(string(document), test.old, test.new, 1)
			if changed == string(document) || os.WriteFile(path, []byte(changed), 0o600) != nil {
				t.Fatal("failed to make exact invalid configuration fixture")
			}
			if loaded, err := LoadAdminConfig(path); err == nil || loaded != nil {
				t.Fatal("one-field authority violation was accepted")
			}
		})
	}
}

// TestLoadAdminConfigRejectsEqualCredentialBytes proves path aliases cannot fake authority separation.
func TestLoadAdminConfigRejectsEqualCredentialBytes(t *testing.T) {
	path, _ := writeAdminConfigFixture(t, testBackendLDAP)
	directory := filepath.Dir(path)
	snapshot, err := os.ReadFile(filepath.Join(directory, "snapshot.password"))
	if err != nil || os.WriteFile(filepath.Join(directory, "staging.password"), snapshot, 0o600) != nil {
		t.Fatal("prepare equal protected credential fixture")
	}
	clear(snapshot)
	if loaded, err := LoadAdminConfig(path); err == nil || loaded != nil {
		t.Fatal("equal credential bytes under distinct paths were accepted")
	}
}

// TestLoadAdminConfigExpandsOnlyScalarValues freezes one-pass fail-closed environment expansion.
func TestLoadAdminConfigExpandsOnlyScalarValues(t *testing.T) {
	path, document := writeAdminConfigFixture(t, testBackendLDAP)
	t.Setenv("DKIM2_TEST_ADMIN_ADDRESS", "192.0.2.12:636")
	expanded := strings.Replace(string(document), "192.0.2.10:636", "${DKIM2_TEST_ADMIN_ADDRESS}", 1)
	if os.WriteFile(path, []byte(expanded), 0o600) != nil {
		t.Fatal("write scalar placeholder fixture")
	}
	loaded, err := LoadAdminConfig(path)
	if err != nil || loaded == nil || loaded.Authority().Endpoints[0].Host != "192.0.2.12" {
		t.Fatal("scalar value placeholder was not expanded before typed validation")
	}
	_ = loaded.Close()

	t.Setenv("DKIM2_TEST_ADMIN_TTL", "600")
	numeric := strings.Replace(string(document), "export_ttl_seconds: 300", "export_ttl_seconds: ${DKIM2_TEST_ADMIN_TTL}", 1)
	if os.WriteFile(path, []byte(numeric), 0o600) != nil {
		t.Fatal("write numeric scalar placeholder fixture")
	}
	loaded, err = LoadAdminConfig(path)
	if err != nil || loaded == nil || loaded.DNSPolicy().ExportTTLSeconds != 600 {
		t.Fatal("plain whole placeholder was not resolved through typed numeric validation")
	}
	_ = loaded.Close()

	quotedNumeric := strings.Replace(string(document), "export_ttl_seconds: 300", "export_ttl_seconds: \"${DKIM2_TEST_ADMIN_TTL}\"", 1)
	if os.WriteFile(path, []byte(quotedNumeric), 0o600) != nil {
		t.Fatal("write quoted numeric placeholder fixture")
	}
	if value, quotedErr := LoadAdminConfig(path); quotedErr == nil || value != nil {
		t.Fatal("quoted placeholder was weakly converted into a numeric scalar")
	}

	missing := strings.Replace(string(document), "192.0.2.10:636", "${DKIM2_TEST_MISSING}", 1)
	if os.WriteFile(path, []byte(missing), 0o600) != nil {
		t.Fatal("write missing placeholder fixture")
	}
	if value, missingErr := LoadAdminConfig(path); missingErr == nil || value != nil {
		t.Fatal("missing scalar placeholder did not fail closed")
	}

	t.Setenv("DKIM2_TEST_ADMIN_KEY", "backend")
	mapKey := strings.Replace(string(document), "backend:", "${DKIM2_TEST_ADMIN_KEY}:", 1)
	if os.WriteFile(path, []byte(mapKey), 0o600) != nil {
		t.Fatal("write map-key placeholder fixture")
	}
	if value, mapKeyErr := LoadAdminConfig(path); mapKeyErr == nil || value != nil {
		t.Fatal("map-key placeholder was expanded")
	}

	dsn := strings.Replace(string(document), "backend: ldap", "backend: ldap\ndsn: ${DKIM2_TEST_ADMIN_ADDRESS}", 1)
	if os.WriteFile(path, []byte(dsn), 0o600) != nil {
		t.Fatal("write forbidden DSN fixture")
	}
	if value, dsnErr := LoadAdminConfig(path); dsnErr == nil || value != nil {
		t.Fatal("schema-free DSN entered protected provider configuration")
	}
}

// TestAdminAuthorityDescriptorBindsEveryProviderIdentityField proves substitution sensitivity.
func TestAdminAuthorityDescriptorBindsEveryProviderIdentityField(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		old     string
		new     string
	}{
		{"endpoint", testBackendLDAP, "192.0.2.10:636", "192.0.2.11:636"},
		{"authority-id", testBackendLDAP, testAuthorityIDLine, "authority_id: aaaaaaaaaaaaaaaaaaaaaaaaai"},
		{"tls-name", testBackendLDAP, testLDAPServerName, "ldap-alt.example.test"},
		{"ldap-base", testBackendLDAP, "ou=dkim2,dc=example,dc=test", "ou=dkim2-alt,dc=example,dc=test"},
		{"ldap-snapshot", testBackendLDAP, "cn=snapshot,ou=services,dc=example,dc=test", "cn=snapshot-alt,ou=services,dc=example,dc=test"},
		{"ldap-staging", testBackendLDAP, "cn=stager,ou=services,dc=example,dc=test", "cn=stager-alt,ou=services,dc=example,dc=test"},
		{"ldap-activation", testBackendLDAP, "cn=activator,ou=services,dc=example,dc=test", "cn=activator-alt,ou=services,dc=example,dc=test"},
		{"sql-database", testBackendPostgreSQL, "database: dkim2", "database: dkim2_alt"},
		{"sql-snapshot", testBackendPostgreSQL, testSnapshotRoleLine, "role: dkim2_snapshot_alt"},
		{"sql-staging", testBackendPostgreSQL, testStagingRoleLine, "role: dkim2_stager_alt"},
		{"sql-activation", testBackendPostgreSQL, "role: dkim2_activator", "role: dkim2_activator_alt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, document := writeAdminConfigFixture(t, test.backend)
			first, err := LoadAdminConfig(path)
			if err != nil {
				t.Fatal("baseline authority failed")
			}
			defer first.Close() //nolint:errcheck // Test cleanup has no recovery action.
			changed := strings.Replace(string(document), test.old, test.new, 1)
			if changed == string(document) || os.WriteFile(path, []byte(changed), 0o600) != nil {
				t.Fatal("failed to make exact authority substitution")
			}
			second, err := LoadAdminConfig(path)
			if err != nil {
				t.Fatal("valid substituted authority failed")
			}
			defer second.Close() //nolint:errcheck // Test cleanup has no recovery action.
			if reflect.DeepEqual(first.Authority(), second.Authority()) {
				t.Fatal("provider authority descriptor ignored an identity field")
			}
		})
	}
}

// TestAdminAuthorityDescriptorBindsTrustFingerprint proves CA substitution changes the protected authority.
func TestAdminAuthorityDescriptorBindsTrustFingerprint(t *testing.T) {
	path, _ := writeAdminConfigFixture(t, testBackendLDAP)
	first, err := LoadAdminConfig(path)
	if err != nil {
		t.Fatal("baseline authority failed")
	}
	defer first.Close() //nolint:errcheck // Test cleanup has no recovery action.
	writeTestCA(t, filepath.Join(filepath.Dir(path), "ca.pem"))
	second, err := LoadAdminConfig(path)
	if err != nil {
		t.Fatal("substituted protected trust failed")
	}
	defer second.Close() //nolint:errcheck // Test cleanup has no recovery action.
	if reflect.DeepEqual(first.Authority(), second.Authority()) {
		t.Fatal("provider authority descriptor ignored trust fingerprint substitution")
	}
}

// TestCommandRequestRejectsOverlappingArtifacts freezes nonoverlap and closed activation authorization.
func TestCommandRequestRejectsOverlappingArtifacts(t *testing.T) {
	base := CommandRequest{
		Command: CommandStatus, ConfigPath: "/tmp/admin.yaml",
		OperationPath: "/tmp/admin.yaml/operation.json", ToolVersion: "test",
	}
	if base.Validate() == nil {
		t.Fatal("ancestor command paths were accepted")
	}
	base.OperationPath = "/tmp/operation.json"
	base.Apply = true
	if base.Validate() == nil {
		t.Fatal("apply authorization was accepted outside activation")
	}
}

// TestAdminConfigRejectsCommandArtifactsOverAuthorityChildren prevents DNS export from overwriting credentials.
func TestAdminConfigRejectsCommandArtifactsOverAuthorityChildren(t *testing.T) {
	path, _ := writeAdminConfigFixture(t, testBackendLDAP)
	loaded, err := LoadAdminConfig(path)
	if err != nil {
		t.Fatal("load authority child-path fixture")
	}
	defer loaded.Close() //nolint:errcheck // Test cleanup has no recovery action.
	for _, output := range []string{
		filepath.Join(filepath.Dir(path), "ca.pem"),
		filepath.Join(filepath.Dir(path), "activation.password"),
		filepath.Dir(path),
	} {
		request := CommandRequest{
			Command: CommandDNSExport, ConfigPath: path,
			OperationPath: filepath.Join(filepath.Dir(path), "operation.json"),
			OutputPath:    output, ToolVersion: "development",
		}
		if loaded.ValidateCommandRequest(request) == nil {
			t.Fatal("command artifact overlapped protected authority child")
		}
	}
}

// TestCommandRequestRejectsInvalidToolVersionBeforeExecution freezes report grammar at input preflight.
func TestCommandRequestRejectsInvalidToolVersionBeforeExecution(t *testing.T) {
	request := CommandRequest{
		Command: CommandActivate, ConfigPath: "/tmp/admin.yaml",
		OperationPath: "/tmp/operation.json", Apply: true, ToolVersion: "invalid/version",
	}
	if request.Validate() == nil {
		t.Fatal("invalid build-owned report token reached command execution")
	}
}

// writeAdminConfigFixture writes one otherwise complete owner-only backend configuration.
func writeAdminConfigFixture(t *testing.T, backend string) (string, []byte) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect administration fixture directory")
	}
	caPath := filepath.Join(directory, "ca.pem")
	writeTestCA(t, caPath)
	passwords := map[string]string{
		"snapshot":   filepath.Join(directory, "snapshot.password"),
		"staging":    filepath.Join(directory, "staging.password"),
		"activation": filepath.Join(directory, "activation.password"),
	}
	for role, path := range passwords {
		if err := os.WriteFile(path, []byte("secret-"+role+"\n"), 0o600); err != nil {
			t.Fatal("write protected role fixture")
		}
	}
	port, serverName := "5432", "sql.example.test"
	providerDocument := `sql:
  database: dkim2
  schema: dkim2_datasource
  snapshot:
    role: dkim2_snapshot
    password_file: ` + passwords["snapshot"] + `
  staging:
    role: dkim2_stager
    password_file: ` + passwords["staging"] + `
  activation:
    role: dkim2_activator
    password_file: ` + passwords["activation"] + "\n"
	switch backend {
	case testBackendLDAP:
		port, serverName = "636", testLDAPServerName
		providerDocument = `ldap:
  base_dn: ou=dkim2,dc=example,dc=test
  snapshot:
    principal: cn=snapshot,ou=services,dc=example,dc=test
    password_file: ` + passwords["snapshot"] + `
  staging:
    principal: cn=stager,ou=services,dc=example,dc=test
    password_file: ` + passwords["staging"] + `
  activation:
    principal: cn=activator,ou=services,dc=example,dc=test
    password_file: ` + passwords["activation"] + "\n"
	case testBackendMySQL, testBackendMariaDB:
		port = "3306"
		providerDocument = strings.Replace(providerDocument, "schema: dkim2_datasource", "schema: dkim2", 1)
	}
	document := []byte(`version: dkim2-domain-admin-v1
` + testAuthorityIDLine + `
backend: ` + backend + `
deadline: 10s
endpoint:
  address: 192.0.2.10:` + port + `
  server_name: ` + serverName + `
  ca_file: ` + caPath + `
dns:
  resolver_class: system
  resolver_endpoints: []
  export_ttl_seconds: 300
  proof_lifetime_seconds: 300
` + providerDocument)
	path := filepath.Join(directory, "admin.yaml")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal("write protected configuration fixture")
	}
	return path, document
}

// writeTestCA writes one syntactically valid protected CA bundle.
func writeTestCA(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate test CA key")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin-test-ca"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create test CA")
	}
	document := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal("write test CA")
	}
}
