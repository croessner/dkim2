package ldap

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

// TestGoLDAPConnectorOwnsTrustAndCanonicalAuthority reproduces caller trust
// aliasing and LDAP aliases that cannot safely identify administration roles.
func TestGoLDAPConnectorOwnsTrustAndCanonicalAuthority(t *testing.T) {
	roots := x509.NewCertPool()
	config := ConnectionConfig{
		Address: "127.0.0.1:636", ServerName: "ldap.example.test",
		BaseDN:   "ou=dkim2,dc=example,dc=test",
		BindDN:   "cn=dkim2-snapshot,ou=services,dc=example,dc=test",
		Password: []byte("synthetic-password"), RootCAs: roots,
	}
	connector, err := NewGoLDAPConnector(config)
	if err != nil {
		t.Fatal("construct LDAP connector with canonical authority")
	}
	authority := connector.AdministrationAuthority()
	if !authority.Valid() || fmt.Sprint(authority) != ldapAdministrationAuthorityRedacted ||
		fmt.Sprintf("%#v", authority) != ldapAdministrationAuthorityRedacted {
		t.Fatal("LDAP administration authority formatting exposed identity")
	}
	if encoded, marshalErr := json.Marshal(authority); marshalErr == nil || encoded != nil {
		t.Fatal("LDAP administration authority was generically serializable")
	}
	roleConnector := func(role string) *GoLDAPConnector {
		t.Helper()
		roleConfig := config
		roleConfig.BindDN = "cn=dkim2-" + role + ",ou=services,dc=example,dc=test"
		value, connectorErr := NewGoLDAPConnector(roleConfig)
		if connectorErr != nil {
			t.Fatal("construct canonical role connector")
		}
		return value
	}
	stager := roleConnector("stager")
	activator := roleConnector("activator")
	limits := datasourceadmin.GenerationLimits{
		MaxGenerations: 256, MaxOutstandingCandidates: 8,
		MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20,
		BackendDeadline: 2 * time.Second,
	}
	if administrator, adminErr := NewAdministrator(
		connector, stager, activator, provider.DefaultLimits(), limits,
	); adminErr != nil || administrator == nil {
		t.Fatal("canonical administration role connectors rejected")
	}
	if administrator, adminErr := NewAdministrator(
		connector, roleConnector("snapshot"), activator, provider.DefaultLimits(), limits,
	); administrator != nil || datasourceadmin.CodeOf(adminErr) != datasourceadmin.CodeInvalid {
		t.Fatal("same canonical administration authority accepted")
	}

	for _, test := range []struct {
		name   string
		bindDN string
	}{
		{name: "descriptor OID alias", bindDN: "2.5.4.3=dkim2-snapshot,ou=services,dc=example,dc=test"},
		{name: "uppercase descriptor", bindDN: "CN=dkim2-snapshot,ou=services,dc=example,dc=test"},
		{name: "uppercase value", bindDN: "cn=DKIM2-snapshot,ou=services,dc=example,dc=test"},
		{name: "insignificant space", bindDN: "cn=dkim2-snapshot, ou=services,dc=example,dc=test"},
		{name: "multiple spaces", bindDN: "cn=dkim2-snapshot,  ou=services,dc=example,dc=test"},
		{name: "unicode value", bindDN: "cn=dkim2-snäpshot,ou=services,dc=example,dc=test"},
		{name: "escaped value", bindDN: `cn=dkim2\2dsnapshot,ou=services,dc=example,dc=test`},
		{name: "multivalued RDN", bindDN: "cn=dkim2-snapshot+ou=services,dc=example,dc=test"},
		{name: "unexpected type", bindDN: "uid=dkim2-snapshot,ou=services,dc=example,dc=test"},
		{name: "missing organizational unit", bindDN: "cn=dkim2-snapshot,dc=example,dc=test"},
		{name: "organizational unit after domain", bindDN: "cn=dkim2-snapshot,dc=example,ou=services,dc=test"},
		{name: "non LDH value", bindDN: "cn=dkim2_snapshot,ou=services,dc=example,dc=test"},
		{name: "leading hyphen", bindDN: "cn=-snapshot,ou=services,dc=example,dc=test"},
		{name: "trailing hyphen", bindDN: "cn=snapshot-,ou=services,dc=example,dc=test"},
		{
			name:   "overlong value",
			bindDN: "cn=" + strings.Repeat("a", 64) + ",ou=services,dc=example,dc=test",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			noncanonical := config
			noncanonical.BindDN = test.bindDN
			value, connectorErr := NewGoLDAPConnector(noncanonical)
			if connectorErr != nil || value == nil {
				t.Fatal("general LDAP connector rejected syntactically valid bind DN")
			}
			if value.AdministrationAuthority().Valid() {
				t.Fatal("noncanonical bind DN received administration authority")
			}
			administrator, adminErr := NewAdministrator(
				connector, value, activator, provider.DefaultLimits(), limits,
			)
			if administrator != nil || datasourceadmin.CodeOf(adminErr) != datasourceadmin.CodeInvalid {
				t.Fatal("noncanonical bind DN reached LDAP administrator")
			}
		})
	}

	constructorTrust := x509.NewCertPool()
	config.Password[0] = 'X'
	roots.AddCert(&x509.Certificate{RawSubject: []byte("caller-added-root")})
	if roots.Equal(constructorTrust) || !connector.config.RootCAs.Equal(constructorTrust) ||
		!bytes.Equal(connector.config.Password, []byte("synthetic-password")) ||
		!authority.Equal(connector.AdministrationAuthority()) {
		t.Fatal("LDAP connector retained caller-owned credential or trust alias")
	}

	invalid := config
	invalid.BindDN = "cn=incomplete,"
	if value, invalidErr := NewGoLDAPConnector(invalid); invalidErr == nil || value != nil {
		t.Fatal("syntactically invalid bind DN reached connector state")
	}
}

// TestLDAPAdministratorCloseClearsConnectorCredentialsExactlyOnce freezes one-shot secret cleanup.
func TestLDAPAdministratorCloseClearsConnectorCredentialsExactlyOnce(t *testing.T) {
	newConnector := func(role string) (*GoLDAPConnector, []byte) {
		t.Helper()
		connector, err := NewGoLDAPConnector(ConnectionConfig{
			Address: "127.0.0.1:636", ServerName: "ldap.example.test",
			BaseDN:   "ou=dkim2,dc=example,dc=test",
			BindDN:   "cn=dkim2-" + role + ",ou=services,dc=example,dc=test",
			Password: []byte("secret-" + role), RootCAs: x509.NewCertPool(),
		})
		if err != nil {
			t.Fatal("construct role connector")
		}
		return connector, connector.config.Password
	}
	snapshot, snapshotSecret := newConnector("snapshot")
	stager, stagingSecret := newConnector("stager")
	activator, activationSecret := newConnector("activator")
	administrator, err := NewAdministrator(
		snapshot, stager, activator, provider.DefaultLimits(), datasourceadmin.GenerationLimits{
			MaxGenerations: 256, MaxOutstandingCandidates: 8,
			MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20,
			BackendDeadline: 2 * time.Second,
		},
	)
	if err != nil {
		t.Fatal("construct LDAP administrator")
	}
	firstClose := administrator.Close()
	secondClose := administrator.Close()
	if firstClose != nil || secondClose != nil {
		t.Fatal("idempotent LDAP administrator close failed")
	}
	for _, secret := range [][]byte{snapshotSecret, stagingSecret, activationSecret} {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("LDAP connector retained credential bytes after administrator close")
		}
	}
	if snapshot.AdministrationAuthority().Valid() || stager.AdministrationAuthority().Valid() || activator.AdministrationAuthority().Valid() {
		t.Fatal("closed LDAP connector retained administration authority")
	}
}
