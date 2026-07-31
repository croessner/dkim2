package migration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	migrationTestDomain            = "example.test"
	migrationTestSelector          = "selector"
	migrationTestSourceKey         = migrationTestDomain + "\x00" + migrationTestSelector
	migrationTestAddress           = "127.0.0.1:636"
	migrationTestCAPath            = "/tmp/ca"
	migrationTestBaseDN            = "dc=legacy"
	migrationTestServerName        = "ldap.example"
	migrationTestMixedCaseSelector = "Selector-AB12"
	migrationTestCanonicalSelector = "selector-ab12"
)

type inventoryClientFake struct {
	entries    []RawEntry
	attributes []string
}

// Search returns detached synthetic inventory and records the projection.
func (f *inventoryClientFake) Search(
	_ context.Context,
	attributes []string,
	_ int,
	_ int,
) ([]RawEntry, error) {
	f.attributes = append([]string(nil), attributes...)
	return append([]RawEntry(nil), f.entries...), nil
}

// TestDryRunNeverRequestsKeysOrPublishesIdentity proves the safe default path.
func TestDryRunNeverRequestsKeysOrPublishesIdentity(t *testing.T) {
	client := &inventoryClientFake{entries: []RawEntry{
		legacyFixture(migrationTestSelector, "toxic.example", true),
		legacyFixture("old", "history.example", false),
	}}
	config := testConfig()
	config.Plan.Mappings[0].Domain = "toxic.example"
	report, err := DryRun(
		context.Background(), config, client, "development",
	)
	if err != nil || report.Result != migrationResultSuccess ||
		report.Counts.Active != 1 || report.Counts.Inactive != 1 {
		t.Fatal("valid dry run failed")
	}
	if slices.Contains(client.attributes, legacyKey) {
		t.Fatal("inventory requested private key material")
	}
	machine, err := EncodeMachineReport(report, config.Limits.ReportBytes)
	if err != nil {
		t.Fatal("encode machine report")
	}
	human, err := EncodeHumanReport(report, config.Limits.ReportBytes)
	if err != nil {
		t.Fatal("encode human report")
	}
	for _, marker := range [][]byte{
		[]byte("toxic.example"), []byte("history.example"),
		[]byte(migrationTestSelector), []byte("tenant"), []byte("handle"),
	} {
		if reportContainsProtectedMarker(machine, marker) ||
			reportContainsProtectedMarker(human, marker) {
			t.Fatal("dry-run report exposed protected identity")
		}
	}
}

// TestInventoryRejectsCrossDomainAndDuplicateActiveAlgorithm freezes no-alias behavior.
func TestInventoryRejectsCrossDomainAndDuplicateActiveAlgorithm(t *testing.T) {
	cross := legacyFixture(migrationTestSelector, migrationTestDomain, true)
	cross.Attributes[legacyAssociatedDomain] = [][]byte{[]byte("other.test")}
	duplicate := legacyFixture("second", migrationTestDomain, true)
	for _, entries := range [][]RawEntry{{cross}, {
		legacyFixture("first", migrationTestDomain, true), duplicate,
	}} {
		client := &inventoryClientFake{entries: entries}
		records, counts, err := Inventory(
			context.Background(), client, testConfig().Limits,
		)
		if err == nil || records != nil || counts != (InventoryCounts{}) {
			t.Fatal("ambiguous legacy inventory accepted")
		}
	}
}

// TestInventoryCanonicalizesLegacySelectorCase proves LDAP storage spelling
// cannot escape the canonical lowercase DKIM2 selector namespace.
func TestInventoryCanonicalizesLegacySelectorCase(t *testing.T) {
	entry := legacyFixture(migrationTestMixedCaseSelector, migrationTestDomain, true)
	records, counts, err := Inventory(
		context.Background(),
		&inventoryClientFake{entries: []RawEntry{entry}},
		testConfig().Limits,
	)
	if err != nil || len(records) != 1 || counts.Active != 1 {
		t.Fatal("valid legacy selector case was rejected")
	}
	if records[0].selector != migrationTestCanonicalSelector ||
		records[0].sourceSelector != migrationTestMixedCaseSelector {
		t.Fatal("legacy selector case was not bounded at the adapter")
	}
}

// TestInventoryRejectsUnicodeSelectorConfusables proves canonicalization never
// maps non-ASCII LDAP spelling into the ASCII DKIM2 selector namespace.
func TestInventoryRejectsUnicodeSelectorConfusables(t *testing.T) {
	entry := legacyFixture("sele\u212Aor", migrationTestDomain, true)
	records, counts, err := Inventory(
		context.Background(),
		&inventoryClientFake{entries: []RawEntry{entry}},
		testConfig().Limits,
	)
	if err == nil || records != nil || counts != (InventoryCounts{}) {
		t.Fatal("Unicode legacy selector confusable was accepted")
	}
}

// TestInventoryAcceptsOnlyInactiveLegacyWildcardHistory proves historical
// wildcard rows remain count-only and can never become DKIM2 mappings.
func TestInventoryAcceptsOnlyInactiveLegacyWildcardHistory(t *testing.T) {
	inactive := legacyFixture("Old-Wildcard", "*", false)
	inactive.Attributes[legacyAssociatedDomain] = [][]byte{[]byte(migrationTestDomain)}
	records, counts, err := Inventory(
		context.Background(),
		&inventoryClientFake{entries: []RawEntry{inactive}},
		testConfig().Limits,
	)
	if err != nil || len(records) != 1 || counts.Inactive != 1 ||
		records[0].domain != migrationTestDomain {
		t.Fatal("inactive legacy wildcard history was rejected")
	}

	active := legacyFixture("Active-Wildcard", "*", true)
	active.Attributes[legacyAssociatedDomain] = [][]byte{[]byte(migrationTestDomain)}
	records, counts, err = Inventory(
		context.Background(),
		&inventoryClientFake{entries: []RawEntry{active}},
		testConfig().Limits,
	)
	if err == nil || records != nil || counts != (InventoryCounts{}) {
		t.Fatal("active legacy wildcard was accepted")
	}
}

// TestInventoryIgnoresAUIDAndTimestampsWithoutMapping proves historical fields
// are count-only and cannot become plan facts.
func TestInventoryIgnoresAUIDAndTimestampsWithoutMapping(t *testing.T) {
	entry := legacyFixture(migrationTestSelector, migrationTestDomain, true)
	entry.Attributes["DKIMIdentity"] = [][]byte{[]byte("toxic-auid")}
	entry.Attributes["createTimestamp"] = [][]byte{[]byte("20260101000000Z")}
	entry.Attributes["modifyTimestamp"] = [][]byte{[]byte("20260102000000Z")}
	records, counts, err := Inventory(
		context.Background(),
		&inventoryClientFake{entries: []RawEntry{entry}},
		testConfig().Limits,
	)
	if err != nil || len(records) != 1 ||
		counts.IgnoredIdentityFields != 1 || counts.IgnoredTimestampFields != 2 {
		t.Fatal("ignored legacy audit fields drifted")
	}
	if strings.Contains(records[0].String(), "toxic") {
		t.Fatal("legacy identity reached record formatting")
	}
}

// TestLoadConfigRequiresStrictOwnerOnlyShape proves offline config confinement.
func TestLoadConfigRequiresStrictOwnerOnlyShape(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "migration.yaml")
	caPath := filepath.Join(root, "ca.pem")
	passwordPath := filepath.Join(root, "password")
	importPasswordPath := filepath.Join(root, "import-password")
	publishPasswordPath := filepath.Join(root, "publish-password")
	document := []byte(`version: dkim2-opendkim-migration-v1
deadline: 5s
source:
  address: 127.0.0.1:636
  server_name: ldap.example
  ca_file: ` + caPath + `
  transport: ldaps
  bind_dn: cn=inventory,dc=example,dc=test
  password_file: ` + importPasswordPath + `
  base_dn: dc=legacy,dc=example
  page_size: 128
import:
  address: 127.0.0.1:636
  server_name: ldap.example
  ca_file: ` + caPath + `
  transport: ldaps
  bind_dn: cn=import,dc=example,dc=test
  password_file: ` + passwordPath + `
  base_dn: dc=legacy,dc=example
  page_size: 128
ldap_publish:
  address: 127.0.0.1:636
  server_name: ldap.example
  ca_file: ` + caPath + `
  transport: ldaps
  bind_dn: cn=publisher,dc=example,dc=test
  password_file: ` + publishPasswordPath + `
  base_dn: dc=legacy,dc=example
  page_size: 128
plan:
  generation: "2"
  expected_current: "1"
  target: ldap
  registry_root: ` + root + `
  mappings:
    - domain: example.test
      selector: selector
      tenant_id: tenant
      profile_id: profile
      profile_use: originator
      handle_id: handle
      rollout: enforce
      compatibility: strict
limits:
  records: 32
  response_bytes: 1048576
  report_bytes: 262144
`)
	for path, content := range map[string][]byte{
		configPath: document, caPath: []byte("ca"), passwordPath: []byte("password"),
		importPasswordPath:  []byte("import-password"),
		publishPasswordPath: []byte("publish-password"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal("write protected fixture")
		}
	}
	config, err := LoadConfig(configPath)
	if err != nil || config.Deadline != 5*time.Second ||
		config.Plan.Generation != "2" {
		t.Fatal("valid protected migration config rejected")
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal("weaken fixture mode")
	}
	if config, err := LoadConfig(configPath); err == nil ||
		config.Version != "" {
		t.Fatal("world-readable migration config accepted")
	}
}

// TestReadProtectedRejectsHardLinkedMaterial proves protected migration input
// cannot acquire a second mutable filesystem name.
func TestReadProtectedRejectsHardLinkedMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected")
	if err := os.WriteFile(path, []byte("synthetic"), 0o600); err != nil {
		t.Fatal("write protected fixture")
	}
	if err := os.Link(path, path+".alias"); err != nil {
		t.Fatal("create hard-link fixture")
	}
	if document, err := readProtected(path, 64); err == nil || document != nil {
		t.Fatal("hard-linked protected migration input accepted")
	}
}

// legacyFixture creates one exact synthetic external DKIM object.
func legacyFixture(selector, domain string, active bool) RawEntry {
	activeText := "FALSE"
	if active {
		activeText = "TRUE"
	}
	return RawEntry{Attributes: map[string][][]byte{
		legacyObjectClass:      {[]byte("top"), []byte("DKIM")},
		legacySelector:         {[]byte(selector)},
		legacyDomain:           {[]byte(domain)},
		legacyAssociatedDomain: {[]byte(domain)},
		legacyKeyType:          {[]byte("rsa")},
		legacyActive:           {[]byte(activeText)},
	}}
}

// testConfig returns one bounded explicit dry-run plan.
func testConfig() Config {
	publisher := SourceConfig{
		Address: migrationTestAddress, ServerName: migrationTestServerName,
		CAFile: migrationTestCAPath, Transport: ldapTransportSecure, BindDN: "cn=publisher",
		PasswordFile: "/tmp/publish-password", BaseDN: migrationTestBaseDN, PageSize: 128,
	}
	return Config{
		Version: configVersion, Deadline: 5 * time.Second, DeadlineText: "5s",
		Source: SourceConfig{
			Address: migrationTestAddress, ServerName: migrationTestServerName,
			CAFile: migrationTestCAPath, Transport: ldapTransportSecure, BindDN: "cn=inventory",
			PasswordFile: "/tmp/password", BaseDN: migrationTestBaseDN, PageSize: 128,
		},
		Import: SourceConfig{
			Address: migrationTestAddress, ServerName: migrationTestServerName,
			CAFile: migrationTestCAPath, Transport: ldapTransportSecure, BindDN: "cn=import",
			PasswordFile: "/tmp/import-password", BaseDN: migrationTestBaseDN, PageSize: 128,
		},
		LDAPPublish: &publisher,
		Plan: Plan{
			Generation: "2", ExpectedCurrent: "1", Target: TargetLDAP,
			RegistryRoot: "/tmp/registry",
			Mappings: []Mapping{{
				Domain: migrationTestDomain, Selector: migrationTestSelector, TenantID: "tenant",
				ProfileID: "profile", ProfileUse: "originator", HandleID: "handle",
				Rollout: "enforce", Compatibility: "strict",
			}},
		},
		Limits: Limits{
			Records: 32, ResponseBytes: 1 << 20, ReportBytes: maxConfigBytes,
		},
	}
}

// TestReportsAreDeterministic proves stable machine and human output.
func TestReportsAreDeterministic(t *testing.T) {
	report := Report{
		Schema: migrationReportSchema, ToolVersion: "development",
		Target: TargetLDAP, Mode: "dry_run", Result: migrationResultSuccess, FailureClass: migrationFailureNone,
	}
	first, err := EncodeMachineReport(report, maxConfigBytes)
	if err != nil {
		t.Fatal("encode report")
	}
	second, err := EncodeMachineReport(report, maxConfigBytes)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("machine report is nondeterministic")
	}
}

// FuzzLegacyInventoryNeverPanicsOrRequestsPrivateKeys proves bounded hostile
// external attributes cannot widen the read projection.
func FuzzLegacyInventoryNeverPanicsOrRequestsPrivateKeys(f *testing.F) {
	f.Add(migrationTestSelector, migrationTestDomain, "rsa", "TRUE")
	f.Add("S", "EXAMPLE.TEST", "toxic", "yes")
	f.Fuzz(func(
		t *testing.T,
		selector string,
		domain string,
		keyType string,
		active string,
	) {
		if len(selector) > 512 || len(domain) > 512 ||
			len(keyType) > 64 || len(active) > 64 {
			return
		}
		entry := legacyFixture(selector, domain, true)
		entry.Attributes[legacyKeyType] = [][]byte{[]byte(keyType)}
		entry.Attributes[legacyActive] = [][]byte{[]byte(active)}
		client := &inventoryClientFake{entries: []RawEntry{entry}}
		_, _, _ = Inventory(context.Background(), client, testConfig().Limits)
		if slices.Contains(client.attributes, legacyKey) {
			t.Fatal("fuzzed inventory requested private key material")
		}
	})
}
