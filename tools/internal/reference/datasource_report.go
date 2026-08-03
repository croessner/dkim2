package reference

import (
	"errors"

	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	datasourceIntegrationReportSchema      = "dkim2.datasource-integration-report.v2"
	datasourceIntegrationReportSchemaPath  = "testdata/reference/schemas/datasource-integration-report.schema.json"
	datasourceIntegrationQualificationRuns = 4
	datasourceIntegrationResultCount       = 12
	datasourceIntegrationCheckCount        = 54
	datasourceIntegrationMaxBytes          = int64(1 << 20)
	datasourceIntegrationPass              = "pass"

	datasourceLDAPImage       = "chrroessner/openldap:2.6.13-r4@sha256:17f2e3485dae92122051da6acdb1091e6d9f1f64d30fd76fd3da3c261c6c778f"
	datasourcePostgreSQLImage = "postgres:18.3-alpine@sha256:54451ecb8ab38c24c3ec123f2fd501303a3a1856a5c66e98cecf2460d5e1e9d7"
	datasourceMySQLImage      = "mysql:8.4@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb"
	datasourceMariaDBImage    = "mariadb:10.11@sha256:be981e4113326ada8d6004174dd09eeaefc03094037f811182a52d4f2e737350"
)

type datasourceIntegrationReport struct {
	Schema                   string                        `json:"schema"`
	BaseRevision             string                        `json:"base_revision"`
	CandidateSnapshotSHA256  string                        `json:"candidate_snapshot_sha256"`
	LDAPImage                string                        `json:"ldap_image"`
	PostgreSQLImage          string                        `json:"postgresql_image"`
	MySQLImage               string                        `json:"mysql_image"`
	MariaDBImage             string                        `json:"mariadb_image"`
	RuntimeQualificationRuns int                           `json:"runtime_qualification_runs"`
	Checks                   []string                      `json:"checks"`
	Results                  []datasourceIntegrationResult `json:"results"`
	Overall                  string                        `json:"overall"`
}

type datasourceIntegrationResult struct {
	Image   string `json:"image"`
	Backend string `json:"backend"`
	Check   string `json:"check"`
	Result  string `json:"result"`
}

var datasourceIntegrationImages = map[string]string{
	"ldap":       datasourceLDAPImage,
	"postgresql": datasourcePostgreSQLImage,
	"mysql":      datasourceMySQLImage,
	"mariadb":    datasourceMariaDBImage,
}

var datasourceIntegrationResultChecks = []string{
	"domain_onboarding_full_flow",
	"activated_runtime_signing",
	"app_signing_service_parity",
}

var datasourceIntegrationChecks = map[string]struct{}{
	"ldap_parity_and_denials":                                  {},
	"postgresql_parity_and_denials":                            {},
	"mysql_parity_and_denials":                                 {},
	"mariadb_parity_and_denials":                               {},
	"ldap_absent_to_first_concurrency_fence":                   {},
	"postgresql_absent_to_first_concurrency_fence":             {},
	"ldap_pointerless_nonempty_denial":                         {},
	"postgresql_pointerless_nonempty_denial":                   {},
	"mysql_absent_to_first_concurrency_fence":                  {},
	"mariadb_absent_to_first_concurrency_fence":                {},
	"mysql_pointerless_nonempty_denial":                        {},
	"mariadb_pointerless_nonempty_denial":                      {},
	"postgresql_v2_to_v3_upgrade_and_two_rotations":            {},
	"mysql_v2_to_v3_upgrade_and_two_rotations":                 {},
	"mariadb_v2_to_v3_upgrade_and_two_rotations":               {},
	"postgresql_v3_observed_lock_contention_activation_race":   {},
	"mysql_v3_observed_lock_contention_activation_race":        {},
	"mariadb_v3_observed_lock_contention_activation_race":      {},
	"postgresql_fresh_v3_bootstrap_and_rotation":               {},
	"mysql_fresh_v3_bootstrap_and_rotation":                    {},
	"mariadb_fresh_v3_bootstrap_and_rotation":                  {},
	"sql_stage_replay_and_canonical_inspection":                {},
	"sql_v3_runtime_digest_and_private_readback":               {},
	"postgresql_exact_definer_routine_audit":                   {},
	"postgresql_exact_definer_acl_audit":                       {},
	"postgresql_direct_candidate_root_lock_denial":             {},
	"mysql_fresh_and_upgrade_grant_routine_sets":               {},
	"mariadb_fresh_and_upgrade_grant_routine_sets":             {},
	"mysql_exact_publisher_and_admin_routine_allowlists":       {},
	"mariadb_exact_publisher_and_admin_routine_allowlists":     {},
	"mysql_fixed_routine_definer_allowlist":                    {},
	"mariadb_fixed_routine_definer_allowlist":                  {},
	"mysql_v2_publisher_singleton_column_lock_compatibility":   {},
	"mariadb_v2_publisher_singleton_column_lock_compatibility": {},
	"mysql_v2_publisher_lock_metadata_write_denials":           {},
	"mariadb_v2_publisher_lock_metadata_write_denials":         {},
	"postgresql_stager_and_activator_denials":                  {},
	"mysql_stager_and_activator_denials":                       {},
	"mariadb_stager_and_activator_denials":                     {},
	"postgresql_direct_lock_table_denials":                     {},
	"mysql_direct_lock_table_denials":                          {},
	"mariadb_direct_lock_table_denials":                        {},
	"postgresql_snapshot_physical_lock_denial":                 {},
	"mysql_snapshot_physical_lock_denial":                      {},
	"mariadb_snapshot_physical_lock_denial":                    {},
	"postgresql_activator_claim_denial":                        {},
	"mysql_activator_claim_denial":                             {},
	"mariadb_activator_claim_denial":                           {},
	"mysql_operation_and_digest_coercion_denials":              {},
	"mariadb_operation_and_digest_coercion_denials":            {},
	"postgresql_committed_immutability":                        {},
	"postgresql_runtime_write_denial":                          {},
	"mysql_committed_immutability_and_runtime_write_denial":    {},
	"mariadb_committed_immutability_and_runtime_write_denial":  {},
}

// CheckDatasourceIntegrationReport validates one current candidate-bound v2 report.
func CheckDatasourceIntegrationReport(root string, content []byte) error {
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		return errors.New("report_evidence_schema")
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return errors.New("report_evidence_schema")
	}
	return validateDatasourceIntegrationReport(root, content, revision, snapshot.SHA256)
}

// validateDatasourceIntegrationReport enforces the closed v2 semantic contract.
func validateDatasourceIntegrationReport(root string, content []byte, revision, candidate string) error {
	if len(content) == 0 || int64(len(content)) > datasourceIntegrationMaxBytes {
		return errors.New("report_evidence_schema")
	}
	var report datasourceIntegrationReport
	if err := strictjson.Decode(content, &report, 32, 1<<20); err != nil {
		return errors.New("report_evidence_schema")
	}
	if report.Schema != datasourceIntegrationReportSchema ||
		report.BaseRevision != revision || report.CandidateSnapshotSHA256 != candidate ||
		report.LDAPImage != datasourceLDAPImage ||
		report.PostgreSQLImage != datasourcePostgreSQLImage ||
		report.MySQLImage != datasourceMySQLImage || report.MariaDBImage != datasourceMariaDBImage ||
		report.RuntimeQualificationRuns != datasourceIntegrationQualificationRuns ||
		report.Overall != datasourceIntegrationPass || !validDatasourceIntegrationChecks(report.Checks) ||
		!validDatasourceIntegrationResults(report.Results) {
		return errors.New("report_evidence_schema")
	}
	if err := conformance.ValidateJSONSchema(
		root, datasourceIntegrationReportSchemaPath, content, datasourceIntegrationMaxBytes,
	); err != nil {
		return errors.New("report_evidence_schema")
	}
	return nil
}

// validDatasourceIntegrationChecks requires every closed check exactly once.
func validDatasourceIntegrationChecks(checks []string) bool {
	if len(checks) != datasourceIntegrationCheckCount ||
		len(datasourceIntegrationChecks) != datasourceIntegrationCheckCount {
		return false
	}
	seen := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		if _, allowed := datasourceIntegrationChecks[check]; !allowed {
			return false
		}
		if _, duplicate := seen[check]; duplicate {
			return false
		}
		seen[check] = struct{}{}
	}
	return len(seen) == len(datasourceIntegrationChecks)
}

// validDatasourceIntegrationResults requires the exact backend/check cross product.
func validDatasourceIntegrationResults(results []datasourceIntegrationResult) bool {
	if len(results) != datasourceIntegrationResultCount {
		return false
	}
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		expectedImage, backend := datasourceIntegrationImages[result.Backend]
		if !backend || result.Image != expectedImage || result.Result != datasourceIntegrationPass {
			return false
		}
		allowedCheck := false
		for _, check := range datasourceIntegrationResultChecks {
			if result.Check == check {
				allowedCheck = true
				break
			}
		}
		if !allowedCheck {
			return false
		}
		identity := result.Backend + "\x00" + result.Check
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
	}
	return len(seen) == len(datasourceIntegrationImages)*len(datasourceIntegrationResultChecks)
}
