package mysql

const (
	querySessionIsolation = `SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ`
	querySessionReadOnly  = `SET SESSION TRANSACTION READ ONLY`
	queryIsolation        = `SELECT @@transaction_isolation, @@transaction_read_only`
	queryLegacyIsolation  = `SELECT @@tx_isolation, @@tx_read_only`
	queryCurrent          = `SELECT CAST(current_generation.generation AS CHAR), dataset.schema_version, dataset.dataset_state,
	       dataset.operation_id, dataset.candidate_digest,
	       current_generation.candidate_digest, dataset.was_active
FROM dkim2_current_generation AS current_generation
JOIN dkim2_dataset_generations AS dataset USING (generation)
WHERE current_generation.singleton = 1`
	queryHandles = `SELECT CAST(generation AS CHAR), handle_id
FROM dkim2_handles
WHERE generation = ? AND handle_id > ?
ORDER BY handle_id
LIMIT ?`
	queryProfiles = `SELECT CAST(generation AS CHAR), profile_id, signing_domain, record_status, not_before_utc, not_after_utc
FROM dkim2_profiles
WHERE generation = ? AND profile_id > ?
ORDER BY profile_id
LIMIT ?`
	queryCredentials = `SELECT CAST(generation AS CHAR), profile_id, algorithm, selector, public_key_spki, handle_id
FROM dkim2_credentials
WHERE generation = ? AND (profile_id, algorithm) > (?, ?)
ORDER BY profile_id, algorithm
LIMIT ?`
	queryPolicies = `SELECT CAST(generation AS CHAR), tenant_id, signing_domain, profile_use, profile_id, record_status, rollout, compatibility, feedback_route_id
FROM dkim2_policies
WHERE generation = ? AND (tenant_id, signing_domain, profile_use) > (?, ?, ?)
ORDER BY tenant_id, signing_domain, profile_use
LIMIT ?`
	queryKeyMaterial = `SELECT CAST(generation AS CHAR), tenant_id, signing_domain, profile_use, handle_id, algorithm, public_key_spki, private_key_pkcs8
FROM dkim2_key_material
WHERE generation = ? AND handle_id > ?
ORDER BY handle_id
LIMIT ?`
)
