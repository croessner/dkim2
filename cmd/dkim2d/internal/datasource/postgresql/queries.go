package postgresql

const (
	queryIsolation = `SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')`
	queryCurrent   = `SELECT current.generation::text, dataset.schema_version, dataset.dataset_state,
	       dataset.operation_id, dataset.candidate_digest, current.candidate_digest,
	       dataset.was_active
FROM dkim2_datasource.current_generation AS current
JOIN dkim2_datasource.dataset_generations AS dataset USING (generation)
WHERE current.singleton = TRUE`
	queryHandles = `SELECT generation::text, handle_id
FROM dkim2_datasource.handles
WHERE generation = $1 AND handle_id > $2
ORDER BY handle_id
LIMIT $3`
	queryProfiles = `SELECT generation::text, profile_id, signing_domain, record_status, not_before_utc, not_after_utc
FROM dkim2_datasource.profiles
WHERE generation = $1 AND profile_id > $2
ORDER BY profile_id
LIMIT $3`
	queryCredentials = `SELECT generation::text, profile_id, algorithm, selector, public_key_spki, handle_id
FROM dkim2_datasource.credentials
WHERE generation = $1 AND (profile_id, algorithm) > ($2, $3)
ORDER BY profile_id, algorithm
LIMIT $4`
	queryPolicies = `SELECT generation::text, tenant_id, signing_domain, profile_use, profile_id, record_status, rollout, compatibility, feedback_route_id
FROM dkim2_datasource.policies
WHERE generation = $1 AND (tenant_id, signing_domain, profile_use) > ($2, $3, $4)
ORDER BY tenant_id, signing_domain, profile_use
LIMIT $5`
	queryKeyMaterial = `SELECT generation::text, tenant_id, signing_domain, profile_use, handle_id, algorithm, public_key_spki, private_key_pkcs8
FROM dkim2_datasource.key_material
WHERE generation = $1 AND handle_id > $2
ORDER BY handle_id
LIMIT $3`
)
