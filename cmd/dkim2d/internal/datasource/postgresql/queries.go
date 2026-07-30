package postgresql

const (
	queryIsolation = `SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')`
	queryCurrent   = `SELECT generation::text, schema_version, dataset_state
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
)
