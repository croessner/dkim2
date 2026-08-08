-- Forward-only PostgreSQL campaign fence upgrade from native domain onboarding v3.
-- Apply with all DKIM2 writers stopped. This migration retains the established
-- immutable v3 row shape and adds a database-side forward-candidate fence;
-- retention classification and destructive purge authority are separate work.

BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;

LOCK TABLE dkim2_datasource.dataset_generations,
  dkim2_datasource.current_generation,
  dkim2_datasource.administration_lock IN ACCESS EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION dkim2_datasource.campaign_candidate_generation_is_forward(
  selected_generation dkim2_datasource.generation_number
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT NOT EXISTS (
    SELECT 1
      FROM dkim2_datasource.current_generation AS current
     WHERE current.singleton = TRUE
       AND current.generation >= selected_generation
  )
$$;

REVOKE ALL ON FUNCTION dkim2_datasource.campaign_candidate_generation_is_forward(
  dkim2_datasource.generation_number
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dkim2_datasource.campaign_candidate_generation_is_forward(
  dkim2_datasource.generation_number
) TO dkim2_stager;

DROP POLICY dataset_stage_v3 ON dkim2_datasource.dataset_generations;
CREATE POLICY dataset_stage_v3 ON dkim2_datasource.dataset_generations
  TO dkim2_stager
  USING (schema_version = 'dkim2-datasource-v3')
  WITH CHECK (
    schema_version = 'dkim2-datasource-v3'
    AND dataset_state = 'staging'
    AND NOT was_active
    AND candidate_digest IS NOT NULL
    AND dkim2_datasource.administration_lock_owned_by(operation_id)
    AND dkim2_datasource.campaign_candidate_generation_is_forward(generation)
  );

CREATE TABLE dkim2_datasource.purge_audit_receipts (
  generation dkim2_datasource.generation_number PRIMARY KEY,
  schema_version text COLLATE "C" NOT NULL,
  lifecycle text COLLATE "C" NOT NULL CHECK (lifecycle IN ('active_history', 'never_active')),
  content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
  policy_version text COLLATE "C" NOT NULL CHECK (octet_length(policy_version) BETWEEN 1 AND 128),
  purge_plan_digest bytea NOT NULL CHECK (octet_length(purge_plan_digest) = 32),
  destroyed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dkim2_purger') THEN
    CREATE ROLE dkim2_purger NOLOGIN;
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION dkim2_datasource.enforce_generation_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF current_setting('dkim2_datasource.purge_authorized', TRUE) = 'on' THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'dataset generation is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD.generation = NEW.generation
     AND OLD.schema_version = NEW.schema_version
     AND OLD.operation_id IS NOT DISTINCT FROM NEW.operation_id
     AND OLD.candidate_digest IS NOT DISTINCT FROM NEW.candidate_digest
     AND OLD.was_active = NEW.was_active
     AND OLD.dataset_state = 'staging'
     AND NEW.dataset_state = 'committed' THEN
    RETURN NEW;
  END IF;
  IF OLD.generation = NEW.generation
     AND OLD.schema_version = NEW.schema_version
     AND OLD.operation_id IS NOT DISTINCT FROM NEW.operation_id
     AND OLD.candidate_digest IS NOT DISTINCT FROM NEW.candidate_digest
     AND OLD.dataset_state = 'committed'
     AND NEW.dataset_state = 'committed'
     AND NEW.was_active
     AND EXISTS (SELECT 1 FROM dkim2_datasource.current_generation WHERE generation = OLD.generation) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'dataset generation is immutable' USING ERRCODE = '55000';
END
$$;

CREATE PROCEDURE dkim2_datasource.purge_generation(
  selected_generation dkim2_datasource.generation_number,
  selected_schema text,
  selected_digest bytea,
  selected_current dkim2_datasource.generation_number,
  selected_lifecycle text,
  selected_policy text,
  selected_plan bytea
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
DECLARE
  target_was_active boolean;
BEGIN
  IF selected_generation = selected_current OR selected_schema <> 'dkim2-datasource-v3'
     OR selected_lifecycle NOT IN ('active_history', 'never_active')
     OR octet_length(selected_digest) <> 32 OR octet_length(selected_plan) <> 32
     OR octet_length(selected_policy) = 0 OR octet_length(selected_policy) > 128 THEN
    RAISE EXCEPTION 'purge target denied' USING ERRCODE = '55000';
  END IF;
  PERFORM 1 FROM dkim2_datasource.administration_lock WHERE singleton = TRUE AND lock_operation_id IS NULL FOR UPDATE;
  IF NOT FOUND OR NOT EXISTS (SELECT 1 FROM dkim2_datasource.current_generation WHERE singleton = TRUE AND generation = selected_current) THEN
    RAISE EXCEPTION 'purge fence denied' USING ERRCODE = '55000';
  END IF;
  SELECT was_active INTO target_was_active FROM dkim2_datasource.dataset_generations
   WHERE generation = selected_generation AND schema_version = selected_schema
     AND dataset_state = 'committed' AND candidate_digest = selected_digest FOR UPDATE;
  IF NOT FOUND OR (selected_lifecycle = 'active_history') <> target_was_active THEN
    RAISE EXCEPTION 'purge target denied' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (SELECT 1 FROM dkim2_datasource.current_generation WHERE generation = selected_generation) THEN
    RAISE EXCEPTION 'purge current denied' USING ERRCODE = '55000';
  END IF;
  PERFORM set_config('dkim2_datasource.purge_authorized', 'on', TRUE);
  DELETE FROM dkim2_datasource.key_material WHERE generation = selected_generation;
  DELETE FROM dkim2_datasource.credentials WHERE generation = selected_generation;
  DELETE FROM dkim2_datasource.policies WHERE generation = selected_generation;
  DELETE FROM dkim2_datasource.profiles WHERE generation = selected_generation;
  DELETE FROM dkim2_datasource.handles WHERE generation = selected_generation;
  DELETE FROM dkim2_datasource.dataset_generations WHERE generation = selected_generation;
  INSERT INTO dkim2_datasource.purge_audit_receipts
    (generation, schema_version, lifecycle, content_digest, policy_version, purge_plan_digest)
  VALUES (selected_generation, selected_schema, selected_lifecycle, selected_digest, selected_policy, selected_plan);
END
$$;

REVOKE ALL ON dkim2_datasource.purge_audit_receipts FROM PUBLIC;
REVOKE ALL ON PROCEDURE dkim2_datasource.purge_generation(
  dkim2_datasource.generation_number, text, bytea, dkim2_datasource.generation_number, text, text, bytea
) FROM PUBLIC;
GRANT USAGE ON SCHEMA dkim2_datasource TO dkim2_purger;
GRANT SELECT ON dkim2_datasource.dataset_generations, dkim2_datasource.current_generation,
  dkim2_datasource.purge_audit_receipts TO dkim2_purger;
GRANT EXECUTE ON PROCEDURE dkim2_datasource.purge_generation(
  dkim2_datasource.generation_number, text, bytea, dkim2_datasource.generation_number, text, text, bytea
) TO dkim2_purger;

COMMIT;
