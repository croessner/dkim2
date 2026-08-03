-- Forward-only PostgreSQL upgrade from the deployed native-custody v2 schema.
-- Apply with an administrative connection while dkim2 writers are stopped.
-- Row rewrites and policy replacement make rollback a restore operation.

BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;

LOCK TABLE dkim2_datasource.dataset_generations,
  dkim2_datasource.current_generation,
  dkim2_datasource.handles,
  dkim2_datasource.profiles,
  dkim2_datasource.credentials,
  dkim2_datasource.policies,
  dkim2_datasource.key_material IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM dkim2_datasource.dataset_generations
     WHERE schema_version <> 'dkim2-datasource-v2'
  ) THEN
    RAISE EXCEPTION 'native domain onboarding requires exact v2 input'
      USING ERRCODE = '55000';
  END IF;
END
$$;

ALTER TABLE dkim2_datasource.dataset_generations
  DROP CONSTRAINT dataset_generations_schema_version_check;
ALTER TABLE dkim2_datasource.dataset_generations
  ADD COLUMN operation_id text COLLATE "C",
  ADD COLUMN candidate_digest bytea,
  ADD COLUMN was_active boolean NOT NULL DEFAULT FALSE,
  ADD CONSTRAINT dataset_generations_schema_version_check
    CHECK (schema_version IN (
	  'dkim2-datasource-v2', 'dkim2-datasource-v3'
    )),
  ADD CONSTRAINT dataset_generations_v3_metadata_check CHECK (
    (
      schema_version = 'dkim2-datasource-v3'
	  AND operation_id ~ '^[a-z2-7]{25}[aeimquy4]$'
      AND operation_id <> repeat('a', 26)
      AND octet_length(candidate_digest) = 32
      AND candidate_digest <> decode(repeat('00', 32), 'hex')
    ) OR (
      schema_version <> 'dkim2-datasource-v3'
      AND operation_id IS NULL
      AND candidate_digest IS NULL
    )
  ),
  ADD CONSTRAINT dataset_generations_history_check
    CHECK (dataset_state = 'committed' OR NOT was_active);

ALTER TABLE dkim2_datasource.current_generation
  ADD COLUMN candidate_digest bytea,
  ADD CONSTRAINT current_generation_digest_check CHECK (
    candidate_digest IS NULL OR (
      octet_length(candidate_digest) = 32
      AND candidate_digest <> decode(repeat('00', 32), 'hex')
    )
  );

CREATE TABLE dkim2_datasource.administration_lock (
  singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  lock_revision dkim2_datasource.generation_number NOT NULL DEFAULT 1,
  lock_operation_id text COLLATE "C",
  CONSTRAINT administration_lock_owner_check CHECK (
    lock_operation_id IS NULL OR (
	  lock_operation_id ~ '^[a-z2-7]{25}[aeimquy4]$'
      AND lock_operation_id <> repeat('a', 26)
    )
  )
);

INSERT INTO dkim2_datasource.administration_lock
  (singleton, lock_revision, lock_operation_id)
VALUES (TRUE, 1, NULL);

CREATE FUNCTION dkim2_datasource.enforce_administration_lock_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'administration lock is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD.singleton <> NEW.singleton THEN
    RAISE EXCEPTION 'administration lock is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD.lock_operation_id IS NULL
     AND NEW.lock_operation_id IS NOT NULL
     AND NEW.lock_revision = OLD.lock_revision THEN
    RETURN NEW;
  END IF;
  IF OLD.lock_operation_id IS NOT NULL
     AND NEW.lock_operation_id IS NULL
     AND NEW.lock_revision = OLD.lock_revision + 1 THEN
    RETURN NEW;
  END IF;
  IF OLD.lock_operation_id IS NOT DISTINCT FROM NEW.lock_operation_id
     AND OLD.lock_revision = NEW.lock_revision THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'invalid administration lock transition' USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER administration_lock_transition
  BEFORE UPDATE OR DELETE ON dkim2_datasource.administration_lock
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.enforce_administration_lock_transition();

CREATE OR REPLACE FUNCTION dkim2_datasource.enforce_generation_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
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
     AND EXISTS (
       SELECT 1 FROM dkim2_datasource.current_generation
        WHERE generation = OLD.generation
     ) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'dataset generation is immutable' USING ERRCODE = '55000';
END
$$;

CREATE OR REPLACE FUNCTION dkim2_datasource.enforce_current_generation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  state text;
  digest bytea;
BEGIN
  SELECT dataset_state, candidate_digest INTO state, digest
    FROM dkim2_datasource.dataset_generations
   WHERE generation = NEW.generation;
  IF state IS DISTINCT FROM 'committed'
     OR NEW.candidate_digest IS DISTINCT FROM digest
     OR (TG_OP = 'UPDATE' AND NEW.generation <= OLD.generation) THEN
    RAISE EXCEPTION 'current generation must match forward committed data'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dkim2_snapshot') THEN
    CREATE ROLE dkim2_snapshot NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dkim2_stager') THEN
    CREATE ROLE dkim2_stager NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dkim2_activator') THEN
    CREATE ROLE dkim2_activator NOLOGIN;
  END IF;
END
$$;

REVOKE ALL ON dkim2_datasource.administration_lock FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA dkim2_datasource FROM
  dkim2_runtime, dkim2_publisher, dkim2_snapshot, dkim2_stager, dkim2_activator;
GRANT USAGE ON SCHEMA dkim2_datasource TO
  dkim2_runtime, dkim2_publisher, dkim2_snapshot, dkim2_stager, dkim2_activator;

GRANT SELECT ON dkim2_datasource.dataset_generations,
  dkim2_datasource.current_generation, dkim2_datasource.handles,
  dkim2_datasource.profiles, dkim2_datasource.credentials,
  dkim2_datasource.policies, dkim2_datasource.key_material TO
  dkim2_runtime, dkim2_publisher, dkim2_snapshot, dkim2_stager, dkim2_activator;

GRANT INSERT ON dkim2_datasource.dataset_generations,
  dkim2_datasource.handles, dkim2_datasource.profiles,
  dkim2_datasource.credentials, dkim2_datasource.policies,
  dkim2_datasource.key_material TO dkim2_publisher, dkim2_stager;
GRANT UPDATE (dataset_state) ON dkim2_datasource.dataset_generations TO
  dkim2_publisher, dkim2_stager;
GRANT INSERT ON dkim2_datasource.current_generation TO
  dkim2_publisher, dkim2_activator;
GRANT UPDATE (generation, candidate_digest) ON dkim2_datasource.current_generation TO
  dkim2_publisher, dkim2_activator;
GRANT UPDATE (was_active) ON dkim2_datasource.dataset_generations TO dkim2_activator;
CREATE FUNCTION dkim2_datasource.administration_lock_observe(
) RETURNS TABLE(lock_revision text, lock_operation_id text)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT lock.lock_revision::text, lock.lock_operation_id
    FROM dkim2_datasource.administration_lock AS lock
   WHERE lock.singleton = TRUE
$$;
REVOKE ALL ON FUNCTION dkim2_datasource.administration_lock_observe() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dkim2_datasource.administration_lock_observe()
  TO dkim2_snapshot, dkim2_stager, dkim2_activator;

CREATE FUNCTION dkim2_datasource.administration_lock_for_update(
) RETURNS TABLE(lock_revision text, lock_operation_id text)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT lock.lock_revision::text, lock.lock_operation_id
    FROM dkim2_datasource.administration_lock AS lock
   WHERE lock.singleton = TRUE
   FOR UPDATE
$$;
REVOKE ALL ON FUNCTION dkim2_datasource.administration_lock_for_update() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dkim2_datasource.administration_lock_for_update()
  TO dkim2_stager, dkim2_activator;

CREATE FUNCTION dkim2_datasource.candidate_root_for_update(
  selected_generation dkim2_datasource.generation_number,
  selected_operation text,
  selected_digest bytea
) RETURNS TABLE(
  generation text,
  schema_version text,
  dataset_state text,
  operation_id text,
  candidate_digest bytea,
  was_active boolean
)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT candidate.generation::text, candidate.schema_version,
         candidate.dataset_state, candidate.operation_id,
         candidate.candidate_digest, candidate.was_active
    FROM dkim2_datasource.dataset_generations AS candidate
   WHERE candidate.generation = selected_generation
     AND candidate.schema_version = 'dkim2-datasource-v3'
     AND candidate.dataset_state = 'committed'
     AND candidate.operation_id = selected_operation
     AND candidate.candidate_digest = selected_digest
   FOR UPDATE
$$;
REVOKE ALL ON FUNCTION dkim2_datasource.candidate_root_for_update(
  dkim2_datasource.generation_number, text, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dkim2_datasource.candidate_root_for_update(
  dkim2_datasource.generation_number, text, bytea
) TO dkim2_activator;

CREATE PROCEDURE dkim2_datasource.administration_lock_claim(
  selected_revision dkim2_datasource.generation_number,
  selected_operation text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
BEGIN
  UPDATE dkim2_datasource.administration_lock
     SET lock_operation_id = selected_operation
   WHERE singleton = TRUE AND lock_revision = selected_revision
     AND lock_operation_id IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'administration lock claim denied' USING ERRCODE = '55000';
  END IF;
END
$$;
REVOKE ALL ON PROCEDURE dkim2_datasource.administration_lock_claim(
  dkim2_datasource.generation_number, text
) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE dkim2_datasource.administration_lock_claim(
  dkim2_datasource.generation_number, text
) TO dkim2_stager;

CREATE PROCEDURE dkim2_datasource.administration_lock_release(
  selected_revision dkim2_datasource.generation_number,
  selected_operation text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
BEGIN
  UPDATE dkim2_datasource.administration_lock
     SET lock_revision = lock_revision + 1, lock_operation_id = NULL
   WHERE singleton = TRUE AND lock_revision = selected_revision
     AND lock_operation_id = selected_operation;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'administration lock release denied' USING ERRCODE = '55000';
  END IF;
END
$$;
REVOKE ALL ON PROCEDURE dkim2_datasource.administration_lock_release(
  dkim2_datasource.generation_number, text
) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE dkim2_datasource.administration_lock_release(
  dkim2_datasource.generation_number, text
) TO dkim2_stager;

CREATE FUNCTION dkim2_datasource.administration_lock_owned_by(
  selected_operation text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT EXISTS (
    SELECT 1 FROM dkim2_datasource.administration_lock
     WHERE singleton = TRUE AND lock_operation_id = selected_operation
  )
$$;
REVOKE ALL ON FUNCTION dkim2_datasource.administration_lock_owned_by(text)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dkim2_datasource.administration_lock_owned_by(text)
  TO dkim2_stager, dkim2_activator;

CREATE FUNCTION dkim2_datasource.administration_lock_is_owned(
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT EXISTS (
    SELECT 1 FROM dkim2_datasource.administration_lock
     WHERE singleton = TRUE AND lock_operation_id IS NOT NULL
  )
$$;
REVOKE ALL ON FUNCTION dkim2_datasource.administration_lock_is_owned()
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dkim2_datasource.administration_lock_is_owned()
  TO dkim2_activator;

ALTER TABLE dkim2_datasource.dataset_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE dkim2_datasource.current_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE dkim2_datasource.handles ENABLE ROW LEVEL SECURITY;
ALTER TABLE dkim2_datasource.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE dkim2_datasource.credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE dkim2_datasource.policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE dkim2_datasource.key_material ENABLE ROW LEVEL SECURITY;

CREATE POLICY dataset_read ON dkim2_datasource.dataset_generations FOR SELECT
  TO dkim2_runtime, dkim2_publisher, dkim2_snapshot, dkim2_stager, dkim2_activator
  USING (TRUE);
CREATE POLICY dataset_legacy_v2 ON dkim2_datasource.dataset_generations
  TO dkim2_publisher
  USING (schema_version = 'dkim2-datasource-v2')
  WITH CHECK (schema_version = 'dkim2-datasource-v2');
CREATE POLICY dataset_stage_v3 ON dkim2_datasource.dataset_generations
  TO dkim2_stager
  USING (schema_version = 'dkim2-datasource-v3')
  WITH CHECK (
    schema_version = 'dkim2-datasource-v3' AND NOT was_active
    AND dkim2_datasource.administration_lock_owned_by(operation_id)
  );
CREATE POLICY dataset_activate_history ON dkim2_datasource.dataset_generations
  FOR UPDATE TO dkim2_activator
  USING (
    dataset_state = 'committed'
    AND EXISTS (
      SELECT 1 FROM dkim2_datasource.current_generation AS current
       WHERE current.generation = dataset_generations.generation
    )
    AND dkim2_datasource.administration_lock_is_owned()
  )
  WITH CHECK (
    dataset_state = 'committed' AND was_active
    AND EXISTS (
      SELECT 1 FROM dkim2_datasource.current_generation AS current
       WHERE current.generation = dataset_generations.generation
    )
    AND dkim2_datasource.administration_lock_is_owned()
  );

CREATE POLICY current_read ON dkim2_datasource.current_generation FOR SELECT
  TO dkim2_runtime, dkim2_publisher, dkim2_snapshot, dkim2_stager, dkim2_activator
  USING (TRUE);
CREATE POLICY current_legacy_v2 ON dkim2_datasource.current_generation
  TO dkim2_publisher
  USING (EXISTS (
    SELECT 1 FROM dkim2_datasource.dataset_generations AS generation
     WHERE generation.generation = current_generation.generation
       AND generation.schema_version = 'dkim2-datasource-v2'
  ))
  WITH CHECK (candidate_digest IS NULL AND EXISTS (
    SELECT 1 FROM dkim2_datasource.dataset_generations AS generation
     WHERE generation.generation = current_generation.generation
       AND generation.schema_version = 'dkim2-datasource-v2'
  ));
CREATE POLICY current_activate_v3 ON dkim2_datasource.current_generation
  TO dkim2_activator
  USING (TRUE)
  WITH CHECK (candidate_digest IS NOT NULL AND EXISTS (
    SELECT 1 FROM dkim2_datasource.dataset_generations AS generation
     WHERE generation.generation = current_generation.generation
       AND generation.schema_version = 'dkim2-datasource-v3'
       AND generation.dataset_state = 'committed'
	   AND generation.candidate_digest = current_generation.candidate_digest
	   AND dkim2_datasource.administration_lock_owned_by(generation.operation_id)
  ));

CREATE OR REPLACE FUNCTION dkim2_datasource.generation_is_version(
  selected_generation dkim2_datasource.generation_number,
  selected_version text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT EXISTS (
    SELECT 1 FROM dkim2_datasource.dataset_generations
	 WHERE generation = selected_generation AND schema_version = selected_version
	   AND dataset_state = 'staging'
	   AND (
	     selected_version = 'dkim2-datasource-v2'
	     OR dkim2_datasource.administration_lock_owned_by(operation_id)
	   )
  )
$$;
REVOKE ALL ON FUNCTION dkim2_datasource.generation_is_version(
  dkim2_datasource.generation_number, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dkim2_datasource.generation_is_version(
  dkim2_datasource.generation_number, text
) TO dkim2_publisher, dkim2_stager;

DO $$
DECLARE
  child text;
BEGIN
  FOREACH child IN ARRAY ARRAY['handles', 'profiles', 'credentials', 'policies', 'key_material']
  LOOP
    EXECUTE format(
      'CREATE POLICY %I ON dkim2_datasource.%I FOR SELECT TO dkim2_runtime, dkim2_publisher, dkim2_snapshot, dkim2_stager, dkim2_activator USING (TRUE)',
      child || '_read', child
    );
    EXECUTE format(
      'CREATE POLICY %I ON dkim2_datasource.%I FOR INSERT TO dkim2_publisher WITH CHECK (dkim2_datasource.generation_is_version(generation, %L))',
      child || '_legacy_v2', child, 'dkim2-datasource-v2'
    );
    EXECUTE format(
      'CREATE POLICY %I ON dkim2_datasource.%I FOR INSERT TO dkim2_stager WITH CHECK (dkim2_datasource.generation_is_version(generation, %L))',
      child || '_stage_v3', child, 'dkim2-datasource-v3'
    );
  END LOOP;
END
$$;

COMMIT;
