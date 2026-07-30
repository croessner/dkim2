BEGIN;

CREATE SCHEMA IF NOT EXISTS dkim2_datasource;

CREATE DOMAIN dkim2_datasource.generation_number AS numeric(20,0)
  CHECK (VALUE >= 1 AND VALUE <= 18446744073709551615);
CREATE DOMAIN dkim2_datasource.identifier AS text COLLATE "C"
  CHECK (octet_length(VALUE) BETWEEN 1 AND 128);
CREATE DOMAIN dkim2_datasource.domain_name AS text COLLATE "C"
  CHECK (octet_length(VALUE) BETWEEN 1 AND 253);
CREATE DOMAIN dkim2_datasource.selector_name AS text COLLATE "C"
  CHECK (octet_length(VALUE) BETWEEN 1 AND 253);
CREATE DOMAIN dkim2_datasource.validity_text AS text COLLATE "C"
  CHECK (octet_length(VALUE) BETWEEN 20 AND 40);

CREATE TABLE dkim2_datasource.dataset_generations (
  generation dkim2_datasource.generation_number PRIMARY KEY,
  schema_version text COLLATE "C" NOT NULL
    CHECK (schema_version = 'dkim2-datasource-v1'),
  dataset_state text COLLATE "C" NOT NULL
    CHECK (dataset_state IN ('staging', 'committed'))
);

CREATE TABLE dkim2_datasource.current_generation (
  singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  generation dkim2_datasource.generation_number NOT NULL UNIQUE
    REFERENCES dkim2_datasource.dataset_generations(generation)
);

CREATE TABLE dkim2_datasource.handles (
  generation dkim2_datasource.generation_number NOT NULL
    REFERENCES dkim2_datasource.dataset_generations(generation),
  handle_id dkim2_datasource.identifier NOT NULL,
  PRIMARY KEY (generation, handle_id)
);

CREATE TABLE dkim2_datasource.profiles (
  generation dkim2_datasource.generation_number NOT NULL
    REFERENCES dkim2_datasource.dataset_generations(generation),
  profile_id dkim2_datasource.identifier NOT NULL,
  signing_domain dkim2_datasource.domain_name NOT NULL,
  record_status text COLLATE "C" NOT NULL
    CHECK (record_status IN ('active', 'disabled')),
  not_before_utc dkim2_datasource.validity_text,
  not_after_utc dkim2_datasource.validity_text,
  PRIMARY KEY (generation, profile_id),
  UNIQUE (generation, profile_id, signing_domain),
  CHECK ((not_before_utc IS NULL) = (not_after_utc IS NULL))
);

CREATE TABLE dkim2_datasource.credentials (
  generation dkim2_datasource.generation_number NOT NULL,
  profile_id dkim2_datasource.identifier NOT NULL,
  algorithm text COLLATE "C" NOT NULL
    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256')),
  selector dkim2_datasource.selector_name NOT NULL,
  public_key_spki bytea NOT NULL
    CHECK (octet_length(public_key_spki) BETWEEN 1 AND 2048),
  handle_id dkim2_datasource.identifier NOT NULL,
  PRIMARY KEY (generation, profile_id, algorithm),
  UNIQUE (generation, profile_id, selector),
  UNIQUE (generation, handle_id),
  FOREIGN KEY (generation, profile_id)
    REFERENCES dkim2_datasource.profiles(generation, profile_id),
  FOREIGN KEY (generation, handle_id)
    REFERENCES dkim2_datasource.handles(generation, handle_id)
);

CREATE TABLE dkim2_datasource.policies (
  generation dkim2_datasource.generation_number NOT NULL,
  tenant_id dkim2_datasource.identifier NOT NULL,
  signing_domain dkim2_datasource.domain_name NOT NULL,
  profile_use text COLLATE "C" NOT NULL
    CHECK (profile_use IN ('originator', 'ordinary_transit', 'next_domain_transit')),
  profile_id dkim2_datasource.identifier NOT NULL,
  record_status text COLLATE "C" NOT NULL
    CHECK (record_status IN ('active', 'disabled')),
  rollout text COLLATE "C" NOT NULL
    CHECK (rollout IN ('enforce', 'observe', 'off')),
  compatibility text COLLATE "C" NOT NULL CHECK (compatibility = 'strict'),
  feedback_route_id dkim2_datasource.identifier,
  PRIMARY KEY (generation, tenant_id, signing_domain, profile_use),
  FOREIGN KEY (generation, profile_id, signing_domain)
    REFERENCES dkim2_datasource.profiles(generation, profile_id, signing_domain)
);

CREATE INDEX profiles_domain_idx
  ON dkim2_datasource.profiles (generation, signing_domain);
CREATE INDEX credentials_selector_idx
  ON dkim2_datasource.credentials (generation, selector);
CREATE INDEX policies_profile_idx
  ON dkim2_datasource.policies (generation, profile_id);

CREATE FUNCTION dkim2_datasource.deny_committed_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM dkim2_datasource.dataset_generations
     WHERE generation = OLD.generation
       AND dataset_state = 'committed'
  ) THEN
    RAISE EXCEPTION 'committed generation is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END
$$;

CREATE FUNCTION dkim2_datasource.enforce_generation_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE'
     OR OLD.generation <> NEW.generation
     OR OLD.schema_version <> NEW.schema_version
     OR OLD.dataset_state <> 'staging'
     OR NEW.dataset_state <> 'committed' THEN
    RAISE EXCEPTION 'dataset generation is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION dkim2_datasource.enforce_current_generation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  state text;
BEGIN
  SELECT dataset_state INTO state
    FROM dkim2_datasource.dataset_generations
   WHERE generation = NEW.generation;
  IF state IS DISTINCT FROM 'committed'
     OR (TG_OP = 'UPDATE' AND NEW.generation <= OLD.generation) THEN
    RAISE EXCEPTION 'current generation must move forward to committed data'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER dataset_generations_immutable
  BEFORE UPDATE OR DELETE ON dkim2_datasource.dataset_generations
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.enforce_generation_transition();
CREATE TRIGGER current_generation_forward_only
  BEFORE INSERT OR UPDATE ON dkim2_datasource.current_generation
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.enforce_current_generation();
CREATE TRIGGER handles_immutable
  BEFORE UPDATE OR DELETE ON dkim2_datasource.handles
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.deny_committed_mutation();
CREATE TRIGGER profiles_immutable
  BEFORE UPDATE OR DELETE ON dkim2_datasource.profiles
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.deny_committed_mutation();
CREATE TRIGGER credentials_immutable
  BEFORE UPDATE OR DELETE ON dkim2_datasource.credentials
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.deny_committed_mutation();
CREATE TRIGGER policies_immutable
  BEFORE UPDATE OR DELETE ON dkim2_datasource.policies
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.deny_committed_mutation();

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dkim2_runtime') THEN
    CREATE ROLE dkim2_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dkim2_publisher') THEN
    CREATE ROLE dkim2_publisher NOLOGIN;
  END IF;
END
$$;

REVOKE ALL ON SCHEMA dkim2_datasource FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA dkim2_datasource FROM PUBLIC;
GRANT USAGE ON SCHEMA dkim2_datasource TO dkim2_runtime, dkim2_publisher;
GRANT SELECT ON ALL TABLES IN SCHEMA dkim2_datasource TO dkim2_runtime;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA dkim2_datasource TO dkim2_publisher;
GRANT UPDATE (dataset_state) ON dkim2_datasource.dataset_generations TO dkim2_publisher;
GRANT UPDATE (generation) ON dkim2_datasource.current_generation TO dkim2_publisher;

COMMIT;
