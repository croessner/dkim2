-- Forward-only immutable terminal evidence for one campaign operation.
BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;

CREATE TABLE dkim2_datasource.campaign_terminals (
  operation_id text COLLATE "C" PRIMARY KEY CHECK (operation_id ~ '^[a-z2-7]{25}[aeimquy4]$' AND operation_id <> repeat('a', 26)),
  schema_version text COLLATE "C" NOT NULL CHECK (schema_version = 'dkim2-datasource-v3'),
  source_schema text COLLATE "C" NOT NULL CHECK (source_schema IN ('dkim2-datasource-v2', 'dkim2-datasource-v3')),
  source_generation dkim2_datasource.generation_number NOT NULL,
  candidate_generation dkim2_datasource.generation_number NOT NULL,
  current_generation dkim2_datasource.generation_number NOT NULL,
  candidate_digest bytea NOT NULL CHECK (octet_length(candidate_digest) = 32),
  terminal_state text COLLATE "C" NOT NULL CHECK (terminal_state IN ('closed', 'aborted')),
  terminal_reason text COLLATE "C" NOT NULL CHECK (terminal_reason IN ('activated', 'operator_abort', 'reconcile_abort')),
  terminal_time timestamptz NOT NULL,
  CHECK (candidate_generation > source_generation),
  CHECK ((terminal_state = 'closed' AND terminal_reason = 'activated' AND current_generation = candidate_generation) OR
         (terminal_state = 'aborted' AND terminal_reason IN ('operator_abort', 'reconcile_abort') AND current_generation = source_generation))
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dkim2_closer') THEN CREATE ROLE dkim2_closer NOLOGIN; END IF;
END $$;

CREATE OR REPLACE PROCEDURE dkim2_datasource.record_campaign_terminal(
  selected_operation text, selected_schema text, selected_source_schema text, selected_source dkim2_datasource.generation_number,
  selected_candidate dkim2_datasource.generation_number, selected_current dkim2_datasource.generation_number,
  selected_digest bytea, selected_state text, selected_reason text, selected_time timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, dkim2_datasource AS $$
BEGIN
  PERFORM 1 FROM dkim2_datasource.administration_lock WHERE singleton = TRUE AND lock_operation_id = selected_operation FOR UPDATE;
  IF NOT FOUND OR selected_schema <> 'dkim2-datasource-v3' OR selected_source_schema NOT IN ('dkim2-datasource-v2', 'dkim2-datasource-v3') OR selected_candidate <= selected_source OR octet_length(selected_digest) <> 32 THEN
    RAISE EXCEPTION 'terminal closure denied' USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM dkim2_datasource.current_generation WHERE singleton = TRUE AND generation = selected_current) THEN
    RAISE EXCEPTION 'terminal current denied' USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM dkim2_datasource.dataset_generations WHERE generation = selected_candidate AND schema_version = selected_schema AND candidate_digest = selected_digest) THEN
    RAISE EXCEPTION 'terminal candidate denied' USING ERRCODE = '55000';
  END IF;
  INSERT INTO dkim2_datasource.campaign_terminals VALUES (selected_operation, selected_schema, selected_source_schema, selected_source, selected_candidate, selected_current, selected_digest, selected_state, selected_reason, selected_time);
END $$;

REVOKE ALL ON dkim2_datasource.campaign_terminals FROM PUBLIC;
REVOKE ALL ON PROCEDURE dkim2_datasource.record_campaign_terminal(text, text, text, dkim2_datasource.generation_number, dkim2_datasource.generation_number, dkim2_datasource.generation_number, bytea, text, text, timestamptz) FROM PUBLIC;
GRANT USAGE ON SCHEMA dkim2_datasource TO dkim2_closer;
GRANT SELECT ON dkim2_datasource.campaign_terminals TO dkim2_closer;
GRANT EXECUTE ON PROCEDURE dkim2_datasource.record_campaign_terminal(text, text, text, dkim2_datasource.generation_number, dkim2_datasource.generation_number, dkim2_datasource.generation_number, bytea, text, text, timestamptz) TO dkim2_closer;
COMMIT;
