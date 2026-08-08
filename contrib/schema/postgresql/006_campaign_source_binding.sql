-- Forward-only source-generation binding for v3 campaign candidates.
ALTER TABLE dkim2_datasource.dataset_generations
  ADD COLUMN source_generation dkim2_datasource.generation_number;

ALTER TABLE dkim2_datasource.dataset_generations
  ADD CONSTRAINT dataset_generations_source_generation_check CHECK (
    source_generation IS NULL OR
    (schema_version = 'dkim2-datasource-v3' AND operation_id IS NOT NULL AND source_generation < generation)
  );

-- Existing generations are legacy/unknown and remain retained; new campaign
-- candidates must carry an immutable source_generation from their envelope.

DROP FUNCTION dkim2_datasource.candidate_root_for_update(
  dkim2_datasource.generation_number, text, bytea
);
CREATE FUNCTION dkim2_datasource.candidate_root_for_update(
  selected_generation dkim2_datasource.generation_number,
  selected_operation text,
  selected_digest bytea
) RETURNS TABLE(
  generation text, schema_version text, dataset_state text, operation_id text,
  candidate_digest bytea, source_generation text, was_active boolean
)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, dkim2_datasource
AS $$
  SELECT candidate.generation::text, candidate.schema_version,
         candidate.dataset_state, candidate.operation_id,
         candidate.candidate_digest, candidate.source_generation::text,
         candidate.was_active
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
