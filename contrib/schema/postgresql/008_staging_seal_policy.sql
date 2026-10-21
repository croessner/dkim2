-- Forward-only PostgreSQL staging seal authority repair.
-- Apply with all DKIM2 writers stopped. 004 recreated dataset_stage_v3 without
-- a command clause, so its staging-only WITH CHECK also governed UPDATE and
-- rejected the stager's own staging -> committed seal. This migration splits
-- the policy: INSERT keeps the staging-only forward-candidate check, and a
-- separate UPDATE policy admits only the seal of an inactive v3 candidate whose
-- operation owns the administration lock. The column privilege from 003 still
-- limits the stager to UPDATE (dataset_state), and the immutable-generation
-- trigger from 001 still permits only the staging -> committed transition.

BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;

LOCK TABLE dkim2_datasource.dataset_generations,
  dkim2_datasource.current_generation,
  dkim2_datasource.administration_lock IN ACCESS EXCLUSIVE MODE;

DROP POLICY dataset_stage_v3 ON dkim2_datasource.dataset_generations;
CREATE POLICY dataset_stage_v3 ON dkim2_datasource.dataset_generations
  FOR INSERT TO dkim2_stager
  WITH CHECK (
    schema_version = 'dkim2-datasource-v3'
    AND dataset_state = 'staging'
    AND NOT was_active
    AND candidate_digest IS NOT NULL
    AND dkim2_datasource.administration_lock_owned_by(operation_id)
    AND dkim2_datasource.campaign_candidate_generation_is_forward(generation)
  );

CREATE POLICY dataset_seal_v3 ON dkim2_datasource.dataset_generations
  FOR UPDATE TO dkim2_stager
  USING (
    schema_version = 'dkim2-datasource-v3'
    AND dataset_state = 'staging'
    AND NOT was_active
    AND candidate_digest IS NOT NULL
    AND dkim2_datasource.administration_lock_owned_by(operation_id)
  )
  WITH CHECK (
    schema_version = 'dkim2-datasource-v3'
    AND dataset_state = 'committed'
    AND NOT was_active
    AND candidate_digest IS NOT NULL
    AND dkim2_datasource.administration_lock_owned_by(operation_id)
    AND dkim2_datasource.campaign_candidate_generation_is_forward(generation)
  );

COMMIT;
