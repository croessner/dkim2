-- Forward-only MySQL-family locked current fence source projection.
-- 006 added dkim2_dataset_generations.source_generation and recreated the
-- candidate and insert routines, but dkim2_v3_current_for_update still
-- returned the pre-006 seven-column shape. The locked current read must
-- project exactly the columns of the unlocked current read, so this routine
-- is recreated with the frozen source generation between the candidate digest
-- and the current pointer digest. Legacy rows keep a NULL source generation.

DELIMITER //
DROP PROCEDURE dkim2_v3_current_for_update//
CREATE PROCEDURE dkim2_v3_current_for_update()
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    SELECT CAST(current_generation.generation AS CHAR), dataset.schema_version,
           dataset.dataset_state, dataset.operation_id, dataset.candidate_digest,
           CAST(dataset.source_generation AS CHAR), current_generation.candidate_digest,
           dataset.was_active
      FROM dkim2_current_generation AS current_generation
      JOIN dkim2_dataset_generations AS dataset USING (generation)
     WHERE current_generation.singleton = 1
     FOR UPDATE;
END//
DELIMITER ;

-- Recreating a routine drops its EXECUTE privileges; MySQL-family servers
-- never expose new routines to unprivileged accounts by default.
-- Accounts and grants remain a site-owned operation. Apply the reviewed
-- 002_least_privilege_grants.sql.example after this upgrade.
