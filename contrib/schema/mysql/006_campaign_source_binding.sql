-- Forward-only source-generation binding for v3 campaign candidates.
ALTER TABLE dkim2_dataset_generations
  ADD COLUMN source_generation DECIMAL(20,0) UNSIGNED NULL,
  ADD CONSTRAINT dkim2_source_generation_check CHECK (
    source_generation IS NULL OR
    (schema_version = 'dkim2-datasource-v3' AND operation_id IS NOT NULL AND source_generation < generation)
  );

-- Existing rows are legacy/unknown and intentionally remain retained.

DELIMITER //
DROP PROCEDURE dkim2_v3_lock_candidate_root//
CREATE PROCEDURE dkim2_v3_lock_candidate_root(
    IN selected_generation DECIMAL(20,0), IN selected_operation VARCHAR(128),
    IN selected_digest BLOB, IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_metadata(selected_operation, selected_digest);
    IF NOT EXISTS (SELECT 1 FROM dkim2_publication_lock WHERE singleton = 1 AND lock_revision = selected_revision AND lock_operation_id = selected_operation FOR UPDATE)
       OR NOT EXISTS (SELECT 1 FROM dkim2_dataset_generations WHERE generation = selected_generation AND schema_version = 'dkim2-datasource-v3' AND dataset_state = 'committed' AND operation_id = selected_operation AND candidate_digest = selected_digest FOR UPDATE) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 candidate lock denied';
    END IF;
    SELECT CAST(generation AS CHAR), schema_version, dataset_state, operation_id, candidate_digest, CAST(source_generation AS CHAR), was_active
      FROM dkim2_dataset_generations WHERE generation = selected_generation AND schema_version = 'dkim2-datasource-v3' AND dataset_state = 'committed' AND operation_id = selected_operation AND candidate_digest = selected_digest;
END//

DROP PROCEDURE dkim2_v3_insert_generation//
CREATE PROCEDURE dkim2_v3_insert_generation(
    IN selected_generation DECIMAL(20,0), IN selected_operation VARCHAR(128),
    IN selected_digest BLOB, IN selected_source DECIMAL(20,0),
    IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_metadata(selected_operation, selected_digest);
    IF selected_source = 0 OR selected_source >= selected_generation THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 source generation denied';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM dkim2_publication_lock WHERE singleton = 1 AND lock_revision = selected_revision AND lock_operation_id = selected_operation) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 lock denied';
    END IF;
    INSERT INTO dkim2_dataset_generations (generation, schema_version, dataset_state, operation_id, candidate_digest, source_generation, was_active)
    VALUES (selected_generation, 'dkim2-datasource-v3', 'staging', selected_operation, selected_digest, selected_source, FALSE);
END//
REVOKE EXECUTE ON PROCEDURE dkim2_v3_lock_candidate_root FROM PUBLIC//
GRANT EXECUTE ON PROCEDURE dkim2_v3_lock_candidate_root TO dkim2_activator//
REVOKE EXECUTE ON PROCEDURE dkim2_v3_insert_generation FROM PUBLIC//
GRANT EXECUTE ON PROCEDURE dkim2_v3_insert_generation TO dkim2_stager//
DELIMITER ;
