-- Forward-only MySQL 8.4 and MariaDB 10.11 campaign fence upgrade from native
-- domain onboarding v3. Apply with all DKIM2 writers stopped. The immutable
-- v3 row shape remains unchanged; retention and destructive purge are owned by
-- later explicit migrations.

SET NAMES utf8mb4 COLLATE utf8mb4_bin;

DELIMITER //
CREATE PROCEDURE dkim2_campaign_upgrade_requires_v3()
READS SQL DATA
BEGIN
    IF EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE schema_version NOT IN ('dkim2-datasource-v2', 'dkim2-datasource-v3')
            OR (schema_version = 'dkim2-datasource-v3' AND
                (dataset_state NOT IN ('staging', 'committed') OR
                 candidate_digest IS NULL))
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 campaign upgrade requires exact v3 metadata';
    END IF;
END//
DELIMITER ;

CREATE TABLE dkim2_purge_audit_receipts (
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    schema_version VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    lifecycle VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    content_digest BINARY(32) NOT NULL,
    policy_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    purge_plan_digest BINARY(32) NOT NULL,
    destroyed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (generation),
    CONSTRAINT dkim2_purge_schema CHECK (schema_version = 'dkim2-datasource-v3'),
    CONSTRAINT dkim2_purge_lifecycle CHECK (lifecycle IN ('active_history', 'never_active'))
) ENGINE=InnoDB;

DELIMITER //
CREATE PROCEDURE dkim2_v3_purge_generation(
    IN selected_generation DECIMAL(20,0), IN selected_schema VARCHAR(32),
    IN selected_digest BLOB, IN selected_current DECIMAL(20,0),
    IN selected_lifecycle VARCHAR(32), IN selected_policy VARCHAR(128),
    IN selected_plan BLOB
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    DECLARE target_was_active BOOLEAN;
    SELECT lock_operation_id INTO @dkim2_purge_owner
      FROM dkim2_publication_lock WHERE singleton = 1 FOR UPDATE;
    IF @dkim2_purge_owner IS NOT NULL OR selected_generation = selected_current OR
       selected_schema <> 'dkim2-datasource-v3' OR
       selected_lifecycle NOT IN ('active_history', 'never_active') OR
       OCTET_LENGTH(selected_digest) <> 32 OR OCTET_LENGTH(selected_plan) <> 32 OR
       OCTET_LENGTH(selected_policy) = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 purge target denied';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_current_generation
         WHERE singleton = 1 AND generation = selected_current
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 purge fence denied';
    END IF;
    SELECT was_active INTO target_was_active FROM dkim2_dataset_generations
     WHERE generation = selected_generation AND schema_version = selected_schema
       AND dataset_state = 'committed' AND candidate_digest <=> selected_digest
     FOR UPDATE;
    IF target_was_active IS NULL OR
       (selected_lifecycle = 'active_history') <> target_was_active OR EXISTS (
           SELECT 1 FROM dkim2_current_generation WHERE generation = selected_generation
       ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 purge target denied';
    END IF;
    DELETE FROM dkim2_key_material WHERE generation = selected_generation;
    DELETE FROM dkim2_credentials WHERE generation = selected_generation;
    DELETE FROM dkim2_policies WHERE generation = selected_generation;
    DELETE FROM dkim2_profiles WHERE generation = selected_generation;
    DELETE FROM dkim2_handles WHERE generation = selected_generation;
    DELETE FROM dkim2_dataset_generations WHERE generation = selected_generation;
    INSERT INTO dkim2_purge_audit_receipts
        (generation, schema_version, lifecycle, content_digest, policy_version, purge_plan_digest)
    VALUES (selected_generation, selected_schema, selected_lifecycle, selected_digest, selected_policy, selected_plan);
END//
DELIMITER ;
CALL dkim2_campaign_upgrade_requires_v3();
DROP PROCEDURE dkim2_campaign_upgrade_requires_v3;

DELIMITER //
DROP PROCEDURE dkim2_v3_insert_generation//
CREATE PROCEDURE dkim2_v3_insert_generation(
    IN selected_generation DECIMAL(20,0), IN selected_operation VARCHAR(128),
    IN selected_digest BLOB, IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_metadata(selected_operation, selected_digest);
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_publication_lock
         WHERE singleton = 1 AND lock_revision = selected_revision
           AND lock_operation_id = selected_operation
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 lock denied';
    END IF;
    IF EXISTS (
        SELECT 1 FROM dkim2_current_generation
         WHERE singleton = 1 AND selected_generation <= generation
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 candidate generation denied';
    END IF;
    INSERT INTO dkim2_dataset_generations
        (generation, schema_version, dataset_state, operation_id, candidate_digest, was_active)
    VALUES (
        selected_generation, 'dkim2-datasource-v3', 'staging',
        selected_operation, selected_digest, FALSE
    );
END//
DELIMITER ;
