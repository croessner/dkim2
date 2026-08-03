-- Forward-only MySQL 8.4 and MariaDB 10.11 upgrade from native-custody v2.
-- Stop all writers before applying. ALTER TABLE performs an implicit commit;
-- after the first ALTER this migration is forward-only and rollback requires
-- restoring the database backup taken before the upgrade.

SET NAMES utf8mb4 COLLATE utf8mb4_bin;

DELIMITER //
CREATE PROCEDURE dkim2_require_v2_upgrade_input()
READS SQL DATA
BEGIN
    IF EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE schema_version <> 'dkim2-datasource-v2'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 upgrade requires exact v2';
    END IF;
END//
DELIMITER ;
CALL dkim2_require_v2_upgrade_input();
DROP PROCEDURE dkim2_require_v2_upgrade_input;

ALTER TABLE dkim2_dataset_generations
    ADD COLUMN operation_id VARCHAR(26) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN candidate_digest BINARY(32) NULL,
    ADD COLUMN was_active BOOLEAN NOT NULL DEFAULT FALSE;

SET @dkim2_drop_schema_check = IF(
    VERSION() LIKE '%MariaDB%',
    'ALTER TABLE dkim2_dataset_generations DROP CONSTRAINT dkim2_schema_version',
    'ALTER TABLE dkim2_dataset_generations DROP CHECK dkim2_schema_version'
);
PREPARE dkim2_drop_statement FROM @dkim2_drop_schema_check;
EXECUTE dkim2_drop_statement;
DEALLOCATE PREPARE dkim2_drop_statement;

ALTER TABLE dkim2_dataset_generations
    ADD CONSTRAINT dkim2_schema_version CHECK (
        schema_version IN ('dkim2-datasource-v2', 'dkim2-datasource-v3')
    ),
    ADD CONSTRAINT dkim2_v3_metadata CHECK (
        (
            schema_version = 'dkim2-datasource-v3' AND
			operation_id REGEXP '^[a-z2-7]{25}[aeimquy4]$' AND
            operation_id <> REPEAT('a', 26) AND
            candidate_digest IS NOT NULL AND
            candidate_digest <> UNHEX(REPEAT('00', 32))
        ) OR (
            schema_version = 'dkim2-datasource-v2' AND
            operation_id IS NULL AND candidate_digest IS NULL
        )
    ),
    ADD CONSTRAINT dkim2_history_state CHECK (
        dataset_state = 'committed' OR was_active = FALSE
    );

ALTER TABLE dkim2_publication_lock
    ADD COLUMN lock_revision DECIMAL(20,0) UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN lock_operation_id VARCHAR(26) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD CONSTRAINT dkim2_lock_revision_range CHECK (
        lock_revision BETWEEN 1 AND 18446744073709551615
    ),
    ADD CONSTRAINT dkim2_lock_owner CHECK (
        lock_operation_id IS NULL OR (
			lock_operation_id REGEXP '^[a-z2-7]{25}[aeimquy4]$' AND
            lock_operation_id <> REPEAT('a', 26)
        )
    );

ALTER TABLE dkim2_current_generation
    ADD COLUMN candidate_digest BINARY(32) NULL,
    ADD CONSTRAINT dkim2_current_digest CHECK (
        candidate_digest IS NULL OR
        candidate_digest <> UNHEX(REPEAT('00', 32))
    );

DELIMITER //

DROP TRIGGER dkim2_dataset_update//
DROP TRIGGER dkim2_current_insert//
DROP TRIGGER dkim2_current_update//

CREATE TRIGGER dkim2_dataset_update BEFORE UPDATE ON dkim2_dataset_generations
FOR EACH ROW
BEGIN
    DECLARE exact_state_transition BOOLEAN DEFAULT FALSE;
    DECLARE exact_history_transition BOOLEAN DEFAULT FALSE;
    SET exact_state_transition =
        OLD.generation = NEW.generation AND
        OLD.schema_version = NEW.schema_version AND
        OLD.operation_id <=> NEW.operation_id AND
        OLD.candidate_digest <=> NEW.candidate_digest AND
        OLD.was_active = NEW.was_active AND
        OLD.dataset_state = 'staging' AND NEW.dataset_state = 'committed';
    SET exact_history_transition =
        OLD.generation = NEW.generation AND
        OLD.schema_version = NEW.schema_version AND
        OLD.operation_id <=> NEW.operation_id AND
        OLD.candidate_digest <=> NEW.candidate_digest AND
        OLD.dataset_state = 'committed' AND NEW.dataset_state = 'committed' AND
		NEW.was_active = TRUE AND
        EXISTS (
            SELECT 1 FROM dkim2_current_generation
             WHERE generation = OLD.generation
        );
    IF NOT exact_state_transition AND NOT exact_history_transition THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 immutable generation';
    END IF;
END//

CREATE TRIGGER dkim2_current_insert BEFORE INSERT ON dkim2_current_generation
FOR EACH ROW
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE generation = NEW.generation AND dataset_state = 'committed'
           AND candidate_digest <=> NEW.candidate_digest
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 invalid current generation';
    END IF;
END//

CREATE TRIGGER dkim2_current_update BEFORE UPDATE ON dkim2_current_generation
FOR EACH ROW
BEGIN
    IF OLD.singleton <> NEW.singleton OR NEW.generation <= OLD.generation OR
       NOT EXISTS (
           SELECT 1 FROM dkim2_dataset_generations
            WHERE generation = NEW.generation AND dataset_state = 'committed'
              AND candidate_digest <=> NEW.candidate_digest
       ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 invalid generation transition';
    END IF;
END//

-- The compatibility procedures retain the deployed v2 publisher without
-- granting it any direct v3 root, child, state, or current mutation.
CREATE PROCEDURE dkim2_v2_insert_generation(IN selected_generation DECIMAL(20,0))
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    INSERT INTO dkim2_dataset_generations
        (generation, schema_version, dataset_state, operation_id, candidate_digest, was_active)
    VALUES (selected_generation, 'dkim2-datasource-v2', 'staging', NULL, NULL, FALSE);
END//

CREATE PROCEDURE dkim2_v2_insert_handle(
    IN selected_generation DECIMAL(20,0), IN selected_handle VARCHAR(128)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v2_staging(selected_generation);
    INSERT INTO dkim2_handles VALUES (selected_generation, selected_handle);
END//

CREATE PROCEDURE dkim2_v2_insert_profile(
    IN selected_generation DECIMAL(20,0), IN selected_profile VARCHAR(128),
    IN selected_domain VARCHAR(253), IN selected_status VARCHAR(16),
    IN selected_not_before VARCHAR(64), IN selected_not_after VARCHAR(64)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v2_staging(selected_generation);
    INSERT INTO dkim2_profiles VALUES (
        selected_generation, selected_profile, selected_domain, selected_status,
        selected_not_before, selected_not_after
    );
END//

CREATE PROCEDURE dkim2_v2_insert_credential(
    IN selected_generation DECIMAL(20,0), IN selected_profile VARCHAR(128),
    IN selected_algorithm VARCHAR(32), IN selected_selector VARCHAR(253),
    IN selected_spki BLOB, IN selected_handle VARCHAR(128)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v2_staging(selected_generation);
    INSERT INTO dkim2_credentials VALUES (
        selected_generation, selected_profile, selected_algorithm,
        selected_selector, selected_spki, selected_handle
    );
END//

CREATE PROCEDURE dkim2_v2_insert_policy(
    IN selected_generation DECIMAL(20,0), IN selected_tenant VARCHAR(128),
    IN selected_domain VARCHAR(253), IN selected_use VARCHAR(32),
    IN selected_profile VARCHAR(128), IN selected_status VARCHAR(16),
    IN selected_rollout VARCHAR(16), IN selected_compatibility VARCHAR(16),
    IN selected_feedback VARCHAR(128)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v2_staging(selected_generation);
    INSERT INTO dkim2_policies VALUES (
        selected_generation, selected_tenant, selected_domain, selected_use,
        selected_profile, selected_status, selected_rollout,
        selected_compatibility, selected_feedback
    );
END//

CREATE PROCEDURE dkim2_v2_insert_key_material(
    IN selected_generation DECIMAL(20,0), IN selected_tenant VARCHAR(128),
    IN selected_domain VARCHAR(253), IN selected_use VARCHAR(32),
    IN selected_handle VARCHAR(128), IN selected_algorithm VARCHAR(32),
    IN selected_spki BLOB, IN selected_pkcs8 MEDIUMBLOB
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v2_staging(selected_generation);
    INSERT INTO dkim2_key_material VALUES (
        selected_generation, selected_tenant, selected_domain, selected_use,
        selected_handle, selected_algorithm, selected_spki, selected_pkcs8
    );
END//

CREATE PROCEDURE dkim2_assert_v2_staging(IN selected_generation DECIMAL(20,0))
SQL SECURITY DEFINER READS SQL DATA
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE generation = selected_generation
           AND schema_version = 'dkim2-datasource-v2'
           AND dataset_state = 'staging'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v2 publication denied';
    END IF;
END//

CREATE PROCEDURE dkim2_v2_seal_generation(IN selected_generation DECIMAL(20,0))
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v2_staging(selected_generation);
    UPDATE dkim2_dataset_generations SET dataset_state = 'committed'
     WHERE generation = selected_generation;
	IF ROW_COUNT() <> 1 THEN
		SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v2 seal denied';
	END IF;
END//

CREATE PROCEDURE dkim2_v2_insert_current(IN selected_generation DECIMAL(20,0))
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE generation = selected_generation
           AND schema_version = 'dkim2-datasource-v2'
           AND dataset_state = 'committed'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v2 current denied';
    END IF;
	INSERT INTO dkim2_current_generation
		(singleton, generation, candidate_digest)
	VALUES (1, selected_generation, NULL);
END//

CREATE PROCEDURE dkim2_v2_update_current(
    IN selected_generation DECIMAL(20,0), IN expected_generation DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE generation = selected_generation
           AND schema_version = 'dkim2-datasource-v2'
           AND dataset_state = 'committed'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v2 current denied';
    END IF;
	UPDATE dkim2_current_generation
	   SET generation = selected_generation, candidate_digest = NULL
     WHERE singleton = 1 AND generation = expected_generation;
	IF ROW_COUNT() <> 1 THEN
		SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v2 current drift';
	END IF;
END//

CREATE PROCEDURE dkim2_assert_v3_operation(IN selected_operation VARCHAR(128))
SQL SECURITY DEFINER READS SQL DATA
BEGIN
    IF selected_operation IS NULL OR OCTET_LENGTH(selected_operation) <> 26 OR
       selected_operation NOT REGEXP '^[a-z2-7]{25}[aeimquy4]$' OR
       selected_operation = REPEAT('a', 26) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 invalid v3 operation';
    END IF;
END//

CREATE PROCEDURE dkim2_v3_lock_observe()
SQL SECURITY DEFINER READS SQL DATA
BEGIN
    SELECT CAST(lock_revision AS CHAR), lock_operation_id
      FROM dkim2_publication_lock
     WHERE singleton = 1;
END//

CREATE PROCEDURE dkim2_v3_lock_for_update()
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    SELECT CAST(lock_revision AS CHAR), lock_operation_id
      FROM dkim2_publication_lock
     WHERE singleton = 1
     FOR UPDATE;
END//

CREATE PROCEDURE dkim2_v3_current_for_update()
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    SELECT CAST(current_generation.generation AS CHAR), dataset.schema_version,
           dataset.dataset_state, dataset.operation_id, dataset.candidate_digest,
           current_generation.candidate_digest, dataset.was_active
      FROM dkim2_current_generation AS current_generation
      JOIN dkim2_dataset_generations AS dataset USING (generation)
     WHERE current_generation.singleton = 1
     FOR UPDATE;
END//

CREATE PROCEDURE dkim2_assert_v3_metadata(
    IN selected_operation VARCHAR(128), IN selected_digest BLOB
)
SQL SECURITY DEFINER READS SQL DATA
BEGIN
    CALL dkim2_assert_v3_operation(selected_operation);
    IF selected_digest IS NULL OR OCTET_LENGTH(selected_digest) <> 32 OR
       selected_digest = UNHEX(REPEAT('00', 32)) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 invalid v3 digest';
    END IF;
END//

CREATE PROCEDURE dkim2_v3_lock_candidate_root(
    IN selected_generation DECIMAL(20,0), IN selected_operation VARCHAR(128),
    IN selected_digest BLOB, IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_metadata(selected_operation, selected_digest);
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_publication_lock
         WHERE singleton = 1 AND lock_revision = selected_revision
           AND lock_operation_id = selected_operation FOR UPDATE
    ) OR NOT EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE generation = selected_generation
           AND schema_version = 'dkim2-datasource-v3'
           AND dataset_state = 'committed'
           AND operation_id = selected_operation
           AND candidate_digest = selected_digest FOR UPDATE
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 candidate lock denied';
    END IF;
    SELECT CAST(generation AS CHAR), schema_version, dataset_state,
           operation_id, candidate_digest, was_active
      FROM dkim2_dataset_generations
     WHERE generation = selected_generation
       AND schema_version = 'dkim2-datasource-v3'
       AND dataset_state = 'committed'
       AND operation_id = selected_operation
       AND candidate_digest = selected_digest;
END//

CREATE PROCEDURE dkim2_assert_v3_lock(
    IN selected_generation DECIMAL(20,0), IN selected_operation VARCHAR(128),
    IN selected_digest BLOB, IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER READS SQL DATA
BEGIN
    CALL dkim2_assert_v3_metadata(selected_operation, selected_digest);
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_publication_lock
         WHERE singleton = 1 AND lock_revision = selected_revision
           AND lock_operation_id = selected_operation
    ) OR NOT EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE generation = selected_generation
           AND schema_version = 'dkim2-datasource-v3'
           AND dataset_state = 'staging'
           AND operation_id = selected_operation
           AND candidate_digest = selected_digest
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 operation denied';
    END IF;
END//

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
    INSERT INTO dkim2_dataset_generations
        (generation, schema_version, dataset_state, operation_id, candidate_digest, was_active)
    VALUES (
        selected_generation, 'dkim2-datasource-v3', 'staging',
        selected_operation, selected_digest, FALSE
    );
END//

CREATE PROCEDURE dkim2_v3_claim_lock(
    IN selected_revision DECIMAL(20,0), IN selected_operation VARCHAR(128)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_operation(selected_operation);
    UPDATE dkim2_publication_lock SET lock_operation_id = selected_operation
     WHERE singleton = 1 AND lock_revision = selected_revision
       AND lock_operation_id IS NULL;
    IF ROW_COUNT() <> 1 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 lock claim denied';
    END IF;
END//

CREATE PROCEDURE dkim2_v3_release_lock(
    IN selected_revision DECIMAL(20,0), IN selected_operation VARCHAR(128)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_operation(selected_operation);
    UPDATE dkim2_publication_lock
       SET lock_revision = lock_revision + 1, lock_operation_id = NULL
     WHERE singleton = 1 AND lock_revision = selected_revision
       AND lock_operation_id = selected_operation;
    IF ROW_COUNT() <> 1 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 lock release denied';
    END IF;
END//

CREATE PROCEDURE dkim2_v3_insert_handle(
    IN selected_generation DECIMAL(20,0), IN selected_handle VARCHAR(128),
    IN selected_operation VARCHAR(128), IN selected_digest BLOB,
    IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_lock(selected_generation, selected_operation, selected_digest, selected_revision);
    INSERT INTO dkim2_handles VALUES (selected_generation, selected_handle);
END//

CREATE PROCEDURE dkim2_v3_insert_profile(
    IN selected_generation DECIMAL(20,0), IN selected_profile VARCHAR(128),
    IN selected_domain VARCHAR(253), IN selected_status VARCHAR(16),
    IN selected_not_before VARCHAR(64), IN selected_not_after VARCHAR(64),
    IN selected_operation VARCHAR(128), IN selected_digest BLOB,
    IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_lock(selected_generation, selected_operation, selected_digest, selected_revision);
    INSERT INTO dkim2_profiles VALUES (
        selected_generation, selected_profile, selected_domain, selected_status,
        selected_not_before, selected_not_after
    );
END//

CREATE PROCEDURE dkim2_v3_insert_credential(
    IN selected_generation DECIMAL(20,0), IN selected_profile VARCHAR(128),
    IN selected_algorithm VARCHAR(32), IN selected_selector VARCHAR(253),
    IN selected_spki BLOB, IN selected_handle VARCHAR(128),
    IN selected_operation VARCHAR(128), IN selected_digest BLOB,
    IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_lock(selected_generation, selected_operation, selected_digest, selected_revision);
    INSERT INTO dkim2_credentials VALUES (
        selected_generation, selected_profile, selected_algorithm,
        selected_selector, selected_spki, selected_handle
    );
END//

CREATE PROCEDURE dkim2_v3_insert_policy(
    IN selected_generation DECIMAL(20,0), IN selected_tenant VARCHAR(128),
    IN selected_domain VARCHAR(253), IN selected_use VARCHAR(32),
    IN selected_profile VARCHAR(128), IN selected_status VARCHAR(16),
    IN selected_rollout VARCHAR(16), IN selected_compatibility VARCHAR(16),
    IN selected_feedback VARCHAR(128), IN selected_operation VARCHAR(128),
    IN selected_digest BLOB, IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_lock(selected_generation, selected_operation, selected_digest, selected_revision);
    INSERT INTO dkim2_policies VALUES (
        selected_generation, selected_tenant, selected_domain, selected_use,
        selected_profile, selected_status, selected_rollout,
        selected_compatibility, selected_feedback
    );
END//

CREATE PROCEDURE dkim2_v3_insert_key_material(
    IN selected_generation DECIMAL(20,0), IN selected_tenant VARCHAR(128),
    IN selected_domain VARCHAR(253), IN selected_use VARCHAR(32),
    IN selected_handle VARCHAR(128), IN selected_algorithm VARCHAR(32),
    IN selected_spki BLOB, IN selected_pkcs8 MEDIUMBLOB,
    IN selected_operation VARCHAR(128), IN selected_digest BLOB,
    IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_lock(selected_generation, selected_operation, selected_digest, selected_revision);
    INSERT INTO dkim2_key_material VALUES (
        selected_generation, selected_tenant, selected_domain, selected_use,
        selected_handle, selected_algorithm, selected_spki, selected_pkcs8
    );
END//

CREATE PROCEDURE dkim2_v3_seal_generation(
    IN selected_generation DECIMAL(20,0), IN selected_operation VARCHAR(128),
    IN selected_digest BLOB, IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_lock(
        selected_generation, selected_operation, selected_digest, selected_revision
    );
    UPDATE dkim2_dataset_generations SET dataset_state = 'committed'
     WHERE generation = selected_generation AND dataset_state = 'staging';
	IF ROW_COUNT() <> 1 THEN
		SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 seal denied';
	END IF;
END//

CREATE PROCEDURE dkim2_v3_activate(
    IN expected_generation DECIMAL(20,0), IN selected_generation DECIMAL(20,0),
    IN selected_operation VARCHAR(128), IN selected_digest BLOB,
    IN selected_revision DECIMAL(20,0)
)
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
    CALL dkim2_assert_v3_metadata(selected_operation, selected_digest);
    IF NOT EXISTS (
        SELECT 1 FROM dkim2_publication_lock
         WHERE singleton = 1 AND lock_revision = selected_revision
           AND lock_operation_id = selected_operation FOR UPDATE
    ) OR NOT EXISTS (
        SELECT 1 FROM dkim2_dataset_generations
         WHERE generation = selected_generation
           AND schema_version = 'dkim2-datasource-v3'
           AND dataset_state = 'committed' AND operation_id = selected_operation
           AND candidate_digest = selected_digest FOR UPDATE
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 activation denied';
    END IF;
    IF expected_generation = 0 THEN
        IF selected_generation <> 1 OR EXISTS (
            SELECT 1 FROM dkim2_current_generation WHERE singleton = 1 FOR UPDATE
        ) THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 bootstrap denied';
        END IF;
        INSERT INTO dkim2_current_generation
            (singleton, generation, candidate_digest)
        VALUES (1, selected_generation, selected_digest);
    ELSE
        IF NOT EXISTS (
            SELECT 1 FROM dkim2_current_generation
             WHERE singleton = 1 AND generation = expected_generation FOR UPDATE
        ) THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 current drift';
        END IF;
		IF NOT EXISTS (
			SELECT 1 FROM dkim2_current_generation AS current_generation
			JOIN dkim2_dataset_generations AS dataset USING (generation)
			WHERE current_generation.singleton = 1
			  AND current_generation.generation = expected_generation
			  AND current_generation.candidate_digest <=> dataset.candidate_digest
		) THEN
			SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 current digest drift';
		END IF;
		UPDATE dkim2_dataset_generations SET was_active = TRUE
         WHERE generation = expected_generation AND dataset_state = 'committed';
		IF NOT EXISTS (
			SELECT 1 FROM dkim2_dataset_generations
			 WHERE generation = expected_generation AND dataset_state = 'committed'
			   AND was_active = TRUE
		) THEN
			SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 history denied';
		END IF;
        UPDATE dkim2_current_generation
           SET generation = selected_generation, candidate_digest = selected_digest
         WHERE singleton = 1 AND generation = expected_generation;
		IF ROW_COUNT() <> 1 THEN
			SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 v3 current transition denied';
		END IF;
    END IF;
END//

DELIMITER ;

-- Accounts and grants remain a site-owned operation. Apply the reviewed
-- 002_least_privilege_grants.sql.example after this upgrade.
