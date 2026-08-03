-- DKIM2 native datasource v2. The qualified service releases are documented
-- in docs/reference/compatibility.md; this artifact makes no broader version
-- compatibility claim.
-- Install in one dedicated database using an administrative connection.
-- Apply the separately reviewed 002_least_privilege_grants.sql.example after
-- creating TLS-required site accounts. The publisher also needs narrowly
-- scoped UPDATE(singleton) on dkim2_publication_lock to acquire its row lock.
-- Neither account receives DELETE, DDL, FILE, or global privileges.

SET NAMES utf8mb4 COLLATE utf8mb4_bin;

CREATE TABLE dkim2_publication_lock (
    singleton TINYINT UNSIGNED NOT NULL,
    PRIMARY KEY (singleton),
    CONSTRAINT dkim2_publication_lock_singleton CHECK (singleton = 1)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT INTO dkim2_publication_lock (singleton) VALUES (1);

CREATE TABLE dkim2_dataset_generations (
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    dataset_state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (generation),
    CONSTRAINT dkim2_generation_range CHECK (generation BETWEEN 1 AND 18446744073709551615),
    CONSTRAINT dkim2_schema_version CHECK (schema_version = 'dkim2-datasource-v2'),
    CONSTRAINT dkim2_dataset_state CHECK (dataset_state IN ('staging', 'committed'))
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dkim2_current_generation (
    singleton TINYINT UNSIGNED NOT NULL,
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    PRIMARY KEY (singleton),
    UNIQUE KEY dkim2_current_generation_unique (generation),
    CONSTRAINT dkim2_current_singleton CHECK (singleton = 1),
    CONSTRAINT dkim2_current_dataset FOREIGN KEY (generation)
        REFERENCES dkim2_dataset_generations (generation)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dkim2_handles (
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    handle_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (generation, handle_id),
    CONSTRAINT dkim2_handle_dataset FOREIGN KEY (generation)
        REFERENCES dkim2_dataset_generations (generation)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dkim2_profiles (
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    profile_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    signing_domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    record_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    not_before_utc VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    not_after_utc VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    PRIMARY KEY (generation, profile_id),
    UNIQUE KEY dkim2_profile_domain (generation, profile_id, signing_domain),
    CONSTRAINT dkim2_profile_dataset FOREIGN KEY (generation)
        REFERENCES dkim2_dataset_generations (generation),
    CONSTRAINT dkim2_profile_status CHECK (record_status IN ('active', 'disabled')),
    CONSTRAINT dkim2_profile_validity CHECK (
        (not_before_utc IS NULL AND not_after_utc IS NULL) OR
        (not_before_utc IS NOT NULL AND not_after_utc IS NOT NULL)
    )
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dkim2_credentials (
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    profile_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    algorithm VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    selector VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_key_spki BLOB NOT NULL,
    handle_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (generation, profile_id, algorithm),
    UNIQUE KEY dkim2_credential_selector (generation, profile_id, selector),
    UNIQUE KEY dkim2_credential_handle (generation, handle_id),
    UNIQUE KEY dkim2_credential_handle_algorithm (generation, handle_id, algorithm),
    CONSTRAINT dkim2_credential_profile FOREIGN KEY (generation, profile_id)
        REFERENCES dkim2_profiles (generation, profile_id),
    CONSTRAINT dkim2_credential_handle_reference FOREIGN KEY (generation, handle_id)
        REFERENCES dkim2_handles (generation, handle_id),
    CONSTRAINT dkim2_credential_algorithm CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256')),
    CONSTRAINT dkim2_credential_spki_size CHECK (OCTET_LENGTH(public_key_spki) BETWEEN 1 AND 2048)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dkim2_policies (
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    tenant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    signing_domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    profile_use VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    profile_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    record_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    rollout VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    compatibility VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    feedback_route_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    PRIMARY KEY (generation, tenant_id, signing_domain, profile_use),
    CONSTRAINT dkim2_policy_profile FOREIGN KEY (generation, profile_id, signing_domain)
        REFERENCES dkim2_profiles (generation, profile_id, signing_domain),
    CONSTRAINT dkim2_policy_use CHECK (profile_use IN ('originator', 'ordinary_transit', 'next_domain_transit')),
    CONSTRAINT dkim2_policy_status CHECK (record_status IN ('active', 'disabled')),
    CONSTRAINT dkim2_policy_rollout CHECK (rollout IN ('enforce', 'observe', 'off')),
    CONSTRAINT dkim2_policy_compatibility CHECK (compatibility = 'strict')
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dkim2_key_material (
    generation DECIMAL(20,0) UNSIGNED NOT NULL,
    tenant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    signing_domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    profile_use VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    handle_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    algorithm VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_key_spki BLOB NOT NULL,
    private_key_pkcs8 MEDIUMBLOB NOT NULL,
    PRIMARY KEY (generation, handle_id),
    UNIQUE KEY dkim2_key_context (generation, tenant_id, signing_domain, profile_use, algorithm),
    CONSTRAINT dkim2_key_handle FOREIGN KEY (generation, handle_id)
        REFERENCES dkim2_handles (generation, handle_id),
    CONSTRAINT dkim2_key_credential FOREIGN KEY (generation, handle_id, algorithm)
        REFERENCES dkim2_credentials (generation, handle_id, algorithm),
    CONSTRAINT dkim2_key_algorithm CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256')),
    CONSTRAINT dkim2_key_spki_size CHECK (OCTET_LENGTH(public_key_spki) BETWEEN 1 AND 2048),
    CONSTRAINT dkim2_private_key_size CHECK (OCTET_LENGTH(private_key_pkcs8) BETWEEN 1 AND 65536)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin;

DELIMITER //

CREATE PROCEDURE dkim2_assert_staging(IN selected_generation DECIMAL(20,0))
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
    DECLARE selected_state VARCHAR(16);
    SELECT dataset_state INTO selected_state
      FROM dkim2_dataset_generations
     WHERE generation = selected_generation;
    IF selected_state IS NULL OR selected_state <> 'staging' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 immutable generation';
    END IF;
END//

CREATE TRIGGER dkim2_dataset_update BEFORE UPDATE ON dkim2_dataset_generations
FOR EACH ROW
BEGIN
    IF OLD.generation <> NEW.generation OR OLD.schema_version <> NEW.schema_version OR
       OLD.dataset_state <> 'staging' OR NEW.dataset_state <> 'committed' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 immutable generation';
    END IF;
END//

CREATE TRIGGER dkim2_dataset_delete BEFORE DELETE ON dkim2_dataset_generations
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 immutable generation';
END//

CREATE TRIGGER dkim2_current_insert BEFORE INSERT ON dkim2_current_generation
FOR EACH ROW
BEGIN
    IF (SELECT dataset_state FROM dkim2_dataset_generations WHERE generation = NEW.generation) <> 'committed' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 invalid current generation';
    END IF;
END//

CREATE TRIGGER dkim2_current_update BEFORE UPDATE ON dkim2_current_generation
FOR EACH ROW
BEGIN
    IF OLD.singleton <> NEW.singleton OR NEW.generation <= OLD.generation OR
       (SELECT dataset_state FROM dkim2_dataset_generations WHERE generation = NEW.generation) <> 'committed' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 invalid generation transition';
    END IF;
END//

CREATE TRIGGER dkim2_current_delete BEFORE DELETE ON dkim2_current_generation
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'dkim2 immutable current generation';
END//

CREATE TRIGGER dkim2_handles_insert BEFORE INSERT ON dkim2_handles
FOR EACH ROW BEGIN CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_handles_update BEFORE UPDATE ON dkim2_handles
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_handles_delete BEFORE DELETE ON dkim2_handles
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); END//

CREATE TRIGGER dkim2_profiles_insert BEFORE INSERT ON dkim2_profiles
FOR EACH ROW BEGIN CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_profiles_update BEFORE UPDATE ON dkim2_profiles
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_profiles_delete BEFORE DELETE ON dkim2_profiles
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); END//

CREATE TRIGGER dkim2_credentials_insert BEFORE INSERT ON dkim2_credentials
FOR EACH ROW BEGIN CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_credentials_update BEFORE UPDATE ON dkim2_credentials
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_credentials_delete BEFORE DELETE ON dkim2_credentials
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); END//

CREATE TRIGGER dkim2_policies_insert BEFORE INSERT ON dkim2_policies
FOR EACH ROW BEGIN CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_policies_update BEFORE UPDATE ON dkim2_policies
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_policies_delete BEFORE DELETE ON dkim2_policies
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); END//

CREATE TRIGGER dkim2_key_material_insert BEFORE INSERT ON dkim2_key_material
FOR EACH ROW BEGIN CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_key_material_update BEFORE UPDATE ON dkim2_key_material
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); CALL dkim2_assert_staging(NEW.generation); END//
CREATE TRIGGER dkim2_key_material_delete BEFORE DELETE ON dkim2_key_material
FOR EACH ROW BEGIN CALL dkim2_assert_staging(OLD.generation); END//

DELIMITER ;

-- Least-privilege role names used by the operator grant procedure:
-- dkim2_runtime: SELECT on the seven datasource tables only.
-- dkim2_publisher: publication authority is granted by the separately reviewed
-- template; after the v3 transition it retains fixed v2 procedures and only
-- UPDATE(singleton) on dkim2_publication_lock for its locking read.
