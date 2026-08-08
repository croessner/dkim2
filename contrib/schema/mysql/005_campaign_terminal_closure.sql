-- Forward-only immutable terminal evidence for MySQL 8.4 and MariaDB 10.11.
SET NAMES utf8mb4 COLLATE utf8mb4_bin;
CREATE TABLE dkim2_campaign_terminals (
  operation_id VARCHAR(26) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  schema_version VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_schema VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_generation DECIMAL(20,0) UNSIGNED NOT NULL,
  candidate_generation DECIMAL(20,0) UNSIGNED NOT NULL,
  current_generation DECIMAL(20,0) UNSIGNED NOT NULL,
  candidate_digest BINARY(32) NOT NULL,
  terminal_state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  terminal_reason VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  terminal_time DATETIME(6) NOT NULL,
  CHECK (schema_version = 'dkim2-datasource-v3' AND source_schema IN ('dkim2-datasource-v2', 'dkim2-datasource-v3') AND candidate_generation > source_generation),
  CHECK ((terminal_state = 'closed' AND terminal_reason = 'activated' AND current_generation = candidate_generation) OR (terminal_state = 'aborted' AND terminal_reason IN ('operator_abort', 'reconcile_abort') AND current_generation = source_generation))
) ENGINE=InnoDB;
DELIMITER //
CREATE PROCEDURE dkim2_v3_record_campaign_terminal(IN selected_operation VARCHAR(26), IN selected_schema VARCHAR(32), IN selected_source_schema VARCHAR(32), IN selected_source DECIMAL(20,0), IN selected_candidate DECIMAL(20,0), IN selected_current DECIMAL(20,0), IN selected_digest BLOB, IN selected_state VARCHAR(16), IN selected_reason VARCHAR(32), IN selected_time DATETIME(6))
SQL SECURITY DEFINER MODIFIES SQL DATA
BEGIN
  SELECT lock_operation_id INTO @dkim2_terminal_owner FROM dkim2_publication_lock WHERE singleton = 1 FOR UPDATE;
  IF @dkim2_terminal_owner <> selected_operation OR selected_schema <> 'dkim2-datasource-v3' OR selected_source_schema NOT IN ('dkim2-datasource-v2', 'dkim2-datasource-v3') OR selected_candidate <= selected_source OR OCTET_LENGTH(selected_digest) <> 32 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'terminal closure denied'; END IF;
  IF NOT EXISTS (SELECT 1 FROM dkim2_current_generation WHERE singleton = 1 AND generation = selected_current) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'terminal current denied'; END IF;
  IF NOT EXISTS (SELECT 1 FROM dkim2_dataset_generations WHERE generation = selected_candidate AND schema_version = selected_schema AND candidate_digest <=> selected_digest) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'terminal candidate denied'; END IF;
  INSERT INTO dkim2_campaign_terminals VALUES (selected_operation, selected_schema, selected_source_schema, selected_source, selected_candidate, selected_current, selected_digest, selected_state, selected_reason, selected_time);
END//
DELIMITER ;
