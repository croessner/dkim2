-- Forward-only removal of the mldsa44-ed25519-sha512 composite algorithm.
-- Apply with all DKIM2 writers stopped. 007 admitted the post-quantum
-- composite in credentials and custody keys. The DKIM working group has not
-- settled the DKIM2 post-quantum construction, so the implementation no longer
-- knows the algorithm and this migration restores the rsa-sha256 and
-- ed25519-sha256 allowlist. It fails closed before any constraint changes
-- while any row in any generation still declares the composite: retire those
-- generations and purge them through the reviewed purge workflow first. The
-- guard routine is temporary; a failed run leaves it behind, and a rerun
-- replaces it. 007 stays applied history and is never edited.

DELIMITER //
DROP PROCEDURE IF EXISTS dkim2_require_no_composite_algorithm//
CREATE PROCEDURE dkim2_require_no_composite_algorithm()
SQL SECURITY INVOKER READS SQL DATA
BEGIN
    IF EXISTS (SELECT 1 FROM dkim2_credentials
                WHERE algorithm = 'mldsa44-ed25519-sha512')
       OR EXISTS (SELECT 1 FROM dkim2_key_material
                   WHERE algorithm = 'mldsa44-ed25519-sha512') THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'mldsa44-ed25519-sha512 rows remain; purge every generation that holds them before applying 009';
    END IF;
END//
DELIMITER ;

CALL dkim2_require_no_composite_algorithm();
DROP PROCEDURE dkim2_require_no_composite_algorithm;

ALTER TABLE dkim2_credentials
  DROP CONSTRAINT dkim2_credential_algorithm;
ALTER TABLE dkim2_credentials
  ADD CONSTRAINT dkim2_credential_algorithm
    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256'));

ALTER TABLE dkim2_key_material
  DROP CONSTRAINT dkim2_key_algorithm;
ALTER TABLE dkim2_key_material
  ADD CONSTRAINT dkim2_key_algorithm
    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256'));
