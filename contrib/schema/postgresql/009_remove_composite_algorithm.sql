-- Forward-only removal of the mldsa44-ed25519-sha512 composite algorithm.
-- Apply with all DKIM2 writers stopped. 007 admitted the post-quantum
-- composite in credentials and custody keys. The DKIM working group has not
-- settled the DKIM2 post-quantum construction, so the implementation no longer
-- knows the algorithm and this migration restores the rsa-sha256 and
-- ed25519-sha256 allowlist. It fails closed, changing nothing, while any row in
-- any generation still declares the composite: retire those generations and
-- purge them through the reviewed purge workflow first. 007 stays applied
-- history and is never edited.

BEGIN;

LOCK TABLE dkim2_datasource.credentials,
  dkim2_datasource.key_material IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM dkim2_datasource.credentials
     WHERE algorithm = 'mldsa44-ed25519-sha512'
  ) OR EXISTS (
    SELECT 1 FROM dkim2_datasource.key_material
     WHERE algorithm = 'mldsa44-ed25519-sha512'
  ) THEN
    RAISE EXCEPTION 'mldsa44-ed25519-sha512 rows remain; purge every generation that holds them before applying 009'
      USING ERRCODE = '55000';
  END IF;
END
$$;

ALTER TABLE dkim2_datasource.credentials
  DROP CONSTRAINT credentials_algorithm_check;
ALTER TABLE dkim2_datasource.credentials
  ADD CONSTRAINT credentials_algorithm_check
  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256'));

ALTER TABLE dkim2_datasource.key_material
  DROP CONSTRAINT key_material_algorithm_check;
ALTER TABLE dkim2_datasource.key_material
  ADD CONSTRAINT key_material_algorithm_check
  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256'));

COMMIT;
