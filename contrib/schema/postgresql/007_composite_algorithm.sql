-- Forward-only admission of mldsa44-ed25519-sha512 credentials and custody keys.
BEGIN;

LOCK TABLE dkim2_datasource.credentials,
  dkim2_datasource.key_material IN ACCESS EXCLUSIVE MODE;

ALTER TABLE dkim2_datasource.credentials
  DROP CONSTRAINT credentials_algorithm_check;
ALTER TABLE dkim2_datasource.credentials
  ADD CONSTRAINT credentials_algorithm_check
  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44-ed25519-sha512'));

ALTER TABLE dkim2_datasource.key_material
  DROP CONSTRAINT key_material_algorithm_check;
ALTER TABLE dkim2_datasource.key_material
  ADD CONSTRAINT key_material_algorithm_check
  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44-ed25519-sha512'));

COMMIT;
