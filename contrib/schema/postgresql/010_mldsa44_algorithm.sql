-- Forward-only admission of pure ML-DSA-44 (mldsa44) credentials and custody
-- keys. Draft-08 Section 3.4 replaces the Draft-07 composite with pure
-- ML-DSA-44; 009 removed the composite, and this migration extends the
-- rsa-sha256 and ed25519-sha256 allowlist by mldsa44. Custody keys are the
-- seed-only PKCS#8 form (OID 2.16.840.1.101.3.4.3.17, 54 octets) and public
-- keys the PKIX SubjectPublicKeyInfo (1334 octets), both inside the existing
-- size checks. Apply with all DKIM2 writers stopped and before any writer
-- stores an mldsa44 row; the upgraded dkim2d accepts profiles with up to three
-- credentials. 009 stays applied history and is never edited.

BEGIN;

LOCK TABLE dkim2_datasource.credentials,
  dkim2_datasource.key_material IN ACCESS EXCLUSIVE MODE;

ALTER TABLE dkim2_datasource.credentials
  DROP CONSTRAINT credentials_algorithm_check;
ALTER TABLE dkim2_datasource.credentials
  ADD CONSTRAINT credentials_algorithm_check
  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44'));

ALTER TABLE dkim2_datasource.key_material
  DROP CONSTRAINT key_material_algorithm_check;
ALTER TABLE dkim2_datasource.key_material
  ADD CONSTRAINT key_material_algorithm_check
  CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44'));

COMMIT;
