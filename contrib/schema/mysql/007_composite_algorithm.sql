-- Forward-only admission of mldsa44-ed25519-sha512 credentials and custody keys.
ALTER TABLE dkim2_credentials
  DROP CONSTRAINT dkim2_credential_algorithm;
ALTER TABLE dkim2_credentials
  ADD CONSTRAINT dkim2_credential_algorithm
    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44-ed25519-sha512'));

ALTER TABLE dkim2_key_material
  DROP CONSTRAINT dkim2_key_algorithm;
ALTER TABLE dkim2_key_material
  ADD CONSTRAINT dkim2_key_algorithm
    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256', 'mldsa44-ed25519-sha512'));
