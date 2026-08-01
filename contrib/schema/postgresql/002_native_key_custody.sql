BEGIN;

LOCK TABLE dkim2_datasource.dataset_generations,
  dkim2_datasource.credentials IN ACCESS EXCLUSIVE MODE;

ALTER TABLE dkim2_datasource.dataset_generations
  DROP CONSTRAINT dataset_generations_schema_version_check;
ALTER TABLE dkim2_datasource.dataset_generations
  ADD CONSTRAINT dataset_generations_schema_version_check
  CHECK (schema_version IN ('dkim2-datasource-v1', 'dkim2-datasource-v2'));

ALTER TABLE dkim2_datasource.credentials
  ADD CONSTRAINT credentials_native_key_reference
  UNIQUE (generation, handle_id, algorithm, public_key_spki);

CREATE TABLE dkim2_datasource.key_material (
  generation dkim2_datasource.generation_number NOT NULL,
  tenant_id dkim2_datasource.identifier NOT NULL,
  signing_domain dkim2_datasource.domain_name NOT NULL,
  profile_use text COLLATE "C" NOT NULL
    CHECK (profile_use IN ('originator', 'ordinary_transit', 'next_domain_transit')),
  handle_id dkim2_datasource.identifier NOT NULL,
  algorithm text COLLATE "C" NOT NULL
    CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256')),
  public_key_spki bytea NOT NULL
    CHECK (octet_length(public_key_spki) BETWEEN 1 AND 2048),
  private_key_pkcs8 bytea NOT NULL
    CHECK (octet_length(private_key_pkcs8) BETWEEN 1 AND 65536),
  PRIMARY KEY (generation, handle_id),
  UNIQUE (generation, tenant_id, signing_domain, profile_use, algorithm),
  FOREIGN KEY (generation, handle_id, algorithm, public_key_spki)
    REFERENCES dkim2_datasource.credentials
      (generation, handle_id, algorithm, public_key_spki)
);

CREATE INDEX key_material_selection_idx
  ON dkim2_datasource.key_material
    (generation, tenant_id, signing_domain, profile_use);

CREATE TRIGGER key_material_immutable
  BEFORE UPDATE OR DELETE ON dkim2_datasource.key_material
  FOR EACH ROW EXECUTE FUNCTION dkim2_datasource.deny_committed_mutation();

REVOKE ALL ON dkim2_datasource.key_material FROM PUBLIC;
GRANT SELECT ON dkim2_datasource.key_material TO dkim2_runtime;
GRANT SELECT, INSERT ON dkim2_datasource.key_material TO dkim2_publisher;

COMMIT;
