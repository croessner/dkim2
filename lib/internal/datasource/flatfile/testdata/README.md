# Flat-File Datasource Fixtures

`valid-v1.json` is the canonical complete positive fixture for the strict
`dkim2-datasource-v1` decoder. It contains:

- one synthetic provider-neutral handle identifier;
- one active Ed25519-SHA256 signing profile with public SPKI material; and
- one exact enforcing originator policy for the same synthetic domain.

The SPKI value is public verification material generated for tests. This
directory contains no private key, signing callback, key path, private
credential material, token, provider connection value, message, envelope
address, or production identity. Tests derive malformed, duplicate, limit,
cross-reference, parity, and fuzz cases in memory rather than storing protected
reproducer inputs here.

Changing the fixture requires strict decoder, memory-provider parity, limit,
privacy, and fuzz evidence. The schema remains closed: unknown, duplicate,
missing, null, malformed, or trailing data must fail rather than become a
compatibility fallback.
