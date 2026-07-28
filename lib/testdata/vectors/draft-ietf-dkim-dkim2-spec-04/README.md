# DKIM2 Draft-04 Library Vectors

This directory pins protocol evidence to
`draft-ietf-dkim-dkim2-spec-04`.

- `public-golden.json` covers public verification, policy, malformed input,
  sequence, timestamp, envelope, and provider outcomes.
- `custody-crypto-golden.json` covers RSA/Ed25519 cryptography and the complete
  ordinary/next-domain custody transition matrix.
- `signing-golden.json` covers byte-exact Message-Instance fields, Section 9.6
  canonical input, RSA/Ed25519/dual unsigned and complete signature fields,
  one-recipient Bcc-safe copy shape, restriction and derived-flag field shapes,
  the explicit next-domain creation/continuation/completion chain, normal
  insertion, and header-only insertion.
- `signing-test-rsa.pem` is a synthetic, test-only RSA key for deterministic
  public-facade evidence under reserved `.test` domains. It is never selected
  by production configuration, and only its artifact digest may enter reports.

Expected cryptographic values use `cross_primitive` provenance: signing uses
the standard-library RSA/Ed25519 primitives, while frozen canonical and field
digests are checked independently from the production facade. Byte-sensitive
recipe and raw-message expectations use reviewed `manual_derivation`
provenance against the named draft or RFC sections.

The versioned JSON is exercised by package-owned loaders. Broader exact/one-over
limits, callback matrices, restricted release, fanout, privacy, concurrency,
and negative abuse behavior remain executable Go tests because their stateful
objects and opaque capabilities must not be serialized into vector files.
