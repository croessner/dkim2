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

The versioned JSON is exercised by package-owned loaders. Broader exact/one-over
limits, callback matrices, restricted release, fanout, privacy, concurrency,
and negative abuse behavior remain executable Go tests because their stateful
objects and opaque capabilities must not be serialized into vector files.
