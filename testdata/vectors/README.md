# Test Vectors

This directory is reserved for DKIM2 conformance, regression, fuzz seed, and
interop vectors.

Vector files should make the exact draft version explicit because the DKIM2
draft is still changing.

The public verification corpus lives at
`lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/public-golden.json`. It is
synthetic-only and targets exactly `draft-ietf-dkim-dkim2-spec-04`. Raw RFC
5322 and SMTP envelope bytes are Base64 encoded so fixed CRLF and byte
boundaries remain intact. The corpus contains public RSA and Ed25519 key
material only; it contains no private keys, seeds, credentials, or production
identifiers.

The frozen header, body, and Section 9.6 inputs and their RSA/Ed25519
signatures were independently cross-checked with a Node.js standard-library
renderer that imported no repository or internal packages. The cross-check
covered RSA, Ed25519, combined algorithms, timestamp boundaries, unknown hash
handling, and the intermediate next-domain vector without recording private
material. Tests decode these bytes only as input to the public root-package
facade; they do not invoke internal verification or canonicalization APIs.
