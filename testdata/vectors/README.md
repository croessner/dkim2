# Test Vectors

This directory is reserved for DKIM2 conformance, regression, fuzz seed, and
interop vectors.

Vector files should make the exact draft version explicit because the DKIM2
draft is still changing.

The public verification corpus lives at
`lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-05/public-golden.json`. It is
synthetic-only and targets exactly `draft-ietf-dkim-dkim2-spec-05`. Raw RFC
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

The DNS-backed public verification manifest lives at
`lib/testdata/vectors/draft-chuang-dkim2-dns-04/dns-golden.json`. It binds the
same synthetic messages to `draft-chuang-dkim2-dns-04`, stores only the public
PKCS#1 RSA representation and raw 32-byte Ed25519 representation, and names
only reserved `.test` lookup owners. DNS vector tests enter through the public
TXT transport, DNS provider, and verifier APIs; they perform no network calls.

The internal draft-05 recipe-application fixture lives at
`lib/internal/recipe/testdata/golden/recipe-application-draft-ietf-dkim-dkim2-spec-05.json`.
Its package-local loader proves bottom-up header reconstruction, top-down body
reconstruction, copied terminal-line fidelity, deterministic cross-name
grouping, and truthful unavailable-body handling. It remains internal because
M8 deliberately exposes no public history result or recipe API.

The internal draft-05 recipe-generation fixture lives at
`lib/internal/recipe/testdata/golden/recipe-generation-draft-ietf-dkim-dkim2-spec-05.json`.
It retains exact compact decoded JSON together with synthetic previous/current
states, disclosure and unavailable-body policies, closed outcomes,
reconstructed semantics, and Section 6 canonical evidence. Package-local fuzz,
abuse, privacy, dependency, and race tests complement the retained vectors.
Generation remains internal because Message-Instance base64 and formatting,
revision hash gating, and signing are intentionally deferred.
