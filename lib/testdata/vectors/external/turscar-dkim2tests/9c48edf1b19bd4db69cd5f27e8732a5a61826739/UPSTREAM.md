# Turscar DKIM2 Tests Provenance

This directory retains public-only fixture bytes from
`https://forge.turscar.ie/turscar/dkim2tests` at immutable revision
`9c48edf1b19bd4db69cd5f27e8732a5a61826739`.

The reviewed source archive SHA-256 is
`fbff809cb8e07df428eba29511366f5f0dc0b983985f955d1aa63fdc10dbd7fb`.
The retained `LICENSE` SHA-256 is
`57c5397bf69dc2be320dd0f36ff4f5cefba5a2cbb51020a186549b21a7528aca`.
It is the upstream BSD-2-Clause license text with Copyright 2026 Turscar.

The imported files are only the 42 original/signed message pairs and the
license. The upstream TOML definitions, generator code, and private test keys
are intentionally not retained.

Every retained signed message omits the terminal semicolon from both
`Message-Instance` and `DKIM2-Signature`. That violates the tag-list ABNF in
the upstream Draft-02 claim and the repository's Draft-04 baseline. The local
manifest consequently classifies every case as
`upstream_fixture_nonconformant`; this corpus is provenance and strict-parser
evidence, not an interoperability or verification PASS corpus.
