# External Vector Corpus Implementation Specification

Status: implemented M24 contract.

## Purpose

M24 retains reviewed, licensed external DKIM2 vector bytes as bounded evidence
without importing external protocol code, dependencies, private keys, or
semantic authority. It keeps external source facts separate from the
repository's `draft-ietf-dkim-dkim2-spec-04` and historical
`draft-chuang-dkim2-dns-04` baselines.

The first corpus is `https://forge.turscar.ie/turscar/dkim2tests` at revision
`9c48edf1b19bd4db69cd5f27e8732a5a61826739`. The source claims
`draft-ietf-dkim-dkim2-spec-02`; the retained archive digest is
`fbff809cb8e07df428eba29511366f5f0dc0b983985f955d1aa63fdc10dbd7fb`.
The upstream BSD-2-Clause license text is retained with digest
`57c5397bf69dc2be320dd0f36ff4f5cefba5a2cbb51020a186549b21a7528aca`.

## Authority And Claim Separation

Authority order remains unchanged:

1. the pinned Draft-04 message specification;
2. the historical DNS-04 behavior identifier;
3. incorporated RFCs;
4. durable repository architecture and implementation specifications; and
5. external vectors as `external_observation` only.

An external fixture never defines local parser, canonicalization, DNS,
signature, policy, or result semantics. A passing external case becomes
Draft-04 conformance evidence only after an explicit per-case authority map
proves equivalence. An external corpus alone never yields an interoperability
PASS; that requires an independent runnable implementation and scoped runtime
agreement under the M21 contract.

## Retained Layout

```text
lib/testdata/vectors/external/turscar-dkim2tests/<revision>/
  LICENSE
  UPSTREAM.md
  manifest.json
  messages/<case>.orig
  messages/<case>.signed
```

Only public original and signed message bytes plus the upstream license are
retained. Upstream TOML definitions include private test keys and are not
copied. Generator code, module metadata, executable artifacts, and private
keys are not retained or executed. `UPSTREAM.md` records immutable source and
license provenance; its SHA-256 is pinned in `manifest.json`, alongside the
SHA-256 of every retained message and the upstream TOML source identity.

## Closed Manifest Contract

The manifest schema is `dkim2.external-vector-corpus.v1`. It contains one
fixed canonical source URL, exact revision/archive/license identities, the
upstream and local draft identifiers, and a lexically ordered case list.

Every case records a stable source identifier, upstream TOML/original/signed
SHA-256 identities, the upstream claimed state as historical metadata, one
closed disposition and reason, and one closed local execution class and typed
reason. The checker rejects unknown JSON members, invalid provenance,
unordered identifiers, unsafe paths, changed bytes, private-key markers, and a
fixture that no longer exhibits its recorded defect. Before reading a retained
artifact, it enumerates the corpus as an exact regular-file allowlist:
`manifest.json`, `LICENSE`, `UPSTREAM.md`, and the 84 manifest-listed message
files. It rejects all unlisted files, subdirectories, symlinks, and additional
hard links. The checker opens and hashes files through descriptor-confined
repository paths, performs no network access, and does not execute upstream
code.

## Current Corpus Finding

All 42 signed fixtures omit the final semicolon in both `Message-Instance` and
`DKIM2-Signature`. The Draft-02 ABNF itself specifies each tag as followed by
`;`; this is an upstream fixture/source-format defect, not a Draft-02 to
Draft-04 behavior migration. Appending terminators would change canonical
header bytes and invalidate the existing signatures, so the repository does
not repair or reinterpret those messages.

Every current case therefore has disposition
`upstream_fixture_nonconformant`, reason `missing_terminal_tag_semicolon`, and
execution class `parser_refusal_expected`. Local expected reasons are either
`malformed_protocol` or the earlier `limit_exceeded` preflight outcome for
oversized RSA fixtures. These outcomes are local structured facts, not
translations of upstream error text.

The current corpus has zero directly executable external verification cases.
The library test proves permanent refusal through the public verifier facade.
This is useful regression and provenance evidence, but does not enter the
Draft-04 conformance report's positive counts.

## Commands And Gates

`make check-external-vectors` validates the complete retained corpus without
network access. It is a dependency of `make check-conformance`, so fixture
tampering fails before the established conformance manifest is evaluated.

`make conformance-external` runs the focused public-facade parser-refusal
test. It does not render or modify the Draft-04 conformance report. Normal
`make test` and `make guardrails` also exercise this regression through the
library test and the conformance check.

## Future Intake

A later source revision may add an `equivalent` disposition only after exact
source/archive/license/file identities, a named Draft-04 authority mapping,
public-only fixture extraction, static-DNS public-facade verification, a
tamper test, and an explicit vector-versus-runtime claim have all been
reviewed. Draft-version differences, non-equivalent surfaces, and defective
upstream fixtures remain explicit classifications. Production validation must
never be weakened, and expected outputs must never be rewritten merely to make
an external case pass.
