# Exim Compatibility Matrix — qualified 2026-07-31

> Historical Draft-04 qualification evidence. The Draft-06 capability is
> `unqualified_draft06`; none of the rows below qualify current candidate bytes
> and the active conformance and security profiles reject their import.

This report records the authenticated five-row implementation inputs and the
completed Linux runtime qualification. The strict verifier accepted all
5 × 43 cases and the final fail-closed privacy scan.

- Matrix run ID: retained in the generated full-profile evidence so source or
  product corrections cannot leave a stale durable identifier.
- Candidate-bound run manifest: retained in the generated full-profile
  evidence rather than embedded in this candidate document, avoiding a
  self-referential snapshot digest.
- Result: `passed`

| Row | Build ID | Version and options | Runtime cases | Status |
| --- | --- | --- | --- | --- |
| Debian 4.98.2-1+deb13u3 | `5fcf2736c885777917159981a06528eb8a6ba7d7a6df67990112e7c8923a4c10` | Official Debian source manifest, baseline `debian_stable` | 43/43 passed | passed |
| Debian 4.98.2-1+deb13u4 | `81a6c156a52f9bcfcd39e3c8f42f11ed47d3461783f25e7446d428c06833a3c8` | Official stable-security refresh manifest | 43/43 passed | passed |
| Ubuntu 4.99.1-1ubuntu1.3 | `1e4e45acc2eb7088d52b8a5bc3b60f9023053b68ba6f4e0bb1b36a98cedc25bd` | Official Ubuntu Resolute updates source manifest | 43/43 passed | passed |
| Ubuntu 4.99.1-1ubuntu1.4 | `1ca361a6c936b8467259b80cf20570f02e44a7007aa9cf36e8f1369e16a37476` | Official Ubuntu security-refresh source manifest | 43/43 passed | passed |
| Upstream 4.99.5 | `4903a7fd12f8124c14164184738c5192cc8ec0afa04c593f5b5ccf9129a0a21f` | Official upstream source manifest | 43/43 passed | passed |

The runner accepts only bounded status, count, version, and hash records. Raw
mail, SMTP paths, capability material, and protected configuration content are
not evidence artifacts. Before execution, every source-row build record must
match the current Git base and candidate snapshot, authenticated source and
patch digests, and exact adapter, daemon, and Exim binaries.

The previous Ubuntu u1.4 pre-patch observation is superseded by the
source-matched passing row above. The `qualified_linux` claim is limited to
these exact source/build rows. Portable conformance reports do not claim Exim
execution; full reports must rerun the matrix verifier over explicit preserved
evidence and bind the resulting content-free summary to the current manifest,
Git base, candidate snapshot, and verifier digest.
