# DKIM2 Draft Issue Log

This log binds the first preview to
`draft-ietf-dkim-dkim2-spec-04` and historical
`draft-chuang-dkim2-dns-04`. The strict machine source is
`testdata/reference/draft-issues.json`; stable issue IDs are never reused.
Local implementation status and upstream draft status are intentionally
separate. No entry records an upstream filing or resolution unless that event
is independently observed.

## Open upstream text

- `DKIM2-ISSUE-0001` through `DKIM2-ISSUE-0005` cover every literal Draft-04
  `TBA`: architecture references, full-chain policy guidance, EAI, IANA, and
  Security Considerations. No protocol behavior is invented for these areas.
- `DKIM2-ISSUE-0006` records the tag-name case interpretation and the exact
  MailAuthLens disagreement. It is an external observation, not normative
  authority or full interoperability evidence.
- `DKIM2-ISSUE-0007` through `DKIM2-ISSUE-0010` own the byte model, recipe,
  policy-projection, and restricted-release interpretations exercised by the
  conformance manifest.
- `DKIM2-ISSUE-0011` through `DKIM2-ISSUE-0014` preserve the DNS-04 ABNF,
  query-method, strict-identity, and multiple-record discrepancies without
  silently rewriting either pinned draft.

## Adapter and preview limitations

- `DKIM2-ISSUE-0015` keeps Milter/SMTP fidelity in the adapter claim class.
- `DKIM2-ISSUE-0016` records the completed Exim qualification boundary. The
  Linux-only claim requires the verified five-row evidence import to match the
  current manifest, base revision, candidate snapshot, and verifier producer;
  portable reports mark the case not applicable.

The repository has not filed, commented on, or modified any upstream issue as
part of this release-candidate work.

## Stable ID index

`DKIM2-ISSUE-0001`, `DKIM2-ISSUE-0002`, `DKIM2-ISSUE-0003`,
`DKIM2-ISSUE-0004`, `DKIM2-ISSUE-0005`, `DKIM2-ISSUE-0006`,
`DKIM2-ISSUE-0007`, `DKIM2-ISSUE-0008`, `DKIM2-ISSUE-0009`,
`DKIM2-ISSUE-0010`, `DKIM2-ISSUE-0011`, `DKIM2-ISSUE-0012`,
`DKIM2-ISSUE-0013`, `DKIM2-ISSUE-0014`, `DKIM2-ISSUE-0015`,
and `DKIM2-ISSUE-0016`.
