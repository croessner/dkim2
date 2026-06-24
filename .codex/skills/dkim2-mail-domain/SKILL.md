---
name: dkim2-mail-domain
description: Bring email-domain expertise to DKIM2 work. Use when tasks involve RFC 5322 bytes, SMTP envelope state, MIME/header handling, DKIM heritage, Authentication-Results, Milter callback fidelity, EAI/SMTPUTF8, DNS mail records, queue-time behavior, or operational mail-server integration.
---

# DKIM2 Mail Domain

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`. When exact mail
syntax or protocol behavior matters, verify against the relevant RFC or active
draft rather than assuming common MTA behavior.

## Mail Reasoning Rules

- Keep raw RFC 5322 bytes distinct from parsed convenience views.
- Treat SMTP envelope sender and recipients as separate evidence from message
  headers.
- Preserve line endings, header order, duplicate header fields, comments, and
  folding where protocol behavior depends on bytes.
- Do not normalize EAI/SMTPUTF8 values beyond byte preservation unless the
  active draft defines semantics.
- Treat Milter callback reconstruction as a fidelity risk; document what was
  actually observed and reconstructed.
- Keep `Authentication-Results` as local trust-boundary reporting, not DKIM2
  verification state.

## Common Checks

- Does the latest DKIM2 signature match the current envelope?
- Are message headers and body represented without lossy transformations?
- Are header additions, changes, deletes, and body replacement actions safe for
  the adapter path being used?
- Is a failure permanent, temporary, policy-driven, or internal?
- Is any diagnostic leaking raw recipients, local parts, message IDs, body
  content, or raw signatures?

## Test Expectations

Use raw-message fixtures for protocol behavior and adapter-flow fixtures for
Milter behavior. Keep edge-case fixtures for duplicate headers, folded headers,
empty bodies, bare-LF rejection or handling, SMTPUTF8 bytes, multiple
recipients, and current-envelope mismatch.

## Completion Check

Report which mail evidence was used: raw RFC 5322, SMTP envelope, Milter
callbacks, DNS records, or local policy. Call out any fidelity limitation.
