# DNS-03 Migration For Operators

This guide covers the move of the DNS companion from
`draft-ietf-dkim-dkim2-dns-02` to `draft-ietf-dkim-dkim2-dns-03`. The message
baseline stays `draft-ietf-dkim-dkim2-spec-09`. The change-by-change record is
[`docs/specs/dns-03-migration-disposition.md`](../specs/dns-03-migration-disposition.md).
The previous step is described in
[`draft-09-migration.md`](draft-09-migration.md).

DNS-03 rewrites the key-record document. Most of it states rules this
implementation already followed: the `k=mldsa44` key type, the Domain Policy
Record with `f=strict`, the ignored `h=`, `n=`, `s=`, and `t=` tags, and the
rule that TXT records with a foreign `v=` are ignored before the uniqueness
check. Two verification behaviors become stricter.

## What Does Not Change

- No configuration path, REST path, REST schema, CLI flag, or metric changes.
  The REST draft enum (`DraftVersion`) still accepts exactly
  `draft-ietf-dkim-dkim2-spec-09`.
- No component has to move together with another. The DNS draft identifier
  is evidence metadata in reports and build information only; it is not on
  the wire.
- The OpenAPI document differs in one description text only. A consumer that
  vendors the contract byte for byte (`dkim2pub`) resynchronizes the file;
  its generated types do not change.
- Qualification and conformance reports produced by an earlier release name
  DNS-02 and are rejected by the tooling of this release. Regenerate them
  after the upgrade.
- Signing is unaffected. `dkim2d datasource domain dns export` already emits
  padded `p=` values and a well-formed `v=DKIM1; f=strict` record.
- The replay store needs no restart or migration.

## Stricter Key Records: Base64 Padding

DNS-03 Section 2.3 requires the trailing `=` characters a Base64 value needs.
A key record whose `p=` value omits them is now a malformed record:
verification reports PERMERROR with the reason `invalid_key`. Earlier
releases accepted such records.

Who is affected:

- 2048-bit RSA keys encode without any padding, in both the
  SubjectPublicKeyInfo form and the PKCS#1 form. They are not affected.
- 3072-bit RSA keys end in one `=`, 4096-bit RSA keys in `==`, Ed25519 keys
  in one `=`, and ML-DSA-44 keys in `==`. Such a record is affected only if
  the padding was removed when it was published, for example by a DNS web
  form.

Check a published record before the upgrade:

```sh
dig +short TXT selector._domainkey.example.test
```

Join the quoted strings, take the `p=` value, and remove all whitespace. Its
length must be a multiple of four. If it is not, republish the record with
the padding restored; the key itself does not change.

Mail from other domains with such a record now verifies as PERMERROR
`invalid_key` at this implementation. That is the sender's record to fix.

## Stricter Domain Policy Records: Flag Syntax

DNS-03 Section 5.2 defines the syntax of the `f=` tag of the Domain Policy
Record at `_domainkey.<domain>`: flags are separated by `:`, and every flag
starts with a letter, ends with a letter or digit, and otherwise contains
only letters, digits, and hyphens. Unknown flags of that shape are still
ignored.

A record that begins with `v=DKIM1` and carries an `f=` value outside this
syntax is now `domain_policy_invalid` (PERMERROR) for mail whose `d=` is a
subdomain of the From domain. Examples:

| Record | Before | Now |
| --- | --- | --- |
| `v=DKIM1; f=strict` | strict | strict |
| `v=DKIM1; f=foo:strict` | strict | strict |
| `v=DKIM1; f=` | authorized | authorized |
| `v=DKIM1; f=strict:` | strict | `domain_policy_invalid` |
| `v=DKIM1; f=str ict` | authorized | `domain_policy_invalid` |
| `v=DKIM1; f=strict,foo` | authorized | `domain_policy_invalid` |

Both new outcomes deny the subdomain signer, so no record becomes more
permissive. Publish exactly:

```text
_domainkey.example.test. 3600 IN TXT "v=DKIM1; f=strict"
```

## ML-DSA-44 Records

DNS-03 Section 4.2 defines the form this implementation already published
and read: `v=DKIM1; k=mldsa44; p=<raw 1312-octet key>`. No record has to be
republished. The 1752-character `p=` value does not fit a UDP answer;
resolvers must be able to retry over TCP, as the daemon's DNS transport does.

## Rollback

Reinstalling the previous release restores the lenient parsing of unpadded
`p=` values and of malformed `f=` values. No stored state has to be reverted.
