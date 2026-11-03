# DKIM2 Tag and Flag Cheat Sheet

Every tag you can meet in a DKIM2 message or DNS record, in plain words. The
"Do I configure it?" column answers the question most administrators really
have: `dkim2d` sets almost everything itself, so you mostly *read* these
values while debugging.

New to the headers? Read the annotated example in
[DKIM2 explained](dkim2-explained.md) first.

## Header field `DKIM2-Signature`

One field per hop. The newest hop has the highest `i=` and sits on top.

| Tag | Name | Example | Meaning | Do I configure it? |
| --- | --- | --- | --- | --- |
| `i=` | sequence | `i=2` | Position of this hop in the chain. `i=1` is the origin. A gap (1, 3) makes the message unsigned. | No, `dkim2d` counts. |
| `m=` | instance | `m=2` | Which `Message-Instance` (message version) this hop signs. | No. |
| `t=` | timestamp | `t=1700000000` | Signing time in Unix seconds. Verifiers reject signatures older than 14 days or more than one day in the future. | No. Keep your clock in sync (NTP). |
| `mf=` | MAIL FROM | `mf=PD4=` | Base64 of the SMTP reverse path this hop used, including angle brackets. `PD4=` is `<>` (a bounce or auto-reply). | No, taken from the real envelope. |
| `rt=` | RCPT TO | `rt=PGJvYkBkZXN0aW5hdGlvbi50ZXN0Pg==` | Base64 of each SMTP recipient of this copy, comma-separated. This implementation signs one recipient per copy so Bcc recipients are never revealed. | No, taken from the real envelope. |
| `nd=` | next domain | `nd=mail.example.test` | Replaces `mf=`/`rt=` when a message is handed to another domain over a private, out-of-band path. The next hop must sign with exactly `d=` that domain. Needs explicit trust; never a default PASS. | Not via the MTA adapters. |
| `d=` | signing domain | `d=example.test` | The domain that takes responsibility. Must match the domain of this hop's `mf=` (equal or a parent domain). | Yes, indirectly: the domain of your signing profile. |
| `s=` | selector signatures | `s=rsa-2026:rsa-sha256:<b64>` | One or more `selector:algorithm:signature` triples. The key is at `<selector>._domainkey.<d=>`. | Yes: you choose selector names and algorithms in the datasource. |
| `f=` | flags | `f=exploded` | Optional comma-separated flags, see below. | No. |
| `n=` | nonce | `n=abc123` | Optional printable value chosen by the signer. Verifiers do not interpret it. | No. |

### How several algorithms in `s=` combine

`dkim2d` signs with up to three keys per profile and writes them as
`rsa , ed25519 | mldsa44`:

```text
s=rsa-2026a:rsa-sha256:<sig>,ed-2026a:ed25519-sha256:<sig>|ml-2026a:mldsa44:<sig>
  \_________________ group 1: all must verify ________/ \__ group 2 _______/
```

- `,` joins signatures that **all** must verify (sig-all).
- `|` separates alternatives where **any one** group is enough (sig-any).

A verifier that does not know ML-DSA still passes with the RSA and Ed25519
group. A profile with only RSA and Ed25519 produces just `rsa,ed25519`.

## Header field `Message-Instance`

One field per message version. A new one appears only when a hop changes
the message.

| Tag | Name | Example | Meaning |
| --- | --- | --- | --- |
| `m=` | instance number | `m=2` | Version number: 1 for the original, 2 after the first change, and so on. |
| `h=` | hashes | `h=sha256:<header-hash>:<body-hash>` | Hash algorithm, header hash, and body hash of this version. Several values combine with `,` and `\|` like `s=`. |
| `r=` | Recipe | `r=eyJoIjp7...` | Only for `m=2` and higher: base64 JSON that recreates the previous version from this one. |

### Reading a Recipe

Decode `r=` with `base64 -d`. The JSON has a header part `h` and a body part
`b`. Each step is one of:

| Step | Meaning |
| --- | --- |
| `{"c": [...]}` | **Copy** lines or values from the current version. |
| `{"d": [...]}` | **Data**: insert this literal text. |
| `{"u": [...]}` | Like `d`, but the literal is base64 because it is not valid UTF-8. |

Example from the mailing-list case:
`{"h":{"subject":[{"d":[" Grillfest am Samstag"]}]}}` means "the previous
Subject value was ` Grillfest am Samstag`". A hop that changed only headers
has no `b` part, because the body hash is unchanged. A null body Recipe
(`"b": null`) says "the previous body cannot be rebuilt"; Draft-09 verifiers
report such a chain as `PERMERROR` (`body_history_unavailable`).

## Flags in `f=`

| Flag | Set by | Meaning | What a receiver does |
| --- | --- | --- | --- |
| `exploded` | A hop that fanned one message out to several recipients, such as an alias with several targets or a list | "Several copies of this message are expected." | Does not treat the sibling copies as replays. `dkim2d` reports it as information. |
| `feedback` | A signer that wants abuse or delivery feedback about the message | "Please send me feedback." | `dkim2d` records the request; it exposes no feedback address. |
| `feedhere` | A later hop | "Send the feedback to me instead of further upstream." Only meaningful when a lower hop asked for `feedback`. | `dkim2d` reports which hop should receive feedback. |

`dkim2d` never adds flags because an adapter asks for them. `exploded` is
derived only from a real multi-copy delivery plan. The old Draft-06 flags
`donotmodify` and `donotexplode` no longer exist: a received one is ignored,
and a configuration key that still mentions them is refused at startup.

## Commonly confused names

| You saw | It is |
| --- | --- |
| `mt=` | Not a Draft-09 tag. You probably mean `m=` (message instance) or `mf=` (MAIL FROM). |
| `i=` in DKIM2 vs DKIM | In DKIM, `i=` is the agent identity. In DKIM2 it is the hop number. |
| `h=` in DKIM2 vs DKIM | In DKIM, `h=` lists signed header names. In DKIM2 `Message-Instance`, it carries the hashes. |
| `t=` in DNS | Retired. DNS-02 ignores the old DKIM testing flag `t=y`; use `policy.mode: testing` on the receiving side instead. |

## DNS key record

Location: `<selector>._domainkey.<domain>`, type TXT. The format is the
familiar DKIM key record; the
[OpenDKIM migration](../operator/opendkim-migration.md) can import existing
DKIM RSA and Ed25519 keys.

```text
rsa-2026a._domainkey.example.test. 3600 IN TXT "v=DKIM1; k=rsa; p=MIIBCgKCAQEA..."
ed-2026a._domainkey.example.test.  3600 IN TXT "v=DKIM1; k=ed25519; p=NRzo7cyrLSlM..."
```

| Tag | Meaning |
| --- | --- |
| `v=DKIM1` | Record version. TXT records at the same name with another `v=` are ignored. |
| `k=` | Key type: `rsa`, `ed25519`, or `mldsa44`. |
| `p=` | The public key in base64. An empty `p=` means "revoked": verification is `PERMERROR`. |

More than one `v=DKIM1` record at the same selector is ambiguous and also
`PERMERROR`. `dkim2d datasource key generate` prints the exact record for
you; see [Keys and DNS](keys-and-dns.md).

## DNS Domain Policy Record

Location: `_domainkey.<domain>` (no selector), type TXT.

```text
_domainkey.example.test. 3600 IN TXT "v=DKIM1; f=strict"
```

By default, a signature from a subdomain (`d=news.example.test`) may vouch
for a From address in the parent (`alice@example.test`). `f=strict` forbids
that: only `d=example.test` or a parent may sign for From addresses in
`example.test`. Publish it only after you have checked that no service signs
your From domain with a subdomain key.

## Results you see in headers and logs

| Value | Where | Meaning |
| --- | --- | --- |
| `dkim2=none` | `Authentication-Results` | The message carries no DKIM2 header. |
| `dkim2=pass` | `Authentication-Results` | Fully verified. |
| `dkim2=fail` | `Authentication-Results` | Verified, but something does not match. |
| `dkim2=permerror` | `Authentication-Results` | Broken DKIM2 data or key. |
| `dkim2=temperror` | `Authentication-Results` | Try again later; usually DNS. |
| `X-DKIM2-Info: ...` | optional header after signing | Diagnostic only: which software signed, with which algorithms. Never an authentication result. Enable with `signing.interop_info.enabled: true`. |

The complete list of reason codes (`envelope_mismatch`, `custody_mismatch`,
`from_subdomain_forbidden`, and others) is in the `VerificationReason`
schema of [`docs/specs/openapi/dkim2d.yaml`](../specs/openapi/dkim2d.yaml).
