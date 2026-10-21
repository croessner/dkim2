# Stalwart mail-auth composite vectors

External interoperability evidence for `mldsa44-ed25519-sha512`, copied
unchanged from `stalwartlabs/mail-auth` (Apache-2.0 OR MIT) at commit
`8d153e523a023d85acf043c8654f60bc4d344014`:

- `lamps-mldsa44-ed25519.json`: the `id-MLDSA44-Ed25519-SHA512` known-answer
  vector of `draft-ietf-lamps-pq-composite-sigs` (`resources/dkim2/`).
- `simple-mldsa44.eml`: a DKIM2 message (stored with LF line endings; tests
  normalize to CRLF) Stalwart signed with
  `mldsa44-ed25519-sha512` (`resources/dkim2/expected/`).
- `mldsa44._domainkey.test1.dkim2.com.pem`: the synthetic PKCS#8 test key
  (two 32-byte seeds) that produced the message signature
  (`resources/dkim2/keys/`). It is public test material and protects nothing.

The DKIM2 working group interim interoperability round uses the LAMPS
composite construction for this algorithm; Draft-07 Section 3.4 does not yet
spell out its message representative.
