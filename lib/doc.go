// Package dkim2 provides current-message verification for
// draft-ietf-dkim-dkim2-spec-04.
//
// A Verifier requires an injected PublicKeyProvider. VerifyRequest owns cloned
// raw RFC 5322 bytes; those bytes are the sole authority for message and DKIM2
// protocol fields. Bracketed SMTP reverse-path and forward-path bytes are
// separate current-envelope evidence and are never inferred from headers.
// Results and requests expose copies rather than caller-owned mutable storage.
//
// Verify returns exactly PASS, FAIL, PERMERROR, or TEMPERROR. Caller context
// cancellation and API misuse return a zero result with a Go error. Message,
// parser, limit, protocol, key, provider, timestamp, envelope, custody, hash,
// and cryptographic outcomes return a populated result with a nil Go error.
// The precedence is caller/API error, PERMERROR, FAIL, TEMPERROR, then PASS;
// these states do not prescribe local MTA acceptance policy.
//
// Provider status is exactly found, missing, invalid, or ambiguous, and a
// declared status accompanies a nil error. Found results contain a matching
// *rsa.PublicKey or ed25519.PublicKey; accepted public material is cloned before
// use. Private keys, crypto.Signer, open-ended material, mismatched algorithms,
// and inconsistent status/material pairs are not accepted. Provider failures
// are classified only through typed temporary or permanent errors, never error
// text. An error matching the active caller context remains Go control flow.
// Missing, invalid, ambiguous, typed permanent, and contract failures produce
// structured PERMERROR results. Typed temporary failure produces TEMPERROR only
// without a higher-priority fact. A provider-owned deadline while the caller
// context is live is temporary only when explicitly typed temporary; otherwise
// it is a provider contract error.
//
// Every populated result reports scope=current, historical content and recipes
// not_evaluated, and historical signatures not_evaluated. Custody structure is
// reported separately as not_evaluated, not_present, nd_links_evaluated, or
// terminal_nd_requires_oob. Pre-extraction parser or early-limit uncertainty is
// not_evaluated, never not_present; not_present is reported only after
// successful extraction establishes absence. Structural link evaluation is not
// historical content or signature verification. A terminal current nd=
// requires unmodeled out-of-band trust and therefore returns PERMERROR.
//
// Supported PASS plus an unknown algorithm may pass; unknown-only coverage is
// PERMERROR, and a supported signature or current hash mismatch prevents PASS
// according to the precedence above. Callers should inspect typed state,
// ReasonCode, CheckClass, and SignatureSetFact values rather than parse text.
//
// Defaults and hard maxima are 32 MiB raw message bytes, 2,000 current
// recipients, 16 Message-Instance hash sets, 16 signature sets, 128 retained
// check facts, and 16 retained signature facts. Options may narrow but never
// widen these limits. Timestamp policy permits five minutes of future skew as
// local verification policy, not a draft requirement, and enforces a
// non-disableable 14-day maximum age.
//
// MAIL FROM comparison uses bracketed paths, ASCII-only domain lowercasing,
// case-sensitive local parts, and <> matching only <>. Every current recipient
// must occur in signed rt=; signed extras and order differences are allowed.
// Signing-domain d= uses relaxed right-label alignment against the signed MAIL
// FROM domain and is distinct from exact envelope-path comparison.
package dkim2
