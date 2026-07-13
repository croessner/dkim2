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
// EvaluatePolicy applies a separate immutable local policy decision to the
// sealed projection embedded in a library-created VerifyResult. Verification
// state remains authoritative and unchanged. Strict mode is the default;
// permissive and testing modes require explicit options. A continue verdict is
// non-terminal and is neither PASS nor accept. Every successful evaluation
// returns exactly one matching disposition action.
//
// The public verifier authenticates current-signature flags only on aggregate
// PASS. Current scope therefore reports donotmodify and donotexplode history as
// not_evaluated and never infers historical honor. Feedback output is bounded
// intent without a destination or route. DNS t=y is authenticated key metadata,
// not the local testing mode; coherent all-set testing makes PASS and the
// closed eligible failure rows non-terminal without rewriting verification
// state. Effective testing PASS also suppresses flag-derived compliance,
// feedback, and exploded output. Pre-target malformed, missing, sequence, or
// limit outcomes remain valid fact-free PERMERROR results for policy
// evaluation. Policy results, findings, actions, and errors contain only bounded
// enums, booleans, counts, and sequence numbers, never message, identity,
// selector, key, provider, or route material.
//
// Provider status is exactly found, missing, invalid, ambiguous, revoked,
// unsupported_key_type, or algorithm_mismatch, and a declared status accompanies
// a nil error. Found results contain a matching *rsa.PublicKey or
// ed25519.PublicKey; accepted public material is cloned before use. Private
// keys, crypto.Signer, open-ended material, mismatched algorithms, and
// inconsistent status/material pairs are not accepted. Provider failures are
// classified only through typed temporary or permanent errors, never error
// text. An error matching the active caller context remains Go control flow.
// Missing, invalid, ambiguous, revoked, unsupported, mismatch, typed permanent,
// and contract failures produce structured PERMERROR results. Typed temporary
// failure produces TEMPERROR only without a higher-priority fact. A
// provider-owned deadline while the caller context is live is temporary only
// when explicitly typed temporary; otherwise it is a provider contract error.
//
// NewDNSPublicKeyProvider constructs the DNS-backed provider for
// draft-chuang-dkim2-dns-04. It derives an absolute
// <selector>._domainkey.<signing-domain>. owner from signed values, so transports
// and callers must treat that name as sensitive diagnostic data. TXTTransport
// returns already-concatenated bytes for one TXT resource record while retaining
// the RR count. More than one RR is fail-closed ambiguous; records are never
// selected or concatenated across RR boundaries. NetTXTTransport maps each
// net.Resolver string to one RR and supplies zero TTL, so it cannot populate the
// provider cache. TTL-aware injected transports may enable bounded positive,
// authoritative-negative, and stable-error caching.
//
// DNS key records use PKCS#1 RSAPublicKey DER for RSA and exactly 32 raw bytes
// for Ed25519. Empty p= is revoked. Non-empty p= accepts omitted terminal
// Base64 padding as DNS-04 specifies while still requiring canonical zero pad
// bits. The parser follows the DNS-04 k= prose and RFC 6376 Erratum 5137 by
// recognizing lowercase k= despite the inherited ABNF typo. The active DKIM2
// signature grammar exposes no q= option; DNS TXT is the only lookup binding.
// Testing t=y and strict-identity t=s declarations reach
// KeyPolicyMetadata, but do not change cryptographic state or prescribe an MTA
// action. StrictIdentityApplicable is false because the active DKIM2 i= is a
// numeric sequence. DNSSECStatus is bounded transport diagnostic metadata and
// never changes key acceptance, cache lifetime, or verification facts.
//
// DNSProviderConfig bounds cache capacity, TTL classes, transport concurrency,
// coalesced waiters, and lookup duration. Non-final canceled waiters leave a
// shared lookup independently. The final canceled waiter cancels the transport
// context and remains cleanup owner until the context-compliant transport
// returns. A deliberately context-ignoring injected transport can therefore
// hold that final caller and its single bounded flight slot; no helper goroutine
// is created to pretend arbitrary Go code can be forcibly canceled.
//
// Every populated public result reports scope=current, historical content and
// recipes not_evaluated, and historical signatures not_evaluated. The internal
// verifier may reconstruct and hash-check bounded Message-Instance history only
// after current PASS, but that internal content evidence is intentionally not
// projected through this public facade and never authenticates historical
// signatures or policy flags. Custody structure is
// reported separately as not_evaluated, not_present, nd_links_evaluated, or
// terminal_nd_requires_oob. Pre-extraction parser or early-limit uncertainty is
// not_evaluated, never not_present; not_present is reported only after
// successful extraction establishes absence. Structural link evaluation is not
// historical content or signature verification. A terminal current nd=
// requires unmodeled out-of-band trust and therefore returns PERMERROR.
//
// The internal recipe subsystem can also generate deterministic conservative
// decoded JSON that applies to a current state to reconstruct previous recipe
// semantics. Generation is not exposed by this public facade and does not
// decide whether hashes require a new Message-Instance. Base64, field
// formatting, sequence progression, revision signing, and private-key use
// remain outside the current public API.
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
