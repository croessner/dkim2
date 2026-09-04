// Package dkim2 provides verification and signing for
// draft-ietf-dkim-dkim2-spec-06.
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
// The public verifier authenticates every inherited signature flag on aggregate
// PASS. Complete history can therefore evaluate donotmodify and donotexplode
// across the authenticated chain. Feedback output is bounded
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
// NewDNSPublicKeyProvider constructs the DNS-backed provider for the tested
// draft-chuang-dkim2-dns-04 behavior baseline. That document was replaced by
// draft-ietf-dkim-dkim2-dns-00 without a normative-body change; changing the
// version identifier remains an explicit reviewed baseline migration. The
// provider derives an absolute
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
// Aggregate PASS reports scope=chain, authenticated content coverage as complete
// or partial only for explicit unavailable-body history, and historical
// signatures as complete. Non-PASS results retain scope=current and do not claim
// historical coverage. The verifier reconstructs bounded Message-Instance
// history and verifies every inherited signature after current PASS. Custody structure is
// reported separately as not_evaluated, not_present, nd_links_evaluated, or
// terminal_nd_requires_oob. Pre-extraction parser or early-limit uncertainty is
// not_evaluated, never not_present; not_present is reported only after
// successful extraction establishes absence. Structural link evaluation is not
// historical content or signature verification. A terminal current nd=
// requires unmodeled out-of-band trust and therefore returns PERMERROR.
//
// NewSigner exposes exactly three request paths. SignOriginator creates the
// initial Message-Instance and DKIM2-Signature. SignExisting consumes only a
// capability issued by VerifyForRevision and derives hash-unchanged forwarding
// or revision from the Section 9.1 digest gate; callers cannot select the role.
// SignNextDomain consumes the same sealed revision evidence plus a fresh,
// single-use published-next-domain capability and emits one terminal nd=
// signature. All paths snapshot the raw message plus the independently observed
// exact outgoing SMTP reverse path and ordered forward paths. Signing requires
// that envelope observation to equal the authority-issued exact-copy route
// ticket; it is never inferred from the ticket. All paths also require the
// closed final_network_form_pre_dot_stuffing transport declaration. Signing
// profiles contain public verification material and opaque private-key handles;
// injected private signers receive only one closed algorithm and native SHA-256
// digest.
//
// Fanout planning binds raw pre-sign bytes, envelope paths, disclosure class,
// route scope, purpose, and revision capability before signing. Signing limits
// may narrow but never widen the protocol, recipe, verification, route, crypto,
// and callback owners' hard ceilings. Every successful message is inserted,
// reparsed, custody-checked, and cryptographically self-verified before its
// reservation commits to unrestricted completion or the exact
// restricted-release state.
//
// Internal datasource providers resolve exact immutable signing profiles and
// administrative policies without becoming protocol authorities. The
// datasource/signingprofile package is the only bridge to the signing domain:
// it validates same-snapshot results and maps provider-neutral key-handle IDs
// through an immutable registry to existing inert PrivateKeyHandle values.
// Datasource success never replaces the fresh DNS publication check, signing
// validation, route authorization, or private signer callback. The confined
// flat-file provider owns a duplicated directory descriptor, strictly decodes
// bounded versioned JSON, publishes complete snapshots atomically, and stops
// serving after a failed reload until explicit recovery.
//
// Verifier.EvaluateReceivedDSN exposes the read-only Draft-06 Section 12.1.2
// evaluation of an inbound DKIM2-signed delivery-status notification after the
// caller verified the outer message as an ordinary message with the same
// verifier. It takes the exact outer bytes, the observed null reverse path and
// single forward path, and an optional tenant-bound LocalAuthority, and proves
// in order RFC 6522 and strict generic RFC 3464 structure, embedded-original
// verification through the dedicated embedded verifiers, local-hop identity,
// outer-signer alignment, recipient linkage, failure class, and the previous
// hop. The completion signature's Section 8.4 window is evaluated at the outer
// DSN's highest-signature t= instead of the clock, because a DSN may
// legitimately arrive long after the forwarding it reports on. "Local" is
// datasource authority over the completion signature's d=, never an address
// in mf=; a verified foreign signer naming a local address is not_local. The
// local hop is a run: the completion signature plus every Section 9.3 nd= or
// same-tenant imaginary-hop member below it, each verified cryptographically;
// a non-verifying member or an nd= previous hop is an unsupported chain. The
// result is the closed delivery_status projection with bounded sequence facts
// and no content; it can never authorize signing. Without an authority the
// local hop and propagation are not evaluated. WithReceivedDSNEvaluation
// attaches the evaluation to EvaluatePolicy or EvaluateAuthenticationPolicy,
// which record the received-DSN mapping-table row as one finding on the single
// PolicyDecision: reject, tempfail, and continue rows replace the outer
// verdict, accept rows keep it, and an outer verification or final replay
// state other than PASS keeps the outer policy unchanged.
//
// SigningResult is a closed sum. Only UnrestrictedSignedMessage has Bytes.
// LocalOnlySignedMessage and OutOfBandAcceptanceSignedMessage deliberately have
// no generic byte, marshal, text, or release surface. Their type-specific
// release methods atomically consume the same ticket lineage only after proving
// the exact sealed in-control route or OOB receiver, envelope, and route. A
// terminal next-domain result remains OOB-restricted until that release or a
// later authorized ordinary completion. Once an adapter legitimately receives
// released bytes, it can still duplicate or misroute them; the library does not
// claim replay prevention outside the bound release arrangement.
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
