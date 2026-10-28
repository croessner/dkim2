// Package tagvalue owns shared DKIM2 tag-list scanning rules.
//
// Both scanners implement the draft-ietf-dkim-dkim2-spec-08 Section 8
// tag-list grammar: at least one tag-spec, an optional final semicolon,
// case-sensitive names and values, and no duplicated tags. Scan is the DNS key
// record mode and unfolds valid CRLF WSP FWS. ScanHeader is the
// Message-Instance and DKIM2-Signature mode: it receives raw-header unfolded
// input and rejects any uppercase tag name under Sections 9 and 10, including
// unknown extension names.
// It also owns DKIM2 base64string parsing: space and tab FWS are stripped,
// non-canonical pad bits fail, and encoded plus decoded byte views remain
// immutable after parsing. ParseBase64String requires standard RFC 4648
// padding for protocol header fields. ParseOptionalPaddingBase64String is the
// DNS-02 mode; it accepts omitted terminal padding and returns canonical padded
// encoded bytes without relaxing alphabet, pad-bit, or resource limits.
//
// Errors from this package are structured and bounded. They expose stable
// codes, operational classes, safe location and limit metadata, and only
// allowlisted tag names; they must not include raw DKIM2 field values,
// decoded recipient paths, nonces, hashes, signatures, or other
// message-derived secret material.
package tagvalue
