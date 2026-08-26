// Package tagvalue owns shared DKIM2 tag-list scanning rules.
//
// Scan accepts case-sensitive DNS-compatible tag lists, unfolds valid CRLF WSP
// FWS, and permits an optional final semicolon.
// ScanTerminated owns the stricter draft-ietf-dkim-dkim2-spec-05 header-field
// rule that every tag has a semicolon terminator and tag names are matched
// case-insensitively after raw-header unfolding. Both split semicolon-separated
// tag specifications, preserve case-sensitive values, and reject ambiguous or
// duplicated tags before semantic parsers run.
// It also owns DKIM2 base64string parsing: space and tab FWS are stripped,
// non-canonical pad bits fail, and encoded plus decoded byte views remain
// immutable after parsing. ParseBase64String requires standard RFC 4648
// padding for protocol header fields. ParseOptionalPaddingBase64String is the
// DNS-04 mode; it accepts omitted terminal padding and returns canonical padded
// encoded bytes without relaxing alphabet, pad-bit, or resource limits.
//
// Errors from this package are structured and bounded. They expose stable
// codes, operational classes, safe location and limit metadata, and only
// allowlisted tag names; they must not include raw DKIM2 field values,
// decoded recipient paths, nonces, hashes, signatures, or other
// message-derived secret material.
package tagvalue
