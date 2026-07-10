// Package tagvalue owns shared DKIM2 tag-list scanning rules.
//
// Scan accepts case-sensitive DNS-compatible tag lists, unfolds valid CRLF WSP
// FWS, and permits an optional final semicolon.
// ScanTerminated owns the stricter draft-ietf-dkim-dkim2-spec-04 header-field
// rule that every tag has a semicolon terminator and tag names are matched
// case-insensitively after M1 unfolding. Both split semicolon-separated tag
// specifications, preserve case-sensitive values, and reject ambiguous or
// duplicated tags before semantic parsers run.
// It also owns strict DKIM2 base64string parsing: space and tab FWS are
// stripped, standard RFC 4648 padding is required, non-canonical pad bits fail,
// and encoded plus decoded byte views remain immutable after parsing.
//
// Errors from this package are structured and bounded. They expose stable
// codes, operational classes, safe location and limit metadata, and only
// allowlisted tag names; they must not include raw DKIM2 field values,
// decoded recipient paths, nonces, hashes, signatures, or other
// message-derived secret material.
package tagvalue
