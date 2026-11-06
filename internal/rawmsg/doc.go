// Package rawmsg owns the raw RFC 5322 message representation used by DKIM2
// protocol code.
//
// Values in this package are byte-oriented and immutable after construction.
// Constructors copy caller-owned slices, and accessors return fresh copies so
// later canonicalization, recipe, and signature code cannot accidentally
// observe mutated protocol state.
//
// The parser contract is strict by default. Raw messages are expected to use
// CRLF line endings, bounded header and body sizes, and explicit metadata for
// any future compatibility normalization. Structured errors report typed,
// bounded context only; they must not include raw message bodies, full header
// values, recipients, credentials, or other secret-bearing data.
package rawmsg
