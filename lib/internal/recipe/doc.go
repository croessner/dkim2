// Package recipe strictly parses, applies, and generates bounded DKIM2 message
// reconstruction recipes for draft-ietf-dkim-dkim2-spec-04.
//
// The package owns the decoded RFC 8259 schema, immutable recipe plans,
// reconstruction state, resource accounting, transactional application, and
// deterministic inverse generation from a current source state to a previous
// target state. Generated compact decoded JSON is conservative and reproducible
// but not required to be minimal. Copy-only disclosure and unavailable-body
// behavior are explicit closed policies, and every recipe success passes the
// package's strict parse, apply, and semantic reconstruction proof first.
//
// Message-Instance base64 remains owned by instance, RFC 5322 bytes remain
// owned by rawmsg, and signed-header relevance and canonical hashes remain
// owned by canonical. Authenticated history remains owned by verify. Hash-gated
// revision decisions, Message-Instance formatting, and signing are outside this
// package.
package recipe
