// Package recipe strictly parses and applies bounded DKIM2 message
// reconstruction recipes for draft-ietf-dkim-dkim2-spec-04.
//
// The package owns the decoded RFC 8259 schema, immutable recipe plans,
// reconstruction state, resource accounting, and transactional application.
// Message-Instance base64 remains owned by instance, RFC 5322 bytes remain
// owned by rawmsg, and canonical hashes and authenticated descent remain owned
// by canonical and verify. Recipe generation and serialization are deferred to
// a later increment.
package recipe
