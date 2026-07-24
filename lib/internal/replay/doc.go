// Package replay owns storage-neutral replay detection contracts and invariants.
//
// Replay detection is explicit local policy. This package does not modify
// DKIM2 verification results or turn local replay disposition into protocol
// conformance.
package replay
