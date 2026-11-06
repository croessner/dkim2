// Package datasource owns storage-neutral profile and administrative-policy
// contracts without binding protocol code to provider models.
//
// Requests select exact validated identities and uses. Successful results are
// immutable, self-contained, and generation-consistent; absence, ambiguity,
// inactive data, malformed input, provider unavailability, cancellation, and
// invariants remain distinct closed failures. Credentials contain public
// verification material and provider-neutral key-handle IDs, never private
// keys, signing callbacks, paths, or provider-specific backend records.
//
// Replay storage is a separate domain. Concrete providers and the signing
// bridge live in subpackages so protocol owners do not import provider
// implementations.
package datasource
