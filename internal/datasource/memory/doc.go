// Package memory provides the immutable static datasource reference provider.
//
// Construction validates and detaches one complete profile, policy, and handle
// dataset before publication. Exact lookups are lock-free, deterministic, and
// return self-contained values from the single published generation. The
// provider has no reload, fallback, clock, network, signer, or replay behavior.
package memory
