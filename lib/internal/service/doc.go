// Package service coordinates bounded current-message verification and maps
// protocol-core facts into deterministic four-state internal results.
//
// Service is the sole authentication boundary for policy projections. It
// validates the verify-owned target flag candidate against the authoritative
// selected target, upgrades current flags only after aggregate PASS, and seals
// complete pre-retention signature and DNS key metadata. Public fact-retention
// limits never reconstruct or narrow that policy evidence. Pre-target failures
// are sealed as fact-free unavailable projections; incoherent provenance fails
// closed. Service does not parse signature fields or raw f= values.
package service
