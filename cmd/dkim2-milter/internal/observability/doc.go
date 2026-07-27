// Package observability owns adapter-local, secret-safe logging and metrics.
//
// The package accepts only closed operational classifications. It deliberately
// has no API for mail data, identities, network peers, paths, capabilities,
// endpoints, keys, arbitrary errors, or arbitrary metric labels.
package observability
