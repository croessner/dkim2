// Package observability owns adapter-local, secret-safe logging and metrics.
//
// The package accepts only closed operational classifications. It deliberately
// has no API for addresses, hosts, queue identifiers, message content,
// capabilities, endpoints, keys, arbitrary errors, or arbitrary metric labels.
package observability
