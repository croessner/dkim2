// Package flatfile decodes strict bounded versioned datasource documents into
// immutable in-memory snapshots.
//
// On Linux and macOS the provider duplicates and owns a caller-opened directory
// descriptor, validates root and file metadata, and reads one no-follow file
// descriptor relative to that confined root. Reload publishes a complete
// generation atomically. A failed reload retains the prior snapshot only for
// recovery and makes later resolves unavailable until an explicit successful
// reload. The package never resolves paths from record values, exposes private
// keys, serves degraded state, or runs background reload work.
package flatfile
