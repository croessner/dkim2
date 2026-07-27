// Package milter implements the bounded pure-Go Milter-v6 adapter boundary.
//
// It intentionally owns callback reconstruction and operational policy only;
// all DKIM2 protocol semantics remain in the standalone library and daemon.
package milter
