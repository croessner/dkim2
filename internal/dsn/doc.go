// Package dsn parses the bounded MIME structure required before DKIM2 delivery-status evidence can be evaluated.
//
// It deliberately validates only the RFC 6522 report envelope and exposes
// byte-preserving part views. It does not interpret delivery-status fields,
// verify embedded DKIM2 state, or make signing or authorization decisions.
package dsn
