// Package signingstore owns descriptor-confined private signing generations
// for the daemon.
//
// It composes one immutable flat-file datasource snapshot, its exact
// signing-profile registry, and opaque PKCS#8 private signers. Provider records
// and private material never cross this package boundary.
package signingstore
