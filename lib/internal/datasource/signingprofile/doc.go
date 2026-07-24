// Package signingprofile is the sole bridge from validated datasource results
// to signing profiles.
//
// An adapter resolves one self-contained datasource result, validates its exact
// identity and eligibility, and maps every provider-neutral key-handle ID
// through an immutable registry to an existing inert signing handle. The bridge
// does not invoke a signer, perform DNS lookup, authorize routes, or weaken any
// signing invariant. Missing, inconsistent, inactive, or unauthorized bindings
// fail closed without returning a partial profile.
package signingprofile
