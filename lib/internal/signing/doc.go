// Package signing owns shared signing-operation contracts, restrictive limits,
// usage accounting, and bounded error vocabulary for the DKIM2 draft baseline.
//
// Protocol field construction remains owned by instance and signature. This
// package deliberately contains no provider, key, route-authority, recipe,
// raw-message mutation, public facade, or concrete observability behavior.
package signing
