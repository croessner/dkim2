// Package dkim2 will expose the public facade for the DKIM2 reference
// implementation.
//
// The package is intentionally empty at this stage. The architecture document
// defines the first implementation boundaries before protocol code is added.
//
// This package is the root package of the standalone library module. Adapter
// implementations such as dkim2d and dkim2-milter should depend on this module
// instead of sharing adapter-specific dependencies with library consumers.
package dkim2
