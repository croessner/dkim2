// The Rspamd policy E2E compose helper is compiled only from a Nauthilus
// checkout through explicit file arguments (see ../run-policy-e2e.sh), which
// always resolves imports through the Nauthilus module. This go.mod only keeps
// the helper outside the root library module; it is intentionally not part of
// go.work and declares no requirements of its own.
module github.com/croessner/dkim2/contrib/rspamd/tests/policy-e2e

go 1.27

toolchain go1.27.3
