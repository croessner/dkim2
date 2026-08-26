#!/bin/sh
set -eu

work=$(mktemp -d /tmp/dkim2-openapi-make-contract.XXXXXX)
chmod 0700 "$work"
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

generated_paths='cmd/dkim2d/internal/httpjson/wire/protected_string.gen.go
cmd/dkim2ctl/internal/testclient/wire/protected_string.gen.go
cmd/dkim2-milter/internal/daemon/wire/protected_string.gen.go
cmd/dkim2-exim/internal/daemon/wire/protected_string.gen.go
cmd/dkim2d/internal/httpjson/generated/server.gen.go
cmd/dkim2ctl/internal/testclient/generated/client.gen.go
cmd/dkim2-milter/internal/daemon/generated/client.gen.go
cmd/dkim2-milter/internal/integration/generated/server.gen.go
cmd/dkim2-exim/internal/daemon/generated/client.gen.go
cmd/dkim2-exim/internal/integration/generated/server.gen.go'

# snapshot_generated records stable identities for every generated OpenAPI artifact.
snapshot_generated() {
	output=$1
	: >"$output"
	printf '%s\n' "$generated_paths" | while IFS= read -r path; do
		test -f "$path"
		shasum -a 256 "$path"
	done >"$output"
}

snapshot_generated "$work/before.sha256"
if ! make -n release-candidate >"$work/dry-run.log" 2>&1; then
	cat "$work/dry-run.log" >&2
	exit 1
fi
snapshot_generated "$work/after.sha256"
cmp "$work/before.sha256" "$work/after.sha256"

if ! make -j2 check-openapi >"$work/parallel.log" 2>&1; then
	cat "$work/parallel.log" >&2
	exit 1
fi
if grep -Eiq 'jobserver unavailable|using -j1' "$work/parallel.log"; then
	cat "$work/parallel.log" >&2
	exit 1
fi

stale_output="$work/server.gen.go"
cp cmd/dkim2d/internal/httpjson/generated/server.gen.go "$stale_output"
printf '\n' >>"$stale_output"
if make check-openapi OPENAPI_SERVER_OUTPUT="$stale_output" >"$work/stale.log" 2>&1; then
	echo 'check-openapi admitted stale alternate server output' >&2
	exit 1
fi
