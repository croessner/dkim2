#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DKIM2_REPO=$(CDPATH= cd -- "$SCRIPT_DIR/../../../.." && pwd)
OVERLAY=$(mktemp "${TMPDIR:-/tmp}/dkim2-policy-e2e-overlay.XXXXXX")

cleanup() {
  rm -f "$OVERLAY"
}
trap cleanup EXIT INT TERM

VIRTUAL_TEST="$DKIM2_REPO/lib/internal/verify/policy_e2e_two_hop_test.go"
SOURCE_TEST="$SCRIPT_DIR/two_hop_projection_lock_test.gotxt"
printf '{"Replace":{"%s":"%s"}}\n' "$VIRTUAL_TEST" "$SOURCE_TEST" >"$OVERLAY"

POLICY_E2E_TWO_HOP_FIXTURE="$SCRIPT_DIR/dkim2-two-hop-response.json" \
  go test -overlay "$OVERLAY" ./lib/internal/verify -run '^TestPolicyE2ETwoHopProjectionBinding$' -count=1
