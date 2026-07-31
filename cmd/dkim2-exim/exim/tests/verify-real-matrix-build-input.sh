#!/usr/bin/env bash
# Verifies one source-matched Exim build input against its exact candidate.
set -euo pipefail

manifest=${1:-}
expected_base_revision=${2:-}
expected_candidate_snapshot_sha256=${3:-}
expected_adapter_sha256=${4:-}
expected_daemon_sha256=${5:-}
expected_binary_sha256=${6:-}
expected_source_sha256=${7:-}
expected_patch_sha256=${8:-}

# fail reports one bounded build-input verification failure.
fail() {
  printf '%s\n' 'real Exim matrix build input verification failed' >&2
  exit 1
}

[[ $# -eq 8 && $manifest == /* && ! -L $manifest && -f $manifest ]] || fail
[[ $expected_base_revision =~ ^[0-9a-f]{40}$ &&
  $expected_candidate_snapshot_sha256 =~ ^[0-9a-f]{64}$ &&
  $expected_adapter_sha256 =~ ^[0-9a-f]{64}$ &&
  $expected_daemon_sha256 =~ ^[0-9a-f]{64}$ &&
  $expected_binary_sha256 =~ ^[0-9a-f]{64}$ &&
  $expected_source_sha256 =~ ^[0-9a-f]{64}$ &&
  $expected_patch_sha256 =~ ^[0-9a-f]{64}$ ]] || fail
read -r manifest_size < <(wc -c <"$manifest")
[[ $manifest_size =~ ^[0-9]+$ && $manifest_size -le 4096 ]] || fail
if LC_ALL=C grep -q '[^ -~]' "$manifest"; then
  fail
fi
[[ $(tail -c 1 -- "$manifest" | wc -l | tr -d ' ') == 1 ]] || fail

mapfile -t lines <"$manifest"
[[ ${#lines[@]} -eq 13 ]] || fail
[[ ${lines[0]} == format=dkim2-exim-container-build-input-v1 ]] || fail
[[ ${lines[1]} == image=golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6 ]] || fail
[[ ${lines[2]} == platform=linux-amd64 ]] || fail
[[ ${lines[3]} == mta_uid=999 ]] || fail
[[ ${lines[4]} == "base_revision=$expected_base_revision" ]] || fail
[[ ${lines[5]} == "candidate_snapshot_sha256=$expected_candidate_snapshot_sha256" ]] || fail
[[ ${lines[6]} == "source_archive_sha256=$expected_source_sha256" ]] || fail
[[ ${lines[7]} == "transport_filter_patch_sha256=$expected_patch_sha256" ]] || fail
[[ ${lines[8]} =~ ^compiler_sha256=[0-9a-f]{64}$ ]] || fail
[[ ${lines[9]} == "adapter_sha256=$expected_adapter_sha256" ]] || fail
[[ ${lines[10]} == "daemon_sha256=$expected_daemon_sha256" ]] || fail
[[ ${lines[11]} == "binary_sha256=$expected_binary_sha256" ]] || fail
[[ ${lines[12]} == input_state=complete ]] || fail
