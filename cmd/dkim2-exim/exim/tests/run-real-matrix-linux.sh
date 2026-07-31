#!/usr/bin/env bash
# Runs the closed five-row Exim qualification from source-matched binaries.
set -euo pipefail
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd -P)
input_root=${DKIM2_EXIM_REAL_MATRIX_INPUT_ROOT:-}
evidence_root=${DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT:-}
executor="$script_dir/execute-real-matrix-linux.sh"
verifier="$script_dir/run-real-matrix.sh"
contract="$script_dir/real-matrix-contract.sh"
go_binary=/usr/local/go/bin/go

# fail reports one bounded driver failure without reading protected payloads.
fail() {
  printf '%s\n' 'real Exim matrix execution failed' >&2
  exit 1
}

# sha256_file returns one lowercase digest for a regular artifact.
sha256_file() {
  sha256sum "$1" | awk '{ print $1 }'
}

# require_root_directory accepts a direct root-owned mode-0700 directory.
require_root_directory() {
  [[ $1 == /* && ! -L $1 && -d $1 &&
    $(readlink -f -- "$1") == "$1" &&
    $(stat -c '%u:%a' "$1") == 0:700 ]] || fail
}

# require_direct_executable accepts one non-symlink executable input artifact.
require_direct_executable() {
  [[ $1 == /* && ! -L $1 && -f $1 && -x $1 ]] || fail
}

[[ $(uname -s) == Linux && $(id -u) -eq 0 ]] || fail
[[ -n $input_root && -n $evidence_root ]] || fail
require_root_directory "$input_root"
chmod 0711 "$input_root"
[[ $evidence_root == /* && ! -e $evidence_root && ! -L $evidence_root ]] || fail
require_direct_executable "$executor"
require_direct_executable "$verifier"
require_direct_executable "$go_binary"
[[ ! -L $contract && -s $contract ]] || fail
# shellcheck disable=SC1090,SC1091
source "$contract"

candidate_base_revision=$(git -C "$repository_root" rev-parse HEAD)
candidate_snapshot_sha256=$(
  "$go_binary" -C "$repository_root/tools" run ./cmd/candidateid -root ..
)
[[ $candidate_base_revision =~ ^[0-9a-f]{40}$ &&
  $candidate_snapshot_sha256 =~ ^[0-9a-f]{64}$ ]] || fail

mapfile -t rows < <(real_matrix_rows)
[[ ${#rows[@]} -eq 5 ]] || fail
adapter_sha256=
daemon_sha256=
run_material='dkim2-exim-real-matrix-run-v1'
for row in "${rows[@]}"; do
  case "$row" in
    upstream-4.99.5 | debian-4.98.2-1+deb13u3 | debian-4.98.2-1+deb13u4 | \
      ubuntu-4.99.1-1ubuntu1.3 | ubuntu-4.99.1-1ubuntu1.4) ;;
    *) fail ;;
  esac
  row_root="$input_root/$row"
  [[ ! -L $row_root && -d $row_root &&
    $(readlink -f -- "$row_root") == "$row_root" ]] || fail
  for artifact in exim dkim2-exim dkim2d; do
    require_direct_executable "$row_root/$artifact"
  done
  current_adapter_sha256=$(sha256_file "$row_root/dkim2-exim")
  current_daemon_sha256=$(sha256_file "$row_root/dkim2d")
  if [[ -z $adapter_sha256 ]]; then
    adapter_sha256=$current_adapter_sha256
    daemon_sha256=$current_daemon_sha256
  else
    [[ $adapter_sha256 == "$current_adapter_sha256" &&
      $daemon_sha256 == "$current_daemon_sha256" ]] || fail
  fi
  run_material+=$'\n'
  run_material+="$row:$(sha256_file "$row_root/exim"):$current_adapter_sha256:$current_daemon_sha256"
done
run_id=$(printf '%s' "$run_material" | sha256sum | awk '{ print $1 }')
mkdir -m 0700 "$evidence_root"
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\n' \
	'format=dkim2-exim-real-matrix-run-v1' \
	"run_id=$run_id" \
	"base_revision=$candidate_base_revision" \
	"candidate_snapshot_sha256=$candidate_snapshot_sha256" \
	"matrix_helper_sha256=$(sha256_file "$script_dir/real_matrix_service.py")" \
  "created_at=$created_at" >"$evidence_root/run-v1.txt"
chmod 0600 "$evidence_root/run-v1.txt"

for row in "${rows[@]}"; do
  row_root="$input_root/$row"
  version=$(awk -F= '$1 == "exim_version" { print $2 }' \
    "$repository_root/cmd/dkim2-exim/exim/fixtures/$row/source-manifest-v1.txt")
  build_id=$(awk -F= '$1 == "build_id" { print $2 }' \
    "$repository_root/cmd/dkim2-exim/exim/fixtures/$row/compatibility-manifest-v1.txt")
  [[ $version =~ ^[0-9][0-9A-Za-z.+:~_-]{0,127}$ &&
    $build_id =~ ^[0-9a-f]{64}$ ]] || fail
  bash "$executor" "$row" "$row_root/exim" "$version" "$build_id" \
    "$row_root/dkim2-exim" "$row_root/dkim2d" "$evidence_root/$row" "$run_id"
done

DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT="$evidence_root" \
  DKIM2_EXIM_REAL_MATRIX_RUN_ID="$run_id" \
  DKIM2_EXIM_REAL_MATRIX_ADAPTER_SHA256="$adapter_sha256" \
  DKIM2_EXIM_REAL_MATRIX_DAEMON_SHA256="$daemon_sha256" \
  bash "$verifier"
