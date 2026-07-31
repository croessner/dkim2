#!/usr/bin/env bash
# Runs the closed real Exim matrix in a disposable systemd Linux container.
set -euo pipefail
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd -P)
input_root=${DKIM2_EXIM_REAL_MATRIX_INPUT_ROOT:-}
evidence_root=${DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT:-}
container_name=dkim2-exim-qualification-$$
runtime_volume=dkim2-exim-qualification-runtime-$$
base_image=dkim2-exim-qualification:local

# fail emits one bounded container qualification failure.
fail() {
  printf '%s\n' 'real Exim container qualification failed' >&2
  exit 1
}

[[ -n $input_root && -n $evidence_root && $input_root == /* && $evidence_root == /* ]] || fail
[[ ! -e $evidence_root && ! -L $evidence_root ]] || fail
[[ $(uname -s) == Darwin || $(uname -s) == Linux ]] || fail
command -v docker >/dev/null 2>&1 || fail
docker build --platform linux/amd64 --tag "$base_image" \
  --file "$script_dir/container/Containerfile" "$repository_root" >/dev/null

cleanup() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  docker volume rm --force "$runtime_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

evidence_parent=$(dirname -- "$evidence_root")
[[ ! -L $evidence_parent ]] || fail
mkdir -p -m 0700 "$evidence_parent"
chmod 0700 "$evidence_parent"
docker volume create "$runtime_volume" >/dev/null
docker run --detach --network none --platform linux/amd64 --privileged --cgroupns=host --name "$container_name" \
  --volume "$repository_root:/workspace:ro" \
  --volume "$input_root:/input:ro" \
  --volume "$evidence_parent:/evidence-parent" \
  --volume "$runtime_volume:/q" \
  "$base_image" >/dev/null

for _ in {1..150}; do
  state=$(docker exec "$container_name" systemctl is-system-running 2>/dev/null || true)
  [[ $state == running || $state == degraded ]] && break
  sleep 0.2
done
[[ ${state:-} == running || ${state:-} == degraded ]] || fail
docker exec \
  --env DKIM2_EXIM_REAL_MATRIX_INPUT_ROOT=/qualification/input \
  --env DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT=/qualification/evidence-parent/$(basename -- "$evidence_root") \
  --env DKIM2_EXIM_REAL_MATRIX_RUNTIME_PARENT=/q \
  "$container_name" bash -lc '
  set -euo pipefail
  if ! id Debian-exim >/dev/null 2>&1; then
    getent passwd 999 >/dev/null && exit 1
    useradd --system --uid 999 --user-group --home-dir /nonexistent Debian-exim
  fi
  test "$(id -u Debian-exim)" = 999
  install -d -m 0700 /qualification/input /qualification/evidence-parent
  chown root:root /q
  chmod 0755 /q
  cp -a /input/. /qualification/input/
  chown -R root:root /qualification/input
  find /qualification/input -mindepth 1 -type d -exec chmod 0711 {} +
  find /qualification/input -type f -name exim -exec chmod 4755 {} +
  mount --bind /evidence-parent /qualification/evidence-parent
  bash /workspace/cmd/dkim2-exim/exim/tests/run-real-matrix-linux.sh
'
