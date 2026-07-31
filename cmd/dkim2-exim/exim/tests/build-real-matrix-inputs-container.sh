#!/usr/bin/env bash
# Builds five source-matched Exim binaries in a disposable pinned Linux container.
set -euo pipefail
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd -P)
source_root=${DKIM2_EXIM_QUALIFICATION_SOURCE_ROOT:-}
input_root=${DKIM2_EXIM_REAL_MATRIX_INPUT_ROOT:-}
base_image=golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6

# fail emits one bounded build-input failure.
fail() {
  printf '%s\n' 'real Exim matrix input build failed' >&2
  exit 1
}

[[ $source_root == /* && -d $source_root && ! -L $source_root ]] || fail
[[ $input_root == /* && ! -e $input_root && ! -L $input_root ]] || fail
command -v docker >/dev/null 2>&1 || fail
base_revision=$(git -C "$repository_root" rev-parse HEAD)
candidate_snapshot_sha256=$(
  go -C "$repository_root/tools" run ./cmd/candidateid -root ..
)
[[ $base_revision =~ ^[0-9a-f]{40}$ &&
  $candidate_snapshot_sha256 =~ ^[0-9a-f]{64}$ ]] || fail
mkdir -m 0700 "$input_root"

docker run --rm --platform linux/amd64 \
  --env "DKIM2_BUILD_BASE_REVISION=$base_revision" \
  --env "DKIM2_BUILD_CANDIDATE_SNAPSHOT_SHA256=$candidate_snapshot_sha256" \
  --volume "$repository_root:/workspace:ro" \
  --volume "$source_root:/sources:ro" \
  --volume "$input_root:/output" \
  "$base_image" bash -lc '
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    export PATH=/usr/local/go/bin:/go/bin:$PATH
    # Keep the large transient Go cache on the mounted output volume, not the image layer.
    export GOCACHE=/output/.go-cache
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends \
      build-essential libdb-dev libfile-fcntllock-perl libgnutls28-dev libidn11-dev libidn2-dev libldap2-dev \
      libpcre2-dev libsqlite3-dev make patch >/dev/null
    id Debian-exim >/dev/null 2>&1 || useradd --system --uid 999 --user-group --home-dir /nonexistent Debian-exim
    test "$(id -u Debian-exim)" = 999
    mkdir -p /build
    # Bound Go parallelism so the evidence builder remains reproducible on constrained runners.
    CGO_ENABLED=0 go -C /workspace/cmd/dkim2-exim build -p 2 -o /output/dkim2-exim .
    CGO_ENABLED=0 go -C /workspace/cmd/dkim2d build -p 2 -o /output/dkim2d .
    exec > >(tee /output/builder.log) 2>&1
    set -x
    adapter_sha=$(sha256sum /output/dkim2-exim | awk "{print \$1}")
    daemon_sha=$(sha256sum /output/dkim2d | awk "{print \$1}")
    patch_file=/workspace/cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch
    patch_sha=$(sha256sum "$patch_file" | awk "{print \$1}")
    compiler_sha=$(cc --version | sha256sum | awk "{print \$1}")
    for row in upstream-4.99.5 debian-4.98.2-1+deb13u3 debian-4.98.2-1+deb13u4 ubuntu-4.99.1-1ubuntu1.3 ubuntu-4.99.1-1ubuntu1.4; do
      row_log=/output/$row.build.log
      (
      set -x
      case "$row" in
        upstream-4.99.5) archive=/sources/upstream/exim-4.99.5.tar.xz ;;
        debian-4.98.2-1+deb13u3) archive=/sources/debian-u3/exim4_4.98.2.orig.tar.xz ;;
        debian-4.98.2-1+deb13u4) archive=/sources/debian-u4/exim4_4.98.2.orig.tar.xz ;;
        ubuntu-4.99.1-1ubuntu1.3) archive=/sources/ubuntu-u13/exim4_4.99.1.orig.tar.xz ;;
        ubuntu-4.99.1-1ubuntu1.4) archive=/sources/ubuntu-u14/exim4_4.99.1.orig.tar.xz ;;
      esac
      test -f "$archive"
      archive_sha=$(sha256sum "$archive" | awk "{print \$1}")
      source_manifest="/workspace/cmd/dkim2-exim/exim/fixtures/$row/source-manifest-v1.txt"
      expected_archive_sha=$(awk -F= "\$1 == \"source_sha256\" { print \$2 }" "$source_manifest")
      expected_patch_sha=$(awk -F= "\$1 == \"transport_filter_patch_sha256\" { print \$2 }" "$source_manifest")
      test "$archive_sha" = "$expected_archive_sha"
      test "$patch_sha" = "$expected_patch_sha"
      work=/build/$row
      mkdir -p "$work"
      tar -C "$work" -xJf "$archive"
      mapfile -t source_candidates < <(
        find "$work" -mindepth 1 -maxdepth 1 -type d -print
      )
      test "${#source_candidates[@]}" -eq 1
      source=${source_candidates[0]}
      patch --fuzz=0 -s -p1 -d "$source" <"$patch_file"
      test -d "$source/Local"
      cp "$source/src/EDITME" "$source/Local/Makefile"
      printf "%s\\n" "EXIM_USER=Debian-exim" "EXIM_GROUP=Debian-exim" "CONFIGURE_FILE=/etc/exim.conf" "SUPPORT_I18N=yes" "LDFLAGS += -lidn" "USE_GNUTLS=yes" "TLS_LIBS=-lgnutls -lgnutls-dane" >>"$source/Local/Makefile"
      printf "%s\\n" \
        "HAVE_LOCAL_SCAN=yes" \
        "LOCAL_SCAN_SOURCE=Local/dkim2_local_scan.c" \
        "LOCAL_SCAN_HAS_OPTIONS=yes" \
        "CFLAGS += -DDKIM2_EXIM_SOURCE_MATCHED=1 -I../Local" >>"$source/Local/Makefile"
      cp /workspace/cmd/dkim2-exim/exim/dkim2_local_scan.c "$source/Local/dkim2_local_scan.c"
      cp "/workspace/cmd/dkim2-exim/exim/fixtures/$row/build-id-v1.h" "$source/Local/build-id-v1.h"
      case "$row" in
        upstream-4.99.5 | ubuntu-4.99.1-1ubuntu1.3 | ubuntu-4.99.1-1ubuntu1.4)
          (cd "$source/src" && patch --fuzz=0 -s -p0 < /workspace/cmd/dkim2-exim/exim/fixtures/upstream-4.99.5/local_scan-expand-string.patch)
          ;;
      esac
      make -C "$source" makefile
      make -C "$source" -j2
      binary=$(find "$source" -type f -path "*/build-*/*" -name exim -print -quit)
      test -n "$binary"
      mkdir -m 0700 "/output/$row"
      install -m 0755 "$binary" "/output/$row/exim"
      install -m 0755 /output/dkim2-exim "/output/$row/dkim2-exim"
      install -m 0755 /output/dkim2d "/output/$row/dkim2d"
      expected_build_id=$(awk "/^#define DKIM2_EXIM_BUILD_ID_V1 / { print \$3 }" \
        "/workspace/cmd/dkim2-exim/exim/fixtures/$row/build-id-v1.h" | tr -d "\"")
      test "${#expected_build_id}" -eq 64
      test "$(grep -aFo "$expected_build_id" "/output/$row/exim" | wc -l)" -eq 1
      test "$(grep -aFo "\$dkim2_transport_filter_return_path" "/output/$row/exim" | wc -l)" -eq 1
      binary_sha=$(sha256sum "/output/$row/exim" | awk "{print \$1}")
      printf "%s\\n" \
        format=dkim2-exim-container-build-input-v1 \
        image=golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6 \
        platform=linux-amd64 \
        mta_uid=999 \
        base_revision="$DKIM2_BUILD_BASE_REVISION" \
        candidate_snapshot_sha256="$DKIM2_BUILD_CANDIDATE_SNAPSHOT_SHA256" \
        source_archive_sha256="$archive_sha" \
        transport_filter_patch_sha256="$patch_sha" \
        compiler_sha256="$compiler_sha" \
        adapter_sha256="$adapter_sha" \
        daemon_sha256="$daemon_sha" \
        binary_sha256="$binary_sha" \
        input_state=complete \
        >"/output/$row/build-input-v1.txt"
      chmod 0600 "/output/$row/build-input-v1.txt"
      ) >"$row_log" 2>&1
      chmod 0600 "$row_log"
    done
    rm -rf /output/.go-cache
    rm -f /output/dkim2-exim /output/dkim2d
  '

[[ $(git -C "$repository_root" rev-parse HEAD) == "$base_revision" ]] || fail
current_candidate_snapshot_sha256=$(
  go -C "$repository_root/tools" run ./cmd/candidateid -root ..
)
[[ $current_candidate_snapshot_sha256 == "$candidate_snapshot_sha256" ]] || fail
