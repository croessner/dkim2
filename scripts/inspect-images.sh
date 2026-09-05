#!/bin/sh
set -eu

action=${1:-check}
case "$action" in
  check|reproducibility) ;;
  *) exit 2 ;;
esac

umask 077
evidence=.artifacts/image-evidence
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory "$evidence"
work=$(mktemp -d .artifacts/.image-inspection-work.XXXXXX)
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM
for product in dkim2d dkim2-milter dkim2ctl dkim2-dsn-propagator; do
  archive=".artifacts/$product.oci.tar"
  test -f "$archive"
  test ! -L "$archive"
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/ocipolicy \
      -archive "../$archive" \
      -product "$product" >"$work/$product.oci.json"
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. \
      -install "$work/$product.oci.json" \
      -target "$evidence/$product.oci.json" -replace
done

if test "$action" = reproducibility; then
  scripts/build-images.sh reproduction
  for product in dkim2d dkim2-milter dkim2ctl dkim2-dsn-propagator; do
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/ocipolicy \
        -archive "../.artifacts/image-reproducibility/second/$product.oci.tar" \
        -product "$product" >"$work/$product.second.json"
    cmp "$evidence/$product.oci.json" \
      "$work/$product.second.json"
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/safepath -root .. \
        -install "$work/$product.second.json" \
        -target ".artifacts/image-reproducibility/$product.second.json" -replace
  done
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-image-policy.XXXXXX")
trap 'rm -rf -- "$temporary" "$work"' EXIT HUP INT TERM
ln -s "$PWD/.artifacts/dkim2d.oci.tar" "$temporary/symlink.oci.tar"
if GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/ocipolicy \
    -archive "$temporary/symlink.oci.tar" -product dkim2d >/dev/null 2>&1; then
  exit 1
fi
if GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/ocipolicy \
    -archive "../.artifacts/dkim2d.oci.tar" -product dkim2ctl >/dev/null 2>&1; then
  exit 1
fi
! grep -Eiq '(/Users/|/home/|private.?key|capability|credential|message-instance|selector|recipient|sender)' \
  "$evidence"/*.oci.json
