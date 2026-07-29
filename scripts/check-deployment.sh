#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
output=$(mktemp -d /tmp/dkim2-deployment-check.XXXXXX)
trap 'rm -rf "$output"' EXIT HUP INT TERM
chmod 0700 "$output"
mkdir -m 0700 "$output/home"

revision=0000000000000000000000000000000000000000
created=1970-01-01T00:00:00Z

render() {
  destination=$1
  shift
  render_with_images "$destination" dkim2d:local dkim2-milter:local "$@"
}

render_with_images() {
  destination=$1
  daemon_image=$2
  milter_image=$3
  shift 3
  env -i \
    PATH=/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin \
    HOME="$output/home" \
    TMPDIR=/tmp \
    DKIM2_REVISION="$revision" \
    SOURCE_DATE_EPOCH=0 \
    DKIM2_CREATED="$created" \
    DKIM2_VERSION=0.0.0-dev \
    DKIM2_DIRTY=clean \
    DKIM2D_IMAGE="$daemon_image" \
    DKIM2_MILTER_IMAGE="$milter_image" \
    docker compose \
      --project-name dkim2-postfix \
      --project-directory "$root/deployments/postfix-compose" \
      "$@" config --format json >"$destination"
}

render "$output/default.json" \
  --file "$root/deployments/postfix-compose/compose.yaml"
render "$output/demo.json" \
  --file "$root/deployments/postfix-compose/compose.yaml" \
  --file "$root/deployments/postfix-compose/compose.demo.yaml"

GOCACHE=${GOCACHE:-/tmp/dkim2-go-build-cache} \
  go -C "$root/tools" run ./cmd/deploymentpolicy \
    -default "$output/default.json" \
    -demo "$output/demo.json" \
    -root "$root"

render_with_images \
  "$output/hostile-default.json" \
  untrusted.example/dkim2d:mutable \
  untrusted.example/dkim2-milter:mutable \
  --file "$root/deployments/postfix-compose/compose.yaml"
render_with_images \
  "$output/hostile-demo.json" \
  untrusted.example/dkim2d:mutable \
  untrusted.example/dkim2-milter:mutable \
  --file "$root/deployments/postfix-compose/compose.yaml" \
  --file "$root/deployments/postfix-compose/compose.demo.yaml"
if GOCACHE=${GOCACHE:-/tmp/dkim2-go-build-cache} \
  go -C "$root/tools" run ./cmd/deploymentpolicy \
    -default "$output/hostile-default.json" \
    -demo "$output/hostile-demo.json" \
    -root "$root" >/dev/null 2>&1; then
  echo "deployment policy accepted hostile image authority" >&2
  exit 1
fi
