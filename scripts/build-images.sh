#!/bin/sh
set -eu
umask 077

mode=${1:-primary}
case "$mode" in
  primary) output_dir=.artifacts ;;
  reproduction) output_dir=.artifacts/image-reproducibility/second ;;
  *) exit 2 ;;
esac
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory "$output_dir"
work=$(mktemp -d .artifacts/.image-build-work.XXXXXX)
docker_config=
builder=
builder_active=false

# cleanup removes only invocation-owned builder, credentials, and source state.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if test "$builder_active" = true; then
    if ! DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" \
      docker buildx rm "$builder" >/dev/null 2>&1; then
      printf '%s\n' 'project builder cleanup failed' >&2
      status=1
    fi
  fi
  if test -n "$docker_config"; then
    rm -rf -- "$docker_config" || status=1
  fi
  rm -rf -- "$work" || status=1
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
mkdir -m 0700 "$work/context"

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. \
    -materialize "$work/context" >"$work/metadata.json"
assert_candidate() {
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/buildmeta -root .. >"$work/metadata-current.json"
  cmp "$work/metadata.json" "$work/metadata-current.json"
}
version=$(jq -er .version "$work/metadata.json")
revision=$(jq -er .revision "$work/metadata.json")
source_date_epoch=$(jq -er .source_date_epoch "$work/metadata.json")
created=$(jq -er .created "$work/metadata.json")
dirty=$(jq -er .dirty "$work/metadata.json")
repository=$(pwd -P)
context="$repository/$work/context"
buildkit_image=$(jq -er \
  '.images[] | select(.name == "buildkit") |
   (.reference + "@sha256:" + .digest)' \
  "$context/build/container/build-inputs.json")

docker_config=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-docker-config.XXXXXX")
chmod 0700 "$docker_config"
printf '%s\n' '{"auths":{}}' >"$docker_config/config.json"
docker_host=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
case "$docker_host" in unix:///*) ;; *) exit 2;; esac
builder="dkim2-product-build-${work##*.}"
DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" docker buildx create \
  --name "$builder" \
  --driver docker-container \
  --driver-opt "image=$buildkit_image" \
  >/dev/null
builder_active=true
DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" \
  docker buildx inspect "$builder" --bootstrap >/dev/null

for target in dkim2d dkim2-milter dkim2ctl; do
  archive="$work/$target.oci.tar"
  DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" docker buildx build \
    --builder "$builder" \
    --file "$context/build/container/Containerfile" \
    --target "$target" \
    --platform linux/amd64,linux/arm64 \
    --network none \
    --build-arg "VERSION=$version" \
    --build-arg "REVISION=$revision" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --build-arg "CREATED=$created" \
    --build-arg "DIRTY=$dirty" \
    --provenance=false \
    --sbom=false \
    --output "type=oci,dest=$archive,rewrite-timestamp=true" \
    "$context"
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. \
      -install "$archive" \
      -target "$output_dir/$target.oci.tar" \
      -replace
  assert_candidate
done
