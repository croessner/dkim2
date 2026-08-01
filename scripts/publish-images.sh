#!/bin/sh
set -eu
umask 077

test "$#" -eq 0
test "${GITHUB_EVENT_NAME:-}" = release
test "${GITHUB_REF_TYPE:-}" = tag
test "${GITHUB_REF_PROTECTED:-}" = true
test "${GITHUB_REPOSITORY:-}" = croessner/dkim2
test -n "${GITHUB_REF_NAME:-}"
test -n "${GITHUB_TOKEN:-}"

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory .artifacts
work=$(mktemp -d .artifacts/.image-build-work.publish.XXXXXX)
docker_config=
builder=
builder_active=false

# cleanup removes only invocation-owned builder and credential state.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if test "$builder_active" = true; then
    if ! DOCKER_CONFIG="$docker_config" docker buildx rm "$builder" \
      >/dev/null 2>&1; then
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
docker_config=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-publish-docker.XXXXXX")
chmod 0700 "$docker_config"
printf '%s\n' '{"auths":{}}' >"$docker_config/config.json"
builder="dkim2-release-publish-${work##*.}"

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. \
    -materialize "$work/context" >"$work/metadata.json"

# assert_candidate proves repository state has not changed since materialization.
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
test "$version" = "$GITHUB_REF_NAME"
test "$dirty" = clean
test "$(git rev-parse "$version^{commit}")" = "$revision"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) exit 2 ;;
esac
major=${version%%.*}
minor=${version%.*}
context="$(pwd -P)/$work/context"
buildkit_image=$(jq -er \
  '.images[] | select(.name == "buildkit") |
   (.reference + "@sha256:" + .digest)' \
  "$context/build/container/build-inputs.json")

printf '%s' "$GITHUB_TOKEN" |
  DOCKER_CONFIG="$docker_config" docker login ghcr.io \
    --username "${GITHUB_ACTOR:-github-actions}" --password-stdin >/dev/null
DOCKER_CONFIG="$docker_config" docker buildx create \
  --name "$builder" \
  --driver docker-container \
  --driver-opt "image=$buildkit_image" \
  >/dev/null
builder_active=true
DOCKER_CONFIG="$docker_config" docker buildx inspect "$builder" \
  --bootstrap >/dev/null

for product in dkim2d dkim2-milter dkim2ctl; do
  repository="ghcr.io/croessner/$product"
  metadata="$work/$product.publish.json"
  DOCKER_CONFIG="$docker_config" docker buildx build \
    --builder "$builder" \
    --file "$context/build/container/Containerfile" \
    --target "$product" \
    --platform linux/amd64,linux/arm64 \
    --network none \
    --build-arg "VERSION=$version" \
    --build-arg "REVISION=$revision" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --build-arg "CREATED=$created" \
    --build-arg "DIRTY=$dirty" \
    --provenance=false \
    --sbom=false \
    --metadata-file "$metadata" \
    --tag "$repository:$version" \
    --tag "$repository:$minor" \
    --tag "$repository:$major" \
    --output "type=registry,oci-mediatypes=true,rewrite-timestamp=true" \
    "$context"
  published_digest=$(jq -er '."containerimage.digest"' "$metadata")
  jq -e '."containerimage.digest" | test("^sha256:[0-9a-f]{64}$")' \
    "$metadata" >/dev/null
  raw="$work/$product.registry-index.json"
  DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
    --raw "$repository@$published_digest" >"$raw"
  actual_digest=$(shasum -a 256 "$raw" | cut -d' ' -f1)
  test "sha256:$actual_digest" = "$published_digest"
  local_digest=$(jq -er .subject_digest \
    ".artifacts/image-evidence/$product.oci.json")
  test "$published_digest" = "$local_digest"
  for platform in linux/amd64 linux/arm64; do
    os=${platform%/*}
    architecture=${platform#*/}
    expected=$(jq -er --arg platform "$platform" \
      '.platforms[] | select(.platform == $platform) | .manifest_digest' \
      ".artifacts/image-evidence/$product.oci.json")
    jq -e --arg os "$os" --arg architecture "$architecture" \
      --arg expected "$expected" \
      '[.manifests[] |
        select(.platform.os == $os and .platform.architecture == $architecture) |
        .digest] == [$expected]' "$raw" >/dev/null
  done
  jq -e '[.manifests[] |
    select(.platform.os == "unknown" or .platform.architecture == "unknown")] |
    length == 0' "$raw" >/dev/null
  for alias in "$version" "$minor" "$major"; do
    alias_raw="$work/$product.$alias.registry-index.json"
    DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
      --raw "$repository:$alias" >"$alias_raw"
    alias_digest=$(shasum -a 256 "$alias_raw" | cut -d' ' -f1)
    test "sha256:$alias_digest" = "$published_digest"
  done
  assert_candidate
done

jq -S -n \
  --arg candidate "$(jq -er .candidate_snapshot_sha256 "$work/metadata.json")" \
  --arg version "$version" \
  --arg revision "$revision" \
  --arg dkim2d "$(jq -er '."containerimage.digest"' "$work/dkim2d.publish.json")" \
  --arg milter "$(jq -er '."containerimage.digest"' "$work/dkim2-milter.publish.json")" \
  --arg ctl "$(jq -er '."containerimage.digest"' "$work/dkim2ctl.publish.json")" \
  '{
    schema:"dkim2-container-publication-subjects-v1",
    candidate_snapshot_sha256:$candidate,
    version:$version,
    revision:$revision,
    workflow:"croessner/dkim2/.github/workflows/container-publish.yml",
    products:{
      dkim2d:{repository:"ghcr.io/croessner/dkim2d",subject_digest:$dkim2d},
      "dkim2-milter":{
        repository:"ghcr.io/croessner/dkim2-milter",
        subject_digest:$milter
      },
      dkim2ctl:{repository:"ghcr.io/croessner/dkim2ctl",subject_digest:$ctl}
    }
  }' >"$work/publication-subjects.json"
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. \
    -install "$work/publication-subjects.json" \
    -target ".artifacts/publication-subjects.json" -replace
assert_candidate
