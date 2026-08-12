#!/bin/sh
set -eu
umask 077

test "$#" -eq 0
test "${DKIM2_DEV_PUBLISH_APPROVED:-}" = true

registry=docker.roessner-net.de/mail
test "${DKIM2_DEV_REGISTRY:-$registry}" = "$registry"
test -z "$(git status --porcelain --untracked-files=all)"

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory .artifacts
work=$(mktemp -d .artifacts/.image-build-work.dev-publish.XXXXXX)
builder=
builder_active=false

# cleanup removes only invocation-owned builder and temporary state.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if test "$builder_active" = true; then
    if ! docker buildx rm "$builder" >/dev/null 2>&1; then
      status=1
    fi
  fi
  rm -rf -- "$work" || status=1
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
mkdir -m 0700 "$work/context"

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. \
    -materialize "$work/context" >"$work/metadata.json"

# assert_candidate proves repository state has not changed since materialization.
assert_candidate() {
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/buildmeta -root .. >"$work/metadata-current.json"
  cmp "$work/metadata.json" "$work/metadata-current.json"
  test -z "$(git status --porcelain --untracked-files=all)"
}

version=$(jq -er .version "$work/metadata.json")
revision=$(jq -er .revision "$work/metadata.json")
source_date_epoch=$(jq -er .source_date_epoch "$work/metadata.json")
created=$(jq -er .created "$work/metadata.json")
dirty=$(jq -er .dirty "$work/metadata.json")
test "$version" = 0.0.0-dev
test "$dirty" = clean
test "${#revision}" -eq 40
case "$revision" in *[!0-9a-f]*) exit 2 ;; esac
test "$(git rev-parse "$revision^{commit}")" = "$revision"
tag="$version-$revision"
context="$(pwd -P)/$work/context"

# Rebuild and exercise every local subject before any registry access. Direct
# script execution intentionally performs the same closed preflight as Make.
scripts/build-images.sh
scripts/inspect-images.sh check
scripts/test-image-runtime.sh
assert_candidate

subjects="$work/local-subjects.jsonl"
: >"$subjects"
for product in dkim2d dkim2-milter dkim2ctl; do
  report=".artifacts/image-evidence/$product.oci.json"
  current_version=$(GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/imageevidence -root .. -oci-version "$product")
  test "$current_version" = "$version"
  subject=$(jq -er .subject_digest "$report")
  amd64=$(jq -er \
    '.platforms[] | select(.platform == "linux/amd64") | .manifest_digest' \
    "$report")
  arm64=$(jq -er \
    '.platforms[] | select(.platform == "linux/arm64") | .manifest_digest' \
    "$report")
  jq -S -n \
    --arg product "$product" \
    --arg repository "$registry/$product" \
    --arg tag "$tag" \
    --arg subject "$subject" \
    --arg amd64 "$amd64" \
    --arg arm64 "$arm64" \
    '{
      product:$product,
      repository:$repository,
      tag:$tag,
      subject_digest:$subject,
      platforms:{"linux/amd64":$amd64,"linux/arm64":$arm64}
    }' >>"$subjects"
done
jq -e -s --arg tag "$tag" '
  length == 3 and
  map(.product) == ["dkim2d","dkim2-milter","dkim2ctl"] and
  all(.[];
    .tag == $tag and
    (.subject_digest | test("^sha256:[0-9a-f]{64}$")) and
    (.platforms | keys) == ["linux/amd64","linux/arm64"] and
    all(.platforms[]; test("^sha256:[0-9a-f]{64}$")))
' "$subjects" >/dev/null
assert_candidate

buildkit_image=$(jq -er \
  '.images[] | select(.name == "buildkit") |
   (.reference + "@sha256:" + .digest)' \
  "$context/build/container/build-inputs.json")
docker_host=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
case "$docker_host" in unix:///*) ;; *) exit 2;; esac
builder="dkim2-dev-publish-${work##*.}"
docker buildx create \
  --name "$builder" \
  --driver docker-container \
  --driver-opt "image=$buildkit_image" \
  >/dev/null
builder_active=true
docker buildx inspect "$builder" --bootstrap >/dev/null

# validate_registry_index checks one exact index and both closed platforms.
validate_registry_index() {
  raw=$1
  product=$2
  expected_subject=$(jq -er -s --arg product "$product" \
    '.[] | select(.product == $product) | .subject_digest' "$subjects")
  actual_subject=$(shasum -a 256 "$raw" | cut -d' ' -f1)
  test "sha256:$actual_subject" = "$expected_subject"
  for platform in linux/amd64 linux/arm64; do
    os=${platform%/*}
    architecture=${platform#*/}
    expected=$(jq -er -s --arg product "$product" --arg platform "$platform" \
      '.[] | select(.product == $product) | .platforms[$platform]' "$subjects")
    jq -e --arg os "$os" --arg architecture "$architecture" \
      --arg expected "$expected" \
      '[.manifests[] |
        select(.platform.os == $os and .platform.architecture == $architecture) |
        .digest] == [$expected]' "$raw" >/dev/null
  done
  jq -e '[.manifests[] |
    select(.platform.os == "unknown" or .platform.architecture == "unknown")] |
    length == 0' "$raw" >/dev/null
}

# Preflight every final tag before any registry mutation. Existing identical
# subjects are idempotent; a different subject or ambiguous lookup fails closed.
remote_states="$work/remote-states.jsonl"
: >"$remote_states"
for product in dkim2d dkim2-milter dkim2ctl; do
  repository="$registry/$product"
  raw="$work/$product.preflight-index.json"
  diagnostic="$work/$product.preflight-error"
  state=absent
  if docker buildx imagetools inspect --raw "$repository:$tag" \
    >"$raw" 2>"$diagnostic"; then
    validate_registry_index "$raw" "$product"
    state=present_identical
  else
    test -s "$diagnostic"
    test "$(wc -c <"$diagnostic")" -le 4096
    LC_ALL=C grep -Eiq '(manifest unknown|not found)' "$diagnostic"
    grep -Fq "$repository" "$diagnostic"
    grep -Fq "$tag" "$diagnostic"
  fi
  jq -S -n --arg product "$product" --arg state "$state" \
    '{product:$product,state:$state}' >>"$remote_states"
done
jq -e -s '
  length == 3 and
  map(.product) == ["dkim2d","dkim2-milter","dkim2ctl"] and
  all(.[]; .state == "absent" or .state == "present_identical")
' "$remote_states" >/dev/null
assert_candidate

for product in dkim2d dkim2-milter dkim2ctl; do
  repository="$registry/$product"
  state=$(jq -er -s --arg product "$product" \
    '.[] | select(.product == $product) | .state' "$remote_states")
  metadata="$work/$product.publish.json"
  if test "$state" = absent; then
    docker buildx build \
      --builder "$builder" \
      --file "$context/build/container/Dockerfile" \
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
      --output "type=registry,name=$repository:$tag,oci-mediatypes=true,rewrite-timestamp=true" \
      "$context"
    published_digest=$(jq -er '."containerimage.digest"' "$metadata")
    jq -e '."containerimage.digest" | test("^sha256:[0-9a-f]{64}$")' \
      "$metadata" >/dev/null
  else
    published_digest=$(jq -er -s --arg product "$product" \
      '.[] | select(.product == $product) | .subject_digest' "$subjects")
    jq -S -n --arg digest "$published_digest" \
      '{"containerimage.digest":$digest}' >"$metadata"
  fi
  local_digest=$(jq -er -s --arg product "$product" \
    '.[] | select(.product == $product) | .subject_digest' "$subjects")
  test "$published_digest" = "$local_digest"
  raw="$work/$product.registry-index.json"
  docker buildx imagetools inspect --raw \
    "$repository@$published_digest" >"$raw"
  validate_registry_index "$raw" "$product"
  tag_raw="$work/$product.registry-tag.json"
  docker buildx imagetools inspect --raw "$repository:$tag" >"$tag_raw"
  validate_registry_index "$tag_raw" "$product"
  assert_candidate
done

jq -S -n \
  --arg candidate "$(jq -er .candidate_snapshot_sha256 "$work/metadata.json")" \
  --arg version "$version" \
  --arg tag "$tag" \
  --arg revision "$revision" \
  --arg dkim2d "$(jq -er '."containerimage.digest"' "$work/dkim2d.publish.json")" \
  --arg milter "$(jq -er '."containerimage.digest"' "$work/dkim2-milter.publish.json")" \
  --arg ctl "$(jq -er '."containerimage.digest"' "$work/dkim2ctl.publish.json")" \
  '{
    schema:"dkim2-internal-dev-publication-subjects-v1",
    registry:"docker.roessner-net.de/mail",
    candidate_snapshot_sha256:$candidate,
    version:$version,
    tag:$tag,
    revision:$revision,
    products:{
      dkim2d:{repository:"docker.roessner-net.de/mail/dkim2d",subject_digest:$dkim2d},
      "dkim2-milter":{
        repository:"docker.roessner-net.de/mail/dkim2-milter",
        subject_digest:$milter
      },
      dkim2ctl:{repository:"docker.roessner-net.de/mail/dkim2ctl",subject_digest:$ctl}
    }
  }' >"$work/dev-publication-subjects.json"
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. \
    -install "$work/dev-publication-subjects.json" \
    -target ".artifacts/dev-publication-subjects.json" -replace
assert_candidate
