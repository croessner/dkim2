#!/bin/sh
set -eu
umask 077

test "$#" -eq 0
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root"

build_marker=privacy-build-context-92d7e4a1
label_marker=privacy-oci-label-41bc8e73
scanner_marker=privacy-scanner-diagnostic-c65a90f2
output_marker=privacy-container-output-7f3c9a2d
run_id=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
case "$run_id" in
  ????????????????) ;;
  *) exit 2 ;;
esac
prefix=dkim2-privacy-"$run_id"
work=$(mktemp -d .artifacts/.privacy-evidence-work.XXXXXX)
scanner_work=$(mktemp -d .artifacts/.image-evidence-work.XXXXXX)
images=
containers=
docker_config=
builder=
builder_active=false

# cleanup removes only invocation-owned containers, tags, and private work.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if test "$builder_active" = true; then
    if ! DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" \
      docker buildx rm "$builder" >/dev/null 2>&1; then
      status=1
    fi
  fi
  if test -n "$docker_config"; then
    rm -rf -- "$docker_config" || status=1
  fi
  for entry in $containers; do
    name=${entry%%,*}
    identity=${entry#*,}
    if docker container inspect "$name" >/dev/null 2>&1; then
      test "$(docker container inspect "$name" --format '{{.Id}}')" = "$identity" ||
        status=1
      docker container rm -f "$name" >/dev/null 2>&1 || status=1
    fi
  done
  for entry in $images; do
    tag=${entry%%,*}
    identity=${entry#*,}
    if docker image inspect "$tag" >/dev/null 2>&1; then
      test "$(docker image inspect "$tag" --format '{{.Id}}')" = "$identity" ||
        status=1
      docker image rm "$tag" >/dev/null 2>&1 || status=1
    fi
  done
  rm -rf -- "$work" "$scanner_work" || status=1
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

for directory in .artifacts .artifacts/image-evidence .artifacts/postfix-deployment; do
  test -d "$directory"
  test ! -L "$directory"
done
candidate=$(GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/candidateid -root ..)
revision=$(git rev-parse HEAD)

# verify_candidate_evidence rejects absent, stale, or mixed prerequisite evidence.
verify_candidate_evidence() {
  first_report=.artifacts/postfix-deployment/run-1/report.json
  second_report=.artifacts/postfix-deployment/run-2/report.json
  for report in "$first_report" "$second_report"; do
    test -f "$report"
    test ! -L "$report"
    jq -e \
      --arg candidate "$candidate" \
      --arg revision "$revision" \
      '.schema == "dkim2.postfix-deployment-report.v1" and
       .state == "pass" and
       .candidate_snapshot_sha256 == $candidate and
       .source_revision == $revision' \
      "$report" >/dev/null
  done
  cmp "$first_report" "$second_report"

  for report in \
    .artifacts/image-evidence/runtime-policy.json \
    .artifacts/image-evidence/trivy-database.json \
    .artifacts/image-evidence/dkim2d.amd64.sbom-binding.json \
    .artifacts/image-evidence/dkim2d.arm64.sbom-binding.json \
    .artifacts/image-evidence/dkim2d.amd64.trivy-binding.json \
    .artifacts/image-evidence/dkim2d.arm64.trivy-binding.json \
    .artifacts/image-evidence/dkim2-milter.amd64.sbom-binding.json \
    .artifacts/image-evidence/dkim2-milter.arm64.sbom-binding.json \
    .artifacts/image-evidence/dkim2-milter.amd64.trivy-binding.json \
    .artifacts/image-evidence/dkim2-milter.arm64.trivy-binding.json \
    .artifacts/image-evidence/dkim2ctl.amd64.sbom-binding.json \
    .artifacts/image-evidence/dkim2ctl.arm64.sbom-binding.json \
    .artifacts/image-evidence/dkim2ctl.amd64.trivy-binding.json \
    .artifacts/image-evidence/dkim2ctl.arm64.trivy-binding.json; do
    test -f "$report"
    test ! -L "$report"
    jq -e --arg candidate "$candidate" \
      '.candidate_snapshot_sha256 == $candidate' "$report" >/dev/null
  done
  for product in dkim2d dkim2-milter dkim2ctl; do
    report=.artifacts/image-evidence/"$product".provenance.json
    test -f "$report"
    test ! -L "$report"
    jq -e \
      --arg candidate "$candidate" \
      --arg revision "$revision" \
      '.predicate.buildDefinition.internalParameters.candidate_snapshot_sha256 ==
         $candidate and
       any(.predicate.buildDefinition.resolvedDependencies[];
         .uri == "git+https://github.com/croessner/dkim2" and
         .digest.gitCommit == $revision)' \
      "$report" >/dev/null
  done
}

verify_candidate_evidence
docker_config=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-privacy-docker.XXXXXX")
chmod 0700 "$docker_config"
printf '%s\n' '{"auths":{}}' >"$docker_config/config.json"
docker_host=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
case "$docker_host" in unix:///*) ;; *) exit 2;; esac
buildkit_image=$(jq -er \
  '.images[] | select(.name == "buildkit") |
   (.reference + "@sha256:" + .digest)' \
  build/container/build-inputs.json)
builder="$prefix-builder"
DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" docker buildx create \
  --name "$builder" \
  --driver docker-container \
  --driver-opt "image=$buildkit_image" >/dev/null
builder_active=true
DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" \
  docker buildx inspect "$builder" --bootstrap >/dev/null

printf '%s\n' "privacy evidence: build context"
printf '%s\n' "$build_marker" >"$work/build-context-seed"
grep -Fq "$build_marker" "$work/build-context-seed"
mkdir -m 0700 "$work/context"
if ! timeout -k 5 60 env \
  DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" \
  docker buildx build \
  --builder "$builder" \
  --file build/container/Containerfile \
  --target context-audit \
  --output "type=local,dest=$work/context" \
  . >"$work/context.stdout" 2>"$work/context.stderr"; then
  exit 1
fi
! grep -aFRq -- "$build_marker" \
  "$work/context" "$work/context.stdout" "$work/context.stderr"

printf '%s\n' "privacy evidence: OCI metadata rejection"
printf '%s\n' "$label_marker" >"$work/label-seed"
grep -Fq "$label_marker" "$work/label-seed"
: >"$work/label.stdout"
: >"$work/label.stderr"
for architecture in amd64 arm64; do
  for target in dkim2d dkim2-milter dkim2ctl; do
    set +e
    timeout -k 5 60 env \
      DOCKER_CONFIG="$docker_config" DOCKER_HOST="$docker_host" \
      docker buildx build \
      --builder "$builder" \
      --file build/container/Containerfile \
      --target "$target" \
      --platform "linux/$architecture" \
      --network none \
      --build-arg "VERSION=$label_marker" \
      --build-arg REVISION=0000000000000000000000000000000000000000 \
      --build-arg SOURCE_DATE_EPOCH=0 \
      --build-arg CREATED=1970-01-01T00:00:00Z \
      --build-arg DIRTY=clean \
      --output type=cacheonly \
      . >>"$work/label.stdout" 2>>"$work/label.stderr"
    label_status=$?
    set -e
    case "$label_status" in
      0)
        printf '%s\n' "privacy evidence failed: hostile OCI metadata accepted" >&2
        exit 1
        ;;
      124|137)
        printf '%s\n' "privacy evidence failed: OCI metadata rejection timed out" >&2
        exit 1
        ;;
    esac
  done
done
if grep -aFRq -- "$label_marker" "$work/label.stdout" "$work/label.stderr"; then
  printf '%s\n' "privacy evidence failed: OCI metadata diagnostic disclosure" >&2
  exit 1
fi

printf '%s\n' "privacy evidence: scanner diagnostic"
mkdir -m 0700 "$scanner_work/input"
printf '{"%s":' "$scanner_marker" >"$scanner_work/input/index.json"
grep -Fq "$scanner_marker" "$scanner_work/input/index.json"
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools build -o "../$work/dbguard" ./cmd/dbguard
set +e
timeout -k 5 60 "$work/dbguard" \
  -root . \
  -input "$scanner_work/input" \
  -output "$scanner_work/output.json" \
  -scan-time "$(jq -er .scan_time .artifacts/image-evidence/trivy-database.json)" \
  >"$work/scanner.stdout" 2>"$work/scanner.stderr"
scanner_status=$?
set -e
test "$scanner_status" -ne 0
test "$scanner_status" -ne 124
test ! -s "$work/scanner.stdout"
test "$(cat "$work/scanner.stderr")" = "scanner database rejected"
if test -e "$scanner_work/output.json"; then
  test -f "$scanner_work/output.json"
  test ! -L "$scanner_work/output.json"
  ! grep -aFq -- "$scanner_marker" "$scanner_work/output.json"
fi
! grep -aFRq -- "$scanner_marker" \
  "$work/scanner.stdout" "$work/scanner.stderr"

architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in
  x86_64|amd64) platform=linux/amd64 ;;
  aarch64|arm64) platform=linux/arm64 ;;
  *) exit 2 ;;
esac

printf '%s\n' "privacy evidence: container output"
printf '%s\n' "$output_marker" >"$work/container-output-seed"
grep -Fq "$output_marker" "$work/container-output-seed"
for product in dkim2d dkim2-milter dkim2ctl; do
  subject=$(jq -er --arg platform "$platform" \
    '.platforms[] | select(.platform == $platform) | .manifest_digest' \
    ".artifacts/image-evidence/$product.oci.json")
  tag="$prefix-$product:local"
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/ocipolicy \
      -archive "../.artifacts/$product.oci.tar" \
      -product "$product" \
      -export-platform "$platform" \
      -expected-manifest "$subject" \
      -docker-tag "$tag" >"$work/$product.docker.tar"
  docker load -i "$work/$product.docker.tar" >/dev/null
  image_id=$(docker image inspect "$tag" --format '{{.Id}}')
  images="$images $tag,$image_id"
  container="$prefix-$product"
  container_id=$(docker create \
    --name "$container" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 256m \
    --cpus 1 \
    --user 2000:2000 \
    "$tag" "$output_marker")
  containers="$containers $container,$container_id"
  set +e
  timeout -k 2 10 docker start -a "$container" \
    >"$work/$product.stdout" 2>"$work/$product.stderr"
  product_status=$?
  set -e
  case "$product_status" in
    0)
      printf '%s\n' "privacy evidence failed: $product hostile argument accepted" >&2
      exit 1
      ;;
    124|137)
      printf '%s\n' "privacy evidence failed: $product output check timed out" >&2
      exit 1
      ;;
  esac
  if test "$(docker inspect "$container" --format '{{.State.ExitCode}}')" -eq 0; then
    printf '%s\n' "privacy evidence failed: $product exited successfully" >&2
    exit 1
  fi
  if test "$(wc -c <"$work/$product.stdout" | tr -d ' ')" -gt 8192 ||
    test "$(wc -c <"$work/$product.stderr" | tr -d ' ')" -gt 8192; then
    printf '%s\n' "privacy evidence failed: $product output exceeded bounds" >&2
    exit 1
  fi
  if grep -aFRq -- "$output_marker" \
    "$work/$product.stdout" "$work/$product.stderr"; then
    printf '%s\n' "privacy evidence failed: $product disclosed hostile output" >&2
    exit 1
  fi
done

printf '%s\n' "privacy evidence: aggregate surfaces"
for marker in \
  "$build_marker" \
  "$label_marker" \
  "$scanner_marker" \
  "$output_marker" \
  privacy-7f3c9a2d \
  privacy-tenant-7f3c9a2d \
  privacy-origin-key-7f3c \
  privacy-transit-key-7f3c \
  privacy-origin-profile-7f3c \
  privacy-transit-profile-7f3c \
  privacy-message-7f3c9a2d \
  privacy-envelope-7f3c \
  privacy-recipient-7f3c \
  privacy-cap-inbound-process-0001 \
  privacy-cap-origin-process-00001 \
  privacy-cap-origin-signing-00001 \
  privacy-cap-transit-process-0000 \
  privacy-cap-transit-revision-000; do
  ! grep -aFRq -- "$marker" \
    .artifacts/product-binaries \
    .artifacts/image-evidence \
    .artifacts/postfix-deployment/run-1/report.json \
    .artifacts/postfix-deployment/run-2/report.json \
    "$work/context" \
    "$work/context.stdout" "$work/context.stderr" \
    "$work/label.stdout" "$work/label.stderr" \
    "$work/scanner.stdout" "$work/scanner.stderr"
done

grep -aFRq --include='*.eml' -- privacy-message-7f3c9a2d \
  .artifacts/postfix-deployment/run-1
grep -aFRq --include='*.eml' -- privacy-7f3c9a2d \
  .artifacts/postfix-deployment/run-2

printf '%s\n' "privacy evidence: report"
jq -S -n \
  --arg candidate "$candidate" \
  --arg revision "$revision" \
  --arg platform "$platform" \
  '{
    schema:"dkim2-deployment-privacy-evidence-v1",
    candidate_snapshot_sha256:$candidate,
    source_revision:$revision,
    platform:$platform,
    state:"pass",
    cases:[
      "build_context_seed_excluded",
      "oci_label_build_arg_seed_rejected",
      "scanner_failure_diagnostic_seed_redacted",
      "container_stdout_stderr_seed_redacted",
      "protected_and_mail_seeds_absent_from_product_surfaces",
      "mail_seeds_present_only_in_authorized_synthetic_messages"
    ]
  }' >"$work/report.json"
jq -e \
  --arg candidate "$candidate" \
  --arg revision "$revision" \
  --arg platform "$platform" \
  '. == {
    schema:"dkim2-deployment-privacy-evidence-v1",
    candidate_snapshot_sha256:$candidate,
    source_revision:$revision,
    platform:$platform,
    state:"pass",
    cases:[
      "build_context_seed_excluded",
      "oci_label_build_arg_seed_rejected",
      "scanner_failure_diagnostic_seed_redacted",
      "container_stdout_stderr_seed_redacted",
      "protected_and_mail_seeds_absent_from_product_surfaces",
      "mail_seeds_present_only_in_authorized_synthetic_messages"
    ]
  }' "$work/report.json" >/dev/null
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. \
    -directory .artifacts/privacy-evidence
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. \
    -install "$work/report.json" \
    -target .artifacts/privacy-evidence/report.json \
    -replace
