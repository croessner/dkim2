#!/bin/sh
set -eu

project=dkim2-postfix-qualification
compose_file=contrib/qualification/postfix-milter/compose.yaml

# lane selects which qualification fragments one pass produces. "core" is the
# signing, verification, and Postfix delivery-status evidence and is the
# default gate. "propagation" is the delivery-status propagation evidence; it
# is opt-in because it drives the deferred LMTP transport through real retry
# and lease windows and therefore takes several minutes; "all" is both.
lane=core
while test "$#" -gt 0; do
  case $1 in
    --lane)
      test "$#" -ge 2 || exit 2
      lane=$2
      shift 2
      ;;
    --lane=*)
      lane=${1#--lane=}
      shift
      ;;
    *) break ;;
  esac
done
case $lane in
  all|core|propagation) ;;
  *) exit 2 ;;
esac

output_root=${1:-.artifacts/postfix-qualification}

validate_output_root() {
  case "$output_root" in
    .artifacts/*/*) exit 2 ;;
    .artifacts/*) ;;
    *) exit 2 ;;
  esac
  output_leaf=${output_root#".artifacts/"}
  case "$output_leaf" in
    ""|"."|".."|.*|-*|*[!a-z0-9._-]*) exit 2 ;;
  esac

  if test -e .artifacts; then
    test -d .artifacts
    test ! -L .artifacts
  else
    mkdir -m 0700 .artifacts
  fi
  if test -e "$output_root"; then
    test -d "$output_root"
    test ! -L "$output_root"
  else
    mkdir -m 0700 "$output_root"
  fi
}

cleanup_project() {
  docker compose --project-name "$project" --file "$compose_file" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
}

cleanup() {
  cleanup_project
  docker image rm \
    dkim2-postfix-qualification-build:verified \
    dkim2-postfix-qualification-daemon:verified \
    dkim2-postfix-qualification-postfix:verified >/dev/null 2>&1 || true
}

trap cleanup EXIT HUP INT TERM
cleanup
validate_output_root

ensure_image() {
  expected_digest=$1
  expected_id=$2
  expected_platform=$3
  if ! docker image inspect "$expected_digest" >/dev/null 2>&1; then
    docker pull "$expected_digest" >/dev/null
  fi
  actual_id=$(docker image inspect "$expected_digest" --format '{{.Id}}')
  actual_digests=$(docker image inspect "$expected_digest" --format '{{json .RepoDigests}}')
  actual_platform=$(docker image inspect "$expected_digest" --format '{{.Os}}/{{.Architecture}}')
  test "$actual_id" = "$expected_id"
  test "$actual_platform" = "$expected_platform"
  case "$actual_digests" in
    *"$expected_digest"*) ;;
    *) exit 1 ;;
  esac
}

ensure_image \
  golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6 \
  sha256:b0bb43a2dcec5fbd07bedbe887849d53b2ac412c7876dd0bfa4c4e07ae80fe1c \
  linux/amd64
ensure_image \
  debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e \
  sha256:49f0bb6384d2a743d631148b80de7644055e0f7fc9fe3f493872dbddb77a747d \
  linux/amd64
ensure_image \
  chrroessner/postfix@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c \
  sha256:d4388e96b70baefcf074555e1f5a1f76b91cfcbb77b16e61bde03449c641d60c \
  linux/amd64

docker tag \
  golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6 \
  dkim2-postfix-qualification-build:verified
docker tag \
  debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e \
  dkim2-postfix-qualification-daemon:verified
docker tag \
  chrroessner/postfix@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c \
  dkim2-postfix-qualification-postfix:verified

assert_project_removed() {
  test -z "$(
    docker ps --all --quiet \
      --filter "label=com.docker.compose.project=$project"
  )"
  test -z "$(
    docker volume ls --quiet \
      --filter "label=com.docker.compose.project=$project"
  )"
}

run_bounded_exec() {
  timeout_seconds=$1
  service=$2
  output=$3
  shift 3
  container=$(
    docker compose --project-name "$project" --file "$compose_file" \
      ps --quiet "$service"
  )
  test -n "$container"

  pending=
  if test "$output" = /dev/null; then
    docker exec "$container" "$@" >/dev/null 2>&1 &
  else
    pending="$output.pending"
    rm -f "$pending"
    docker exec "$container" "$@" >"$pending" &
  fi
  command_pid=$!
  (
    sleep "$timeout_seconds"
    kill -TERM "$command_pid" >/dev/null 2>&1 || true
    sleep 2
    kill -KILL "$command_pid" >/dev/null 2>&1 || true
  ) &
  watchdog_pid=$!

  if wait "$command_pid"; then
    status=0
  else
    status=$?
  fi
  kill -TERM "$watchdog_pid" >/dev/null 2>&1 || true
  wait "$watchdog_pid" 2>/dev/null || true
  if test "$status" -ne 0; then
    test -z "$pending" || rm -f "$pending"
    return "$status"
  fi
  if test -n "$pending"; then
    mv "$pending" "$output"
  fi
}

prove_injected_failure_cleanup() {
  docker compose --project-name "$project" --file "$compose_file" \
    up --build --detach --wait
  if run_bounded_exec \
    10 stack /dev/null /usr/local/bin/qualify injected-failure; then
    exit 1
  fi
  cleanup_project
  assert_project_removed
}

prove_injected_failure_cleanup

# run_once executes one isolated qualification pass and records its bounded evidence.
run_once() {
  run_number=$1
  run_root="$output_root/run-$run_number"
  rm -rf "$run_root"
  mkdir -p "$run_root"

  docker compose --project-name "$project" --file "$compose_file" \
    up --build --detach --wait

  run_bounded_exec 10 stack "$run_root/identity.json" \
    /usr/local/bin/qualify identity
  run_bounded_exec 10 daemon "$run_root/daemon-identity.json" \
    /usr/local/bin/qualify daemon-identity
  jq -e '
    keys == ["executables", "postfix_version", "schema"] and
    .schema == "dkim2.postfix-qualification-identity.v1" and
    .postfix_version == "3.11.6" and
    (.executables | keys == ["dkim2-dsn-propagator", "dkim2-milter", "qualify"])
  ' "$run_root/identity.json" >/dev/null
  jq -e '
    keys == ["executables", "schema"] and
    .schema == "dkim2.postfix-qualification-identity.v1" and
    (.executables | keys == ["dkim2d"])
  ' "$run_root/daemon-identity.json" >/dev/null

  fragment_files=""
  if test "$lane" != propagation; then
    run_bounded_exec 30 stack "$run_root/success.json" \
      /usr/local/bin/qualify success
    fragment_files="$fragment_files $run_root/success.json"
  fi
  if test "$lane" != core; then
    run_bounded_exec 240 stack "$run_root/propagation.json" \
      /usr/local/bin/qualify propagation
    fragment_files="$fragment_files $run_root/propagation.json"
  fi
  if test "$lane" != propagation; then
    docker compose --project-name "$project" --file "$compose_file" \
      pause daemon
    run_bounded_exec 25 stack "$run_root/daemon-failure.json" \
      /usr/local/bin/qualify daemon-failure
    docker compose --project-name "$project" --file "$compose_file" \
      unpause daemon

    run_bounded_exec 15 stack /dev/null \
      /usr/local/bin/qualify stop-origin-milter
    run_bounded_exec 20 stack "$run_root/milter-failure.json" \
      /usr/local/bin/qualify milter-failure
    fragment_files="$fragment_files $run_root/daemon-failure.json"
    fragment_files="$fragment_files $run_root/milter-failure.json"
  fi
  # shellcheck disable=SC2086
  fragments=$(jq -S -s '.' $fragment_files)

  candidate=$(
    GOCACHE=/tmp/dkim2-postfix-qualification-gocache \
      go -C tools run ./cmd/conformance -root .. snapshot |
      jq -er '
        if (
          keys == ["base_revision", "entries", "schema", "sha256"] and
          .schema == "dkim2.candidate-snapshot.v1" and
          (.sha256 | test("^[0-9a-f]{64}$"))
        ) then .sha256 else error("snapshot") end
      '
  )
  test "${#candidate}" -eq 64
  base_revision=$(git rev-parse HEAD)
  test "${#base_revision}" -eq 40
  manifest=$(shasum -a 256 testdata/conformance/manifest.json | cut -d' ' -f1)
  producer=$(shasum -a 256 "$0" | cut -d' ' -f1)
  test "${#manifest}" -eq 64
  test "${#producer}" -eq 64

  jq -S -n \
    --arg candidate "$candidate" \
    --arg base_revision "$base_revision" \
    --arg manifest "$manifest" \
    --arg producer "$producer" \
    --arg postfix_image "chrroessner/postfix@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c" \
    --arg golang_image "golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6" \
    --arg debian_image "debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e" \
    --argjson fragments "$fragments" \
    --arg lane "$lane" \
    --slurpfile identity "$run_root/identity.json" \
    --slurpfile daemon_identity "$run_root/daemon-identity.json" \
    '{
      schema: "dkim2.postfix-qualification-report.v1",
      lane: $lane,
      message_draft: "draft-ietf-dkim-dkim2-spec-06",
      dns_draft: "draft-chuang-dkim2-dns-04",
      base_revision: $base_revision,
      candidate_snapshot_sha256: $candidate,
      manifest_sha256: $manifest,
      profile: "postfix",
      platform: "linux",
      producer_sha256: $producer,
      state: "pass",
      image_identities: {
        debian: $debian_image,
        golang: $golang_image,
        postfix: $postfix_image
      },
      runtime_identity: {
        schema: $identity[0].schema,
        postfix_version: $identity[0].postfix_version,
        executables: ($identity[0].executables + $daemon_identity[0].executables)
      },
      fragments: $fragments,
      topology: {
        compose_host_ports: 0,
        daemon_http: "canonical_loopback_only",
        milter_transport: "owned_unix_sockets_only",
        postfix_protocol: 6,
        postfix_default_action: "tempfail",
        milter_connect_timeout: "2s",
        milter_command_timeout: "5s",
        milter_content_timeout: "5s",
        propagation_transport: "lmtp_owned_unix_socket_only",
        propagation_recipient_limit: 1,
        propagation_reinjection: "milter_free_loopback_listener"
      },
      cleanup: "project_scoped_pending"
    }' >"$run_root/report.pending.json"

  cleanup_project
  assert_project_removed
  jq -S '.cleanup = "project_scoped_pass"' \
    "$run_root/report.pending.json" >"$run_root/report.json"
  rm "$run_root/report.pending.json"
}

run_once 1
run_once 2

cmp "$output_root/run-1/report.json" "$output_root/run-2/report.json"
shasum -a 256 "$output_root/run-1/report.json" |
  cut -d' ' -f1 >"$output_root/report.sha256"
