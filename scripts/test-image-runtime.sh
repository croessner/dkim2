#!/bin/sh
set -eu
umask 077

architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in
  x86_64|amd64) platform=linux/amd64 ;;
  aarch64|arm64) platform=linux/arm64 ;;
  *) exit 2 ;;
esac
metadata=$(GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root ..)
candidate=$(printf '%s\n' "$metadata" | jq -er .candidate_snapshot_sha256)
version=$(printf '%s\n' "$metadata" | jq -er .version)
run_id=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
case "$run_id" in
  ????????) ;;
  ????????????????) ;;
  *) exit 2 ;;
esac
ownership_label="com.croessner.dkim2.runtime-run=$run_id"
project_label=com.croessner.dkim2.project=runtime-test
prefix="dkim2-image-runtime-$run_id"
helper_image=chrroessner/postfix:3.11.6-r2@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c
containers=
images=
volumes=
work=
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  for record in $containers; do
    container=${record%%,*}
    expected_id=${record#*,}
    if ! docker inspect "$container" >"$work/inspect.json" 2>/dev/null ||
      ! GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
        go -C tools run ./cmd/containerownership \
          -kind container -identity "$expected_id" -run "$run_id" \
          <"$work/inspect.json"; then
      printf '%s\n' 'runtime container ownership lost' >&2
      status=1
      continue
    fi
    if ! docker rm -f "$container" >/dev/null 2>&1; then
      printf '%s\n' 'runtime container cleanup failed' >&2
      status=1
    fi
  done
  for record in $volumes; do
    volume=${record%%,*}
    expected_name=${record#*,}
    if ! docker volume inspect "$volume" >"$work/inspect.json" 2>/dev/null ||
      ! GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
        go -C tools run ./cmd/containerownership \
          -kind volume -identity "$expected_name" -run "$run_id" \
          <"$work/inspect.json"; then
      printf '%s\n' 'runtime volume ownership lost' >&2
      status=1
      continue
    fi
    if ! docker volume rm "$volume" >/dev/null 2>&1; then
      printf '%s\n' 'runtime volume cleanup failed' >&2
      status=1
    fi
  done
  for record in $images; do
    image=${record%%,*}
    expected_id=${record#*,}
    if ! docker image inspect "$image" >"$work/inspect.json" 2>/dev/null ||
      ! GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
        go -C tools run ./cmd/containerownership \
          -kind image -identity "$expected_id" -source-tag "$image" \
          <"$work/inspect.json"; then
      printf '%s\n' 'runtime image ownership lost' >&2
      status=1
      continue
    fi
    if ! docker image rm "$image" >/dev/null 2>&1; then
      printf '%s\n' 'runtime image cleanup failed' >&2
      status=1
    fi
  done
  if test -n "$work" && ! rm -rf -- "$work"; then
    printf '%s\n' 'runtime evidence workspace cleanup failed' >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory .artifacts/image-evidence
work=$(mktemp -d .artifacts/.image-runtime-work.XXXXXX)
entries="$work/entries.jsonl"
: >"$entries"

for product in dkim2d dkim2-milter dkim2ctl dkim2-dsn-propagator; do
  image="$prefix-$product:local"
  if docker image inspect "$image" >/dev/null 2>&1; then
    exit 1
  fi
  report=".artifacts/image-evidence/$product.oci.json"
  subject=$(jq -er --arg platform "$platform" \
    '.platforms[] | select(.platform == $platform) | .manifest_digest' \
    "$report")
  other_subject=$(jq -er --arg platform "$platform" \
    '.platforms[] | select(.platform != $platform) | .manifest_digest' \
    "$report")
  config_digest=$(jq -er --arg platform "$platform" \
    '.platforms[] | select(.platform == $platform) | .config_digest' \
    "$report")
  if GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/ocipolicy \
      -archive "../.artifacts/$product.oci.tar" \
      -product "$product" \
      -export-platform "$platform" \
      -expected-manifest "$other_subject" \
      -docker-tag "$image" >"$work/$product.wrong-platform.tar" 2>/dev/null; then
    exit 1
  fi
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/ocipolicy \
      -archive "../.artifacts/$product.oci.tar" \
      -product "$product" \
      -export-platform "$platform" \
      -expected-manifest "$subject" \
      -docker-tag "$image" >"$work/$product.docker.tar"
  docker load -i "$work/$product.docker.tar" >/dev/null
  image_id=$(docker image inspect --format '{{.Id}}' "$image")
  test "$image_id" = "$config_digest"
  images="$images $image,$image_id"
  docker image inspect "$image" --format '{{json .Config}}' |
    jq -e --arg product "$product" '
      .User == "2000:2000" and
      .Entrypoint == [("/usr/local/bin/" + $product)] and
      (.Cmd == null or .Cmd == []) and
      (.ExposedPorts == null) and
      (if $product == "dkim2d"
       then .Healthcheck.Test == ["CMD","/usr/local/bin/dkim2d","probe"]
       else .Healthcheck == null
       end)
    ' >/dev/null
  container="$prefix-$product-version"
  if docker container inspect "$container" >/dev/null 2>&1; then
    exit 1
  fi
  container_id=$(docker create \
    --name "$container" \
    --label "$ownership_label" \
    --label "$project_label" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 256m \
    --cpus 1 \
    --ulimit nofile=1024:1024 \
    --user 2000:2000 \
    "$image" --version)
  containers="$containers $container,$container_id"
  test "$(docker inspect --format "{{index .Config.Labels \"com.croessner.dkim2.runtime-run\"}}" "$container")" = "$run_id"
  docker image inspect "$image" >"$work/$product.inspect.json"
  docker export "$container" >"$work/$product.export.tar"
  if tar -tf "$work/$product.export.tar" |
    grep -Eq '(^|/)(validated|bin/(ash|busybox))$'; then
    exit 1
  fi
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/ocipolicy \
      -archive "../.artifacts/$product.oci.tar" \
      -product "$product" \
      -export-platform "$platform" \
      -expected-manifest "$subject" \
      -verify-inspect "$work/$product.inspect.json" \
      -verify-export "$work/$product.export.tar" >/dev/null
  docker inspect "$container" |
    jq -e '.[0] |
      .Config.User == "2000:2000" and
      .HostConfig.ReadonlyRootfs == true and
      .HostConfig.CapDrop == ["ALL"] and
      (.HostConfig.SecurityOpt | index("no-new-privileges")) != null and
      .HostConfig.Privileged == false and
      .HostConfig.PidsLimit == 64
    ' >/dev/null
  test "$(docker start -a "$container")" = "$product $version"
  test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" -eq 0
  if docker run --rm --read-only --cap-drop ALL \
    --security-opt no-new-privileges \
    --entrypoint /bin/sh "$image" >/dev/null 2>&1; then
    exit 1
  fi
  jq -S -n --arg product "$product" --arg platform "$platform" --arg subject "$subject" \
    '{product:$product,platform:$platform,subject_digest:$subject,user:"2000:2000",read_only:true,cap_drop:["ALL"],no_new_privileges:true}' \
    >>"$entries"
done

daemon_volume="$prefix-daemon-state"
milter_volume="$prefix-milter-state"
socket_volume="$prefix-sockets"
for volume in "$daemon_volume" "$milter_volume" "$socket_volume"; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    exit 1
  fi
  volume_name=$(docker volume create --label "$ownership_label" --label "$project_label" "$volume")
  volumes="$volumes $volume,$volume_name"
  test "$(docker volume inspect --format "{{index .Labels \"com.croessner.dkim2.runtime-run\"}}" "$volume")" = "$run_id"
done

bootstrap="$prefix-bootstrap"
if docker container inspect "$bootstrap" >/dev/null 2>&1; then
  exit 1
fi
bootstrap_id=$(docker create \
  --name "$bootstrap" \
  --label "$ownership_label" \
  --label "$project_label" \
  --network none \
  --cap-drop ALL \
  --cap-add CHOWN \
  --security-opt no-new-privileges \
  --mount "type=volume,source=$daemon_volume,target=/state" \
  --mount "type=volume,source=$milter_volume,target=/milter" \
  --mount "type=volume,source=$socket_volume,target=/sockets" \
  --mount "type=bind,source=$PWD/deployments/postfix-compose/testdata/runtime,target=/input,readonly" \
  --entrypoint /bin/sh \
  "$helper_image" -ceu '
    umask 077
    generation=/state/0123456789abcdef0123456789abcdef
    mkdir -p "$generation" /milter/protected
    dd if=/dev/urandom of="$generation/capability" bs=32 count=1 status=none
    cp "$generation/capability" /milter/protected/capability
    cp /input/dkim2d.yaml /state/dkim2d.yaml
    cp /input/milter.yaml /milter/milter.yaml
    chmod 0500 "$generation" /milter/protected
    chmod 0600 "$generation/capability" /milter/protected/capability /state/dkim2d.yaml /milter/milter.yaml
    chmod 0750 /sockets
    chown -R 2000:2000 /state /milter
    chown 2000:103 /sockets
  ')
containers="$containers $bootstrap,$bootstrap_id"
test "$(docker inspect --format "{{index .Config.Labels \"com.croessner.dkim2.runtime-run\"}}" "$bootstrap")" = "$run_id"
docker start -a "$bootstrap" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$bootstrap")" -eq 0

daemon="$prefix-daemon"
daemon_id=$(docker create \
  --name "$daemon" \
  --label "$ownership_label" \
  --label "$project_label" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 256m \
  --cpus 1 \
  --ulimit nofile=1024:1024 \
  --user 2000:2000 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=2000 \
  --mount "type=volume,source=$daemon_volume,target=/state,readonly" \
  "$prefix-dkim2d:local" serve --config /state/dkim2d.yaml)
containers="$containers $daemon,$daemon_id"
docker start "$daemon" >/dev/null
attempt=0
until test "$(docker inspect --format '{{.State.Health.Status}}' "$daemon")" = healthy; do
  attempt=$((attempt + 1))
  test "$attempt" -le 30
  sleep 1
done

milter="$prefix-milter"
milter_id=$(docker create \
  --name "$milter" \
  --label "$ownership_label" \
  --label "$project_label" \
  --network "container:$daemon" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 256m \
  --cpus 1 \
  --ulimit nofile=1024:1024 \
  --user 2000:103 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=103 \
  --mount "type=volume,source=$milter_volume,target=/etc/dkim2-milter,readonly" \
  --mount "type=volume,source=$socket_volume,target=/run/dkim2" \
  "$prefix-dkim2-milter:local" serve --config /etc/dkim2-milter/milter.yaml)
containers="$containers $milter,$milter_id"
docker start "$milter" >/dev/null
attempt=0
until docker exec "$milter" /usr/local/bin/dkim2-milter probe \
  --config /etc/dkim2-milter/milter.yaml >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if test "$attempt" -gt 20; then
    docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$milter" >&2
    docker logs "$milter" >&2
    exit 1
  fi
  sleep 1
done

socket_state() {
  suffix=$1
  expectation=$2
  output=$3
  inspector="$prefix-socket-$suffix"
  if test "$expectation" = present; then
    command='stat -c "%u:%g:%a:%i" /sockets/runtime.sock'
  else
    command='test ! -e /sockets/runtime.sock'
  fi
  inspector_id=$(docker create \
    --name "$inspector" \
    --label "$ownership_label" \
    --label "$project_label" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 2000:103 \
    --mount "type=volume,source=$socket_volume,target=/sockets,readonly" \
    --entrypoint /bin/sh \
    "$helper_image" -ceu "$command")
  containers="$containers $inspector,$inspector_id"
  docker start -a "$inspector" >"$output"
}

socket_state first present "$work/socket-first"
first_socket=$(cat "$work/socket-first")
case "$first_socket" in 2000:103:660:[0-9]*) ;; *) exit 1;; esac
if docker exec "$milter" /usr/local/bin/dkim2-milter probe \
  --config /etc/passwd >/dev/null 2>&1; then
  exit 1
fi

docker stop --time 10 "$milter" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$milter")" -eq 0
socket_state after-term absent "$work/socket-after-term"
test ! -s "$work/socket-after-term"
docker start "$milter" >/dev/null
attempt=0
until docker exec "$milter" /usr/local/bin/dkim2-milter probe \
  --config /etc/dkim2-milter/milter.yaml >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if test "$attempt" -gt 20; then
    docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$milter" >&2
    docker logs "$milter" >&2
    exit 1
  fi
  sleep 1
done
socket_state second present "$work/socket-second"
second_socket=$(cat "$work/socket-second")
case "$second_socket" in 2000:103:660:[0-9]*) ;; *) exit 1;; esac
docker kill --signal INT "$milter" >/dev/null
docker wait "$milter" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$milter")" -eq 0
socket_state after-int absent "$work/socket-after-int"
test ! -s "$work/socket-after-int"

docker restart "$daemon" >/dev/null
attempt=0
until test "$(docker inspect --format '{{.State.Health.Status}}' "$daemon")" = healthy; do
  attempt=$((attempt + 1))
  test "$attempt" -le 30
  sleep 1
done
docker kill --signal INT "$daemon" >/dev/null
docker wait "$daemon" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$daemon")" -eq 0

report="$work/runtime-policy.json"
jq -S -s --arg candidate "$candidate" --arg platform "$platform" \
  '{schema:"dkim2-image-runtime-evidence-v1",candidate_snapshot_sha256:$candidate,platform:$platform,images:.,lifecycle:{daemon_sigterm:true,daemon_sigint:true,milter_sigterm:true,milter_sigint:true,restart:true,writable_socket_volume:true}}' \
  "$entries" >"$report"
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. \
    -install "$report" -target .artifacts/image-evidence/runtime-policy.json -replace
