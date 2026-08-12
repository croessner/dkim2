#!/bin/sh
set -eu
umask 077

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root"

docker_host=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
case "$docker_host" in
  unix:///*)
    docker_socket=${docker_host#unix://}
    case "$docker_socket" in
      /*/../*|*/..|*'
'*|*' '*|'') exit 2 ;;
    esac
    test -S "$docker_socket"
    ;;
  *) exit 2 ;;
esac
export DOCKER_HOST="$docker_host"

project=dkim2-postfix-runtime
compose_root=deployments/postfix-compose
output_root=.artifacts/postfix-deployment
helper_image=chrroessner/postfix:3.11.6-r1@sha256:8ccda0e26bb241116c7df5e0fb2bcdbc6a77b409b085d87e7ad4d0c23b0c41fd
run_id=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
case "$run_id" in
  ????????????????) ;;
  *) exit 2 ;;
esac
prefix=dkim2-deployment-"$run_id"
daemon_image="$prefix"-dkim2d:verified
milter_image="$prefix"-dkim2-milter:verified
daemon_upgrade_image="$prefix"-dkim2d:lifecycle-upgrade
milter_upgrade_image="$prefix"-dkim2-milter:lifecycle-upgrade
daemon_image_selected=$daemon_image
milter_image_selected=$milter_image
daemon_image_id=
milter_image_id=
daemon_upgrade_image_id=
milter_upgrade_image_id=
work=

# compose renders and runs only the closed test override with trusted metadata.
compose() {
  env -i \
    PATH=/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin \
    HOME="$work/home" \
    TMPDIR=/tmp \
    DOCKER_HOST="$docker_host" \
    DKIM2_REVISION=0000000000000000000000000000000000000000 \
    SOURCE_DATE_EPOCH=0 \
    DKIM2_CREATED=1970-01-01T00:00:00Z \
    DKIM2_VERSION=0.0.0-dev \
    DKIM2_DIRTY=clean \
    DKIM2D_IMAGE="$daemon_image_selected" \
    DKIM2_MILTER_IMAGE="$milter_image_selected" \
    docker compose \
      --project-name "$project" \
      --project-directory "$compose_root" \
      --file "$compose_root/compose.yaml" \
      --file "$compose_root/compose.test.yaml" \
      --profile test-only "$@"
}

# cleanup removes only resources owned by this fixed project and unique image set.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if test -n "$work"; then
    if test "$status" -ne 0; then
      compose ps --all >&2 || true
      compose logs --no-color --tail 100 >&2 || true
    fi
    compose down --volumes --remove-orphans >/dev/null 2>&1 || status=1
  fi
  docker rm -f "$prefix"-helper >/dev/null 2>&1 || true
  for container in $(docker ps --all --quiet \
    --filter "name=^/${prefix}-"); do
    case "$(docker inspect "$container" --format '{{.Name}}')" in
      /"$prefix"-*) docker rm -f "$container" >/dev/null 2>&1 || status=1 ;;
      *) status=1 ;;
    esac
  done
  for image in \
    "$daemon_image" "$milter_image" \
    "$daemon_upgrade_image" "$milter_upgrade_image"; do
    docker image rm "$image" >/dev/null 2>&1 || status=1
  done
  for identity in \
    "$daemon_image_id" "$milter_image_id" \
    "$daemon_upgrade_image_id" "$milter_upgrade_image_id"; do
    test -n "$identity" || continue
    if docker image inspect "$identity" >/dev/null 2>&1 &&
      test "$(docker image inspect "$identity" --format '{{json .RepoTags}}')" = null; then
      docker image rm "$identity" >/dev/null 2>&1 || status=1
    fi
  done
  if test -n "$work"; then
    rm -rf -- "$work" || status=1
  fi
  for volume in $(docker volume ls --quiet \
    --filter "label=org.dkim2.test-run=$run_id"); do
    test "$(docker volume inspect "$volume" \
      --format '{{index .Labels "org.dkim2.test-run"}}')" = "$run_id" ||
      status=1
    docker volume rm "$volume" >/dev/null 2>&1 || status=1
  done
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

if test -n "$(docker ps --all --quiet --filter "label=com.docker.compose.project=$project")" ||
  test -n "$(docker volume ls --quiet --filter "label=com.docker.compose.project=$project")"; then
  exit 1
fi
for image in "$daemon_image" "$milter_image"; do
  if docker image inspect "$image" >/dev/null 2>&1; then
    exit 1
  fi
done

mkdir -p .artifacts
test -d .artifacts
test ! -L .artifacts
mkdir -p "$output_root"
test -d "$output_root"
test ! -L "$output_root"
work=$(mktemp -d .artifacts/.postfix-deployment-work.XXXXXX)
mkdir -m 0700 "$work/home"

architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in
  x86_64|amd64) platform=linux/amd64; goarch=amd64 ;;
  aarch64|arm64) platform=linux/arm64; goarch=arm64 ;;
  *) exit 2 ;;
esac

CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools build \
    -o "../$output_root/deploymentfixture" \
    ./cmd/deploymentfixture
chmod 0755 "$output_root/deploymentfixture"

# load_product_image verifies one platform archive and records its exact subjects.
load_product_image() {
  product=$1
  image=$2
  report=.artifacts/image-evidence/"$product".oci.json
  archive=.artifacts/"$product".oci.tar
  test -f "$report"
  test -f "$archive"
  subject=$(jq -er --arg platform "$platform" \
    '.platforms[] | select(.platform == $platform) | .manifest_digest' \
    "$report")
  config=$(jq -er --arg platform "$platform" \
    '.platforms[] | select(.platform == $platform) | .config_digest' \
    "$report")
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/ocipolicy \
      -archive "../$archive" \
      -product "$product" \
      -export-platform "$platform" \
      -expected-manifest "$subject" \
      -docker-tag "$image" >"$work/$product.docker.tar"
  docker load -i "$work/$product.docker.tar" >/dev/null
  test "$(docker image inspect "$image" --format '{{.Id}}')" = "$config"
  printf '%s\n' "$subject" >"$work/$product.subject"
  printf '%s\n' "$config" >"$work/$product.config"
}

load_product_image dkim2d "$daemon_image"
load_product_image dkim2-milter "$milter_image"

# create_upgrade_image derives one test-only immutable identity without changing product bytes.
create_upgrade_image() {
  source=$1
  target=$2
  product=$3
  container="$prefix"-upgrade-source-"$product"
  docker create --name "$container" "$source" >/dev/null
  docker commit \
    --change "LABEL org.dkim2.lifecycle-test=upgrade-$product" \
    "$container" "$target" >/dev/null
  docker rm "$container" >/dev/null
  source_id=$(docker image inspect "$source" --format '{{.Id}}')
  target_id=$(docker image inspect "$target" --format '{{.Id}}')
  test -n "$source_id"
  test -n "$target_id"
  test "$source_id" != "$target_id"
  test "$(docker image inspect "$source" --format '{{json .Config.Entrypoint}}')" = \
    "$(docker image inspect "$target" --format '{{json .Config.Entrypoint}}')"
  test "$(docker image inspect "$source" --format '{{.Architecture}}/{{.Os}}')" = \
    "$(docker image inspect "$target" --format '{{.Architecture}}/{{.Os}}')"
}

create_upgrade_image "$daemon_image" "$daemon_upgrade_image" dkim2d
create_upgrade_image "$milter_image" "$milter_upgrade_image" dkim2-milter
daemon_image_id=$(docker image inspect "$daemon_image" --format '{{.Id}}')
milter_image_id=$(docker image inspect "$milter_image" --format '{{.Id}}')
daemon_upgrade_image_id=$(docker image inspect "$daemon_upgrade_image" --format '{{.Id}}')
milter_upgrade_image_id=$(docker image inspect "$milter_upgrade_image" --format '{{.Id}}')

# inspect_socket proves exact socket ownership, mode, and file type or absence.
inspect_socket() {
  route=$1
  expectation=$2
  volume="$project"_test-socket-"$route"
  if test "$expectation" = present; then
    command='state=$(stat -c "%u:%g:%a:%F" /sockets/milter.sock); test "$state" = "2000:103:660:socket"'
  else
    command='test ! -e /sockets/milter.sock'
  fi
  docker run --rm \
    --name "$prefix"-helper \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 2000:103 \
    --mount "type=volume,source=$volume,target=/sockets,readonly" \
    --entrypoint /bin/sh \
    "$helper_image" -ceu "$command"
}

# inspect_namespace proves each daemon remains loopback-only in one route namespace.
inspect_namespace() {
  route=$1
  daemon=$(compose ps --quiet daemon-"$route")
  milter=$(compose ps --quiet milter-"$route")
  dns=$(compose ps --quiet dns-"$route")
  test -n "$daemon"
  test -n "$milter"
  test -n "$dns"
  daemon_namespace=$(docker inspect "$daemon" --format '{{.NetworkSettings.SandboxKey}}')
  test -n "$daemon_namespace"
  test "$(docker inspect "$milter" --format '{{.HostConfig.NetworkMode}}')" = "container:$daemon"
  test "$(docker inspect "$dns" --format '{{.HostConfig.NetworkMode}}')" = "container:$daemon"
  docker run --rm \
    --name "$prefix"-helper \
    --network "container:$daemon" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --entrypoint /bin/sh \
    "$helper_image" -ceu '
      grep -q " 0100007F:1F90 " /proc/net/tcp
      ! grep -q " 00000000:1F90 " /proc/net/tcp
    '
}

# inspect_route_authority proves daemon and Milter receive only route-local authority.
inspect_route_authority() {
  route=$1
  mode=$2
  daemon_volume="$project"_test-daemon-"$route"
  milter_volume="$project"_test-milter-"$route"
  docker run --rm \
    --name "$prefix"-helper \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 2000:2000 \
    --mount "type=volume,source=$daemon_volume,target=/daemon,readonly" \
    --mount "type=volume,source=$milter_volume,target=/milter,readonly" \
    --entrypoint /bin/sh \
    "$helper_image" -ceu '
      mode=$1
      route=$2
      generation=0123456789abcdef0123456789abcdef
      rotation=fedcba9876543210fedcba9876543210
      test -f "/daemon/$generation/capability"
      test -f "/daemon/$rotation/capability"
      set -- /daemon/*
      test "$#" -eq 3
      set -- /milter/*
      test "$#" -eq 2
      test -f "/milter/$route.yaml"
      test -f /milter/capability
      case "$mode" in
        inbound)
          set -- "/daemon/$generation"/*
          test "$#" -eq 1
          set -- "/daemon/$rotation"/*
          test "$#" -eq 1
          cmp "/daemon/$generation/capability" /milter/capability
          cmp "/daemon/$rotation/capability" /milter/capability
          ;;
        originator)
          set -- "/daemon/$generation"/*
          test "$#" -eq 5
          test -f "/daemon/$generation/sign-capability"
          test ! -e "/daemon/$generation/revise-capability"
          test -f "/daemon/$generation/datasource"
          test -f "/daemon/$generation/private-manifest"
          test -f "/daemon/$generation/privacy-origin-key-7f3c.pem"
          set -- "/daemon/$rotation"/*
          test "$#" -eq 5
          cmp "/daemon/$generation/sign-capability" /milter/capability
          cmp "/daemon/$rotation/sign-capability" /milter/capability
          ;;
        ordinary_transit)
          set -- "/daemon/$generation"/*
          test "$#" -eq 5
          test ! -e "/daemon/$generation/sign-capability"
          test -f "/daemon/$generation/revise-capability"
          test -f "/daemon/$generation/datasource"
          test -f "/daemon/$generation/private-manifest"
          test -f "/daemon/$generation/privacy-transit-key-7f3c.pem"
          set -- "/daemon/$rotation"/*
          test "$#" -eq 5
          cmp "/daemon/$generation/revise-capability" /milter/capability
          cmp "/daemon/$rotation/revise-capability" /milter/capability
          ;;
        *) exit 2 ;;
      esac
    ' fixture "$mode" "$route"
}

# validate_route_state executes the production read-only validators through final mounts.
validate_route_state() {
  route=$1
  daemon=$(compose ps --quiet daemon-"$route")
  milter=$(compose ps --quiet milter-"$route")
  test -n "$daemon"
  test -n "$milter"
  test -z "$(docker exec "$daemon" \
    /usr/local/bin/dkim2d validate --config /var/lib/dkim2d/config.yaml)"
  test -z "$(docker exec "$milter" \
    /usr/local/bin/dkim2-milter validate \
    --config "/etc/dkim2-milter/$route.yaml")"
}

# inspect_service_policy verifies exact product identity, user, mounts, and hardening.
inspect_service_policy() {
  service=$1
  container=$(compose ps --quiet "$service")
  test -n "$container"
  case "$service" in
    daemon-*)
      expected_user=2000:2000
      expected_image=$daemon_image
      expected_id=$(cat "$work/dkim2d.config")
      expected_kind=daemon
      ;;
    milter-*)
      expected_user=2000:103
      expected_image=$milter_image
      expected_id=$(cat "$work/dkim2-milter.config")
      expected_kind=milter
      ;;
    *) exit 2 ;;
  esac
  if docker inspect "$container" |
    jq -e \
      --arg user "$expected_user" \
      --arg image "$expected_image" \
      --arg identity "$expected_id" \
      --arg kind "$expected_kind" \
      '.[0] |
      .Config.User == $user and
      .Config.Image == $image and
      .Image == $identity and
      .HostConfig.ReadonlyRootfs == true and
      .HostConfig.CapDrop == ["ALL"] and
      (.HostConfig.CapAdd == null or .HostConfig.CapAdd == []) and
      (.HostConfig.SecurityOpt | index("no-new-privileges:true")) != null and
      .HostConfig.Privileged == false and
      .HostConfig.PidsLimit > 0 and
      .HostConfig.Memory > 0 and
      .HostConfig.NanoCpus > 0 and
      .HostConfig.Ulimits == [{"Name":"nofile","Hard":1024,"Soft":1024}] and
      .HostConfig.PortBindings == {} and
      (if $kind == "daemon" then
        ([.Mounts[] | {destination:.Destination,rw:.RW,type:.Type}] |
          sort_by(.destination)) ==
        [{destination:"/var/lib/dkim2d",rw:false,type:"volume"}]
      else
        ([.Mounts[] | {destination:.Destination,rw:.RW,type:.Type}] |
          sort_by(.destination)) ==
        [
          {destination:"/etc/dkim2-milter",rw:false,type:"volume"},
          {destination:"/run/dkim2",rw:true,type:"volume"}
        ]
      end)
    ' >/dev/null; then
    return
  fi
  docker inspect "$container" |
    jq '.[0] | {
      user:.Config.User,
      image:.Config.Image,
      identity:.Image,
      read_only:.HostConfig.ReadonlyRootfs,
      cap_drop:.HostConfig.CapDrop,
      cap_add:.HostConfig.CapAdd,
      security_opt:.HostConfig.SecurityOpt,
      privileged:.HostConfig.Privileged,
      pids_limit:.HostConfig.PidsLimit,
      memory:.HostConfig.Memory,
      nano_cpus:.HostConfig.NanoCpus,
      ulimits:.HostConfig.Ulimits,
      port_bindings:.HostConfig.PortBindings,
      mounts:[.Mounts[] | {destination:.Destination,rw:.RW,type:.Type}] | sort_by(.destination)
    }' >&2
  return 1
}

# wait_healthy waits within the Compose healthcheck retry bound.
wait_healthy() {
  service=$1
  attempt=0
  while :; do
    container=$(compose ps --quiet "$service")
    if test -n "$container" &&
      test "$(docker inspect "$container" --format '{{.State.Health.Status}}')" = healthy; then
      return
    fi
    attempt=$((attempt + 1))
    test "$attempt" -le 60
    sleep 1
  done
}

# wait_socket waits for one recreated socket without accepting another file type.
wait_socket() {
  route=$1
  attempt=0
  until inspect_socket "$route" present >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    test "$attempt" -le 30
    sleep 1
  done
}

# start_existing_service starts only one already-created project container.
start_existing_service() {
  service=$1
  container=$(compose ps --all --quiet "$service")
  test -n "$container"
  test "$(docker inspect "$container" \
    --format '{{index .Config.Labels "com.docker.compose.project"}}')" = "$project"
  test "$(docker inspect "$container" \
    --format '{{index .Config.Labels "com.docker.compose.service"}}')" = "$service"
  docker start "$container" >/dev/null
}

# restart_existing_service restarts only one proven existing project container.
restart_existing_service() {
  service=$1
  container=$(compose ps --quiet "$service")
  test -n "$container"
  test "$(docker inspect "$container" \
    --format '{{index .Config.Labels "com.docker.compose.project"}}')" = "$project"
  test "$(docker inspect "$container" \
    --format '{{index .Config.Labels "com.docker.compose.service"}}')" = "$service"
  docker restart --time 30 "$container" >/dev/null
}

# stop_for_replacement stops admission and every route namespace in ownership order.
stop_for_replacement() {
  compose stop postfix >/dev/null
  compose stop milter-inbound milter-originator milter-transit >/dev/null
  compose stop dns-inbound dns-originator dns-transit >/dev/null
  compose stop daemon-inbound daemon-originator daemon-transit >/dev/null
}

# start_stopped_stack starts existing containers without rerunning one-shot bootstrap.
start_stopped_stack() {
  for route in inbound originator transit; do
    start_existing_service daemon-"$route"
    wait_healthy daemon-"$route"
  done
  for route in inbound originator transit; do
    start_existing_service dns-"$route"
    wait_healthy dns-"$route"
  done
  for route in inbound originator transit; do
    start_existing_service milter-"$route"
    wait_healthy milter-"$route"
    wait_socket "$route"
  done
  start_existing_service postfix
  wait_healthy postfix
}

# recreate_product_stack replaces route namespaces without rerunning bootstrap.
recreate_product_stack() {
  compose rm --force \
    milter-inbound milter-originator milter-transit \
    dns-inbound dns-originator dns-transit >/dev/null
  compose rm --force \
    daemon-inbound daemon-originator daemon-transit >/dev/null
  compose up --detach --no-deps --no-build \
    daemon-inbound daemon-originator daemon-transit
  for route in inbound originator transit; do
    wait_healthy daemon-"$route"
  done
  compose up --detach --no-deps --no-build \
    dns-inbound dns-originator dns-transit
  for route in inbound originator transit; do
    wait_healthy dns-"$route"
  done
  compose up --detach --no-deps --no-build \
    milter-inbound milter-originator milter-transit
  for route in inbound originator transit; do
    wait_healthy milter-"$route"
    wait_socket "$route"
  done
  start_existing_service postfix
  wait_healthy postfix
}

# inspect_selected_product_images binds all running routes to selected immutable IDs.
inspect_selected_product_images() {
  case "$daemon_image_selected" in
    "$daemon_image") expected_daemon=$daemon_image_id ;;
    "$daemon_upgrade_image") expected_daemon=$daemon_upgrade_image_id ;;
    *) return 1 ;;
  esac
  case "$milter_image_selected" in
    "$milter_image") expected_milter=$milter_image_id ;;
    "$milter_upgrade_image") expected_milter=$milter_upgrade_image_id ;;
    *) return 1 ;;
  esac
  for route in inbound originator transit; do
    test "$(docker inspect "$(compose ps --quiet daemon-"$route")" \
      --format '{{.Image}}')" = "$expected_daemon"
    test "$(docker inspect "$(compose ps --quiet milter-"$route")" \
      --format '{{.Image}}')" = "$expected_milter"
  done
}

# validate_selected_image_authority rejects a mutable tag retarget before activation.
validate_selected_image_authority() {
  case "$daemon_image_selected" in
    "$daemon_image") expected_daemon=$daemon_image_id ;;
    "$daemon_upgrade_image") expected_daemon=$daemon_upgrade_image_id ;;
    *) return 1 ;;
  esac
  case "$milter_image_selected" in
    "$milter_image") expected_milter=$milter_image_id ;;
    "$milter_upgrade_image") expected_milter=$milter_upgrade_image_id ;;
    *) return 1 ;;
  esac
  current_daemon=$(docker image inspect "$daemon_image_selected" --format '{{.Id}}')
  current_milter=$(docker image inspect "$milter_image_selected" --format '{{.Id}}')
  test "$current_daemon" = "$expected_daemon" &&
    test "$current_milter" = "$expected_milter"
}

# test_image_authority_retarget proves stored identities outrank mutable local tags.
test_image_authority_retarget() {
  accepted=0
  docker tag "$daemon_upgrade_image_id" "$daemon_image"
  if validate_selected_image_authority; then
    accepted=1
  fi
  docker tag "$daemon_image_id" "$daemon_image"
  validate_selected_image_authority
  test "$accepted" -eq 0

  accepted=0
  docker tag "$milter_upgrade_image_id" "$milter_image"
  if validate_selected_image_authority; then
    accepted=1
  fi
  docker tag "$milter_image_id" "$milter_image"
  validate_selected_image_authority
  test "$accepted" -eq 0
}

# clone_volume copies one component-consistent filesystem snapshot without printing content.
clone_volume() {
  source=$1
  target=$2
  docker volume create \
    --label "org.dkim2.test-run=$run_id" \
    "$target" >/dev/null
  copy_volume_contents "$source" "$target"
}

# copy_volume_contents restores one offline component snapshot into an empty volume.
copy_volume_contents() {
  source=$1
  target=$2
  docker run --rm \
    --name "$prefix"-helper \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add DAC_READ_SEARCH \
    --cap-add FOWNER \
    --security-opt no-new-privileges \
    --mount "type=volume,source=$source,target=/source,readonly" \
    --mount "type=volume,source=$target,target=/target" \
    --entrypoint /bin/sh \
    "$helper_image" -ceu '
      test -z "$(find /target -mindepth 1 -maxdepth 1 -print -quit)"
      cp -a /source/. /target/
      owner=$(stat -c "%u:%g" /source)
      mode=$(stat -c "%a" /source)
      chown "$owner" /target
      chmod "$mode" /target
    '
}

# mutate_volume applies one fixed test-only negative without exposing protected bytes.
mutate_volume() {
  volume=$1
  command=$2
  docker run --rm \
    --name "$prefix"-helper \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --security-opt no-new-privileges \
    --mount "type=volume,source=$volume,target=/state" \
    --entrypoint /bin/sh \
    "$helper_image" -ceu "$command"
}

# daemon_validation_result runs the production validator on one isolated snapshot.
daemon_validation_result() {
  volume=$1
  if docker run --rm \
    --name "$prefix"-validator \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 2000:2000 \
    --mount "type=volume,source=$volume,target=/var/lib/dkim2d,readonly" \
    "$daemon_image" validate --config /var/lib/dkim2d/config.yaml \
    >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# milter_validation_result runs the production validator on one isolated snapshot.
milter_validation_result() {
  volume=$1
  route=$2
  if docker run --rm \
    --name "$prefix"-validator \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 2000:103 \
    --mount "type=volume,source=$volume,target=/etc/dkim2-milter,readonly" \
    "$milter_image" validate --config "/etc/dkim2-milter/$route.yaml" \
    >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# test_socket_collision proves a second owner cannot replace one live route socket.
test_socket_collision() {
  route=$1
  daemon=$(compose ps --quiet daemon-"$route")
  test -n "$daemon"
  socket_volume="$project"_test-socket-"$route"
  milter_volume="$project"_test-milter-"$route"
  collision="$prefix"-collision-"$route"
  docker create \
    --name "$collision" \
    --network "container:$daemon" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 2000:103 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=2000 \
    --mount "type=volume,source=$socket_volume,target=/run/dkim2" \
    --mount "type=volume,source=$milter_volume,target=/etc/dkim2-milter,readonly" \
    "$milter_image" serve \
    --config "/etc/dkim2-milter/$route.yaml" >/dev/null
  docker start "$collision" >/dev/null
  attempt=0
  while test "$(docker inspect "$collision" --format '{{.State.Running}}')" = true; do
    attempt=$((attempt + 1))
    if test "$attempt" -gt 15; then
      docker stop --time 1 "$collision" >/dev/null 2>&1 || true
      docker rm "$collision" >/dev/null 2>&1 || true
      return 1
    fi
    sleep 1
  done
  test "$(docker inspect "$collision" --format '{{.State.ExitCode}}')" -ne 0
  docker rm "$collision" >/dev/null
  inspect_socket "$route" present
  wait_healthy milter-"$route"
}

# recover_forced_milter_stop proves bounded force-stop and exact stale-socket cleanup.
recover_forced_milter_stop() {
  route=$1
  service=milter-"$route"
  container=$(compose ps --quiet "$service")
  test -n "$container"
  test "$(docker inspect "$container" \
    --format '{{index .Config.Labels "com.docker.compose.project"}}')" = "$project"
  test "$(docker inspect "$container" \
    --format '{{index .Config.Labels "com.docker.compose.service"}}')" = "$service"
  docker kill --signal KILL "$container" >/dev/null
  test "$(docker inspect "$container" --format '{{.State.Running}}')" = false
  test "$(docker inspect "$container" --format '{{.State.ExitCode}}')" -ne 0

  volume="$project"_test-socket-"$route"
  docker run --rm \
    --name "$prefix"-helper \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 2000:103 \
    --mount "type=volume,source=$volume,target=/sockets" \
    --entrypoint /bin/sh \
    "$helper_image" -ceu '
      state=$(stat -c "%u:%g:%a:%F" /sockets/milter.sock)
      test "$state" = "2000:103:660:socket"
      rm /sockets/milter.sock
      test ! -e /sockets/milter.sock
    '
  start_existing_service "$service"
  wait_healthy "$service"
  wait_socket "$route"
}

# run_postfix_fixture runs one exact SMTP client in the Postfix namespace.
run_postfix_fixture() {
  operation=$1
  message=${2-}
  postfix=$(compose ps --quiet postfix)
  test -n "$postfix"
  if test -n "$message"; then
    docker run --rm \
      --name "$prefix"-helper \
      --network "container:$postfix" \
      --read-only \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --pids-limit 32 \
      --memory 64m \
      --cpus 0.25 \
      --mount "type=bind,source=$root/$output_root/deploymentfixture,target=/testdata/deploymentfixture,readonly" \
      --mount "type=bind,source=$message,target=/verify/message.eml,readonly" \
      --entrypoint /testdata/deploymentfixture \
      "$helper_image" "$operation"
  else
    docker run --rm \
      --name "$prefix"-helper \
      --network "container:$postfix" \
      --read-only \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --pids-limit 32 \
      --memory 64m \
      --cpus 0.25 \
      --mount "type=bind,source=$root/$output_root/deploymentfixture,target=/testdata/deploymentfixture,readonly" \
      --entrypoint /testdata/deploymentfixture \
      "$helper_image" "$operation"
  fi
}

# verify_message uses only public fixture data and the standalone DKIM2 verifier.
verify_message() {
  operation=$1
  message=$2
  dns_volume="$project"_test-dns
  docker run --rm \
    --name "$prefix"-helper \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 32 \
    --memory 64m \
    --cpus 0.25 \
    --mount "type=bind,source=$root/$output_root/deploymentfixture,target=/testdata/deploymentfixture,readonly" \
    --mount "type=volume,source=$dns_volume,target=/state/dns,readonly" \
    --mount "type=bind,source=$message,target=/verify/message.eml,readonly" \
    --entrypoint /testdata/deploymentfixture \
    "$helper_image" "$operation" >/dev/null
}

# valid_queue_id accepts only bounded Postfix identifier characters.
valid_queue_id() {
  case "$1" in
    ?????*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[!A-Za-z0-9]*) return 1 ;;
  esac
  test "${#1}" -le 64
}

# queue_ids returns the sorted bounded identifiers from real Postfix queue JSON.
queue_ids() {
  postfix=$(compose ps --quiet postfix)
  test -n "$postfix"
  docker exec "$postfix" postqueue -j |
    jq -r '.queue_id' |
    LC_ALL=C sort
}

# sole_queue_id requires exactly one real queue record.
sole_queue_id() {
  ids=$(queue_ids)
  test -n "$ids"
  test "$(printf '%s\n' "$ids" | wc -l | tr -d ' ')" -eq 1
  valid_queue_id "$ids"
  printf '%s\n' "$ids"
}

# wait_for_queue_header waits for pickup/cleanup to finish one local submission.
wait_for_queue_header() {
  name=$1
  attempt=0
  while :; do
    ids=$(queue_ids)
    if test -n "$ids" &&
      test "$(printf '%s\n' "$ids" | wc -l | tr -d ' ')" -eq 1 &&
      valid_queue_id "$ids" &&
      docker exec "$postfix" postcat -bhq "$ids" 2>/dev/null |
        grep -qi "^${name}:"; then
      printf '%s\n' "$ids"
      return
    fi
    attempt=$((attempt + 1))
    test "$attempt" -le 30
    sleep 1
  done
}

# assert_empty_queue proves the synthetic run starts and returns empty.
assert_empty_queue() {
  test -z "$(queue_ids)"
}

# clear_queue removes only this isolated test deployment's synthetic records.
clear_queue() {
  postfix=$(compose ps --quiet postfix)
  test -n "$postfix"
  docker exec "$postfix" postsuper -d ALL >/dev/null
  assert_empty_queue
}

# capture_queue_message records the real queue record and exact message portion.
capture_queue_message() {
  queue_id=$1
  destination=$2
  valid_queue_id "$queue_id"
  postfix=$(compose ps --quiet postfix)
  test -n "$postfix"
  docker exec "$postfix" postcat -q "$queue_id" >"$destination.record"
  docker exec "$postfix" postcat -bhq "$queue_id" >"$destination"
  test -s "$destination.record"
  test -s "$destination"
  test "$(wc -c <"$destination.record" | tr -d ' ')" -le 8388608
  test "$(wc -c <"$destination" | tr -d ' ')" -le 4194304
}

# assert_privacy_markers proves seeded protected and mail facts stay out of
# product logs, normalized reports, and candidate-bound supply-chain evidence.
assert_privacy_markers() {
  report=$1
  message=$2
  logs=$3
  compose logs --no-color \
    daemon-inbound daemon-originator daemon-transit \
    milter-inbound milter-originator milter-transit >"$logs"
  test "$(wc -c <"$logs" | tr -d ' ')" -le 1048576
  for marker in \
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
    privacy-cap-transit-revision-000 \
    'PRIVATE KEY'; do
    if grep -aFRq -- "$marker" \
      "$report" "$logs" .artifacts/image-evidence; then
      exit 1
    fi
    encoded=$(printf '%s' "$marker" | base64 | tr -d '\n=' | tr '+/' '-_')
    if grep -aFRq -- "$encoded" \
      "$report" "$logs" .artifacts/image-evidence; then
      exit 1
    fi
  done
  grep -Fq privacy-message-7f3c9a2d "$message"
  grep -Fq privacy-7f3c9a2d "$message"
}

# smtp_queue_id validates the helper's exact final Postfix queue acceptance.
smtp_queue_id() {
  result=$1
  identifier=${result##* }
  valid_queue_id "$identifier"
  test "$result" = "SMTP queue acceptance passed $identifier"
  printf '%s\n' "$identifier"
}

# run_once executes one complete isolated production-shape deployment proof.
run_once() {
  number=$1
  run_root="$output_root/run-$number"
  rm -rf -- "$run_root"
  mkdir -m 0700 "$run_root"

  validate_selected_image_authority
  test_image_authority_retarget
  compose up --detach --wait --no-build
  inspect_selected_product_images

  printf 'deployment phase: protected-validation-%s\n' "$number"
  for route in inbound originator transit; do
    printf 'deployment check: protected-validation-%s\n' "$route"
    validate_route_state "$route"
  done

  printf 'deployment phase: route-topology-%s\n' "$number"
  for route in inbound originator transit; do
    printf 'deployment check: namespace-%s\n' "$route"
    inspect_namespace "$route"
    printf 'deployment check: socket-%s\n' "$route"
    inspect_socket "$route" present
    printf 'deployment check: daemon-policy-%s\n' "$route"
    inspect_service_policy daemon-"$route"
    printf 'deployment check: milter-policy-%s\n' "$route"
    inspect_service_policy milter-"$route"
  done
  printf 'deployment check: authority-inbound\n'
  inspect_route_authority inbound inbound
  printf 'deployment check: authority-originator\n'
  inspect_route_authority originator originator
  printf 'deployment check: authority-transit\n'
  inspect_route_authority transit ordinary_transit

  printf 'deployment phase: namespace-separation-%s\n' "$number"
  inbound_namespace=$(docker inspect "$(compose ps --quiet daemon-inbound)" \
    --format '{{.NetworkSettings.SandboxKey}}')
  originator_namespace=$(docker inspect "$(compose ps --quiet daemon-originator)" \
    --format '{{.NetworkSettings.SandboxKey}}')
  transit_namespace=$(docker inspect "$(compose ps --quiet daemon-transit)" \
    --format '{{.NetworkSettings.SandboxKey}}')
  test "$inbound_namespace" != "$originator_namespace"
  test "$inbound_namespace" != "$transit_namespace"
  test "$originator_namespace" != "$transit_namespace"

  printf 'deployment phase: postfix-policy-%s\n' "$number"
  postfix=$(compose ps --quiet postfix)
  test -n "$postfix"
  postfix_image_id=$(docker image inspect "$helper_image" --format '{{.Id}}')
  if docker inspect "$postfix" |
    jq -e --arg image "$helper_image" --arg identity "$postfix_image_id" '.[0] |
      .Config.User == "" and
      .Config.Image == $image and
      .Image == $identity and
      .HostConfig.ReadonlyRootfs == false and
      .HostConfig.CapDrop == ["ALL"] and
      (.HostConfig.CapAdd | sort) ==
        ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_NET_BIND_SERVICE",
          "CAP_SETGID","CAP_SETUID","CAP_SYS_CHROOT"] and
      (.HostConfig.SecurityOpt | index("no-new-privileges:true")) != null and
      .HostConfig.Privileged == false and
      .HostConfig.PidsLimit == 128 and
      .HostConfig.Memory == 536870912 and
      .HostConfig.NanoCpus == 1500000000 and
      .HostConfig.Ulimits == [{"Name":"nofile","Hard":4096,"Soft":4096}] and
      .HostConfig.PortBindings == {} and
      ([.Mounts[] | {destination:.Destination,rw:.RW,type:.Type}] |
        sort_by(.destination)) ==
      [
        {destination:"/etc/postfix",rw:true,type:"volume"},
        {destination:"/etc/postfix/custom-config/main.cf",rw:false,type:"bind"},
        {destination:"/etc/postfix/custom-config/master.cf",rw:false,type:"bind"},
        {destination:"/run/dkim2/inbound",rw:false,type:"volume"},
        {destination:"/run/dkim2/originator",rw:false,type:"volume"},
        {destination:"/run/dkim2/transit",rw:false,type:"volume"},
        {destination:"/testdata/deploymentfixture",rw:false,type:"bind"},
        {destination:"/var/spool/postfix",rw:true,type:"volume"}
      ]
    ' >/dev/null; then
    :
  else
    docker inspect "$postfix" |
      jq '.[0] | {
        user:.Config.User,
        image:.Config.Image,
        identity:.Image,
        read_only:.HostConfig.ReadonlyRootfs,
        cap_drop:.HostConfig.CapDrop,
        cap_add:.HostConfig.CapAdd,
        security_opt:.HostConfig.SecurityOpt,
        privileged:.HostConfig.Privileged,
        pids_limit:.HostConfig.PidsLimit,
        memory:.HostConfig.Memory,
        nano_cpus:.HostConfig.NanoCpus,
        ulimits:.HostConfig.Ulimits,
        port_bindings:.HostConfig.PortBindings,
        mounts:[.Mounts[] | {destination:.Destination,rw:.RW,type:.Type}] |
          sort_by(.destination)
      }' >&2
    return 1
  fi
  test "$(docker exec "$postfix" postconf -h milter_protocol)" = 6
  printf 'deployment check: postfix-milter-protocol\n'
  test "$(docker exec "$postfix" postconf -h milter_default_action)" = tempfail
  printf 'deployment check: postfix-milter-action\n'
  test "$(docker exec "$postfix" postconf -h smtpd_milters)" = unix:/run/dkim2/inbound/milter.sock
  printf 'deployment check: postfix-inbound-route\n'
  test "$(docker exec "$postfix" postconf -h non_smtpd_milters)" = unix:/run/dkim2/originator/milter.sock
  printf 'deployment check: postfix-originator-route\n'
  transit_master=$(docker exec "$postfix" postconf -M 127.0.0.1:2526/inet)
  transit_master=$(printf '%s\n' "$transit_master" | awk '{$1=$1; print}')
  expected_transit_master="127.0.0.1:2526 inet n - n - - smtpd -o smtpd_milters=unix:/run/dkim2/transit/milter.sock -o non_smtpd_milters= -o smtpd_client_restrictions=permit_mynetworks,reject -o smtpd_relay_restrictions=permit_mynetworks,reject"
  if test "$transit_master" != "$expected_transit_master"; then
    printf 'unexpected transit master service: %s\n' "$transit_master" >&2
    return 1
  fi
  printf 'deployment check: postfix-transit-route\n'
  docker exec "$postfix" /bin/sh -ceu '
    grep -q " 0100007F:09DE " /proc/net/tcp
    ! grep -q " 00000000:09DE " /proc/net/tcp
  '

  printf 'deployment phase: mail-flow-%s\n' "$number"
  assert_empty_queue
  unsigned_inbound_result=$(run_postfix_fixture smtp-inbound)
  unsigned_inbound_id=$(smtp_queue_id "$unsigned_inbound_result")
  test "$(sole_queue_id)" = "$unsigned_inbound_id"
  clear_queue

  test -z "$(queue_ids)"
  test "$(docker exec "$postfix" /testdata/deploymentfixture local-submit)" = \
    "local submission queue acceptance passed"
  originator_id=$(wait_for_queue_header DKIM2-Signature)
  capture_queue_message "$originator_id" "$run_root/originator.eml"
  verify_message verify-originator "$root/$run_root/originator.eml"
  clear_queue

  originator_inbound_result=$(run_postfix_fixture \
    smtp-inbound-file "$root/$run_root/originator.eml")
  originator_inbound_id=$(smtp_queue_id "$originator_inbound_result")
  test "$(sole_queue_id)" = "$originator_inbound_id"
  clear_queue

  transit_result=$(run_postfix_fixture smtp-transit "$root/$run_root/originator.eml")
  transit_id=$(smtp_queue_id "$transit_result")
  test "$(sole_queue_id)" = "$transit_id"
  capture_queue_message "$transit_id" "$run_root/transit.eml"
  verify_message verify-transit "$root/$run_root/transit.eml"
  clear_queue

  inbound_signed_result=$(run_postfix_fixture smtp-inbound-file "$root/$run_root/transit.eml")
  inbound_signed_id=$(smtp_queue_id "$inbound_signed_result")
  test "$(sole_queue_id)" = "$inbound_signed_id"
  capture_queue_message "$inbound_signed_id" "$run_root/inbound.eml"
  verify_message verify-inbound "$root/$run_root/inbound.eml"

  docker exec "$postfix" postsuper -h "$inbound_signed_id" >/dev/null
  test "$(sole_queue_id)" = "$inbound_signed_id"
  capture_queue_message "$inbound_signed_id" "$run_root/inbound-before-restart.eml"
  restart_existing_service postfix
  wait_healthy postfix
  test "$(sole_queue_id)" = "$inbound_signed_id"
  capture_queue_message "$inbound_signed_id" "$run_root/inbound-after-restart.eml"
  cmp "$run_root/inbound-before-restart.eml" "$run_root/inbound-after-restart.eml"
  verify_message verify-inbound "$root/$run_root/inbound-after-restart.eml"

  compose run --rm --no-deps bootstrap activate-rotation >/dev/null
  for route in inbound originator transit; do
    validate_route_state "$route"
  done
  stop_for_replacement
  validate_selected_image_authority
  queue_backup="$prefix"-"$number"-queue-backup
  queue_volume="$project"_postfix-queue
  clone_volume "$queue_volume" "$queue_backup"
  mutate_volume "$queue_volume" 'rm -rf /state/*'
  copy_volume_contents "$queue_backup" "$queue_volume"
  docker volume rm "$queue_backup" >/dev/null
  start_stopped_stack
  printf 'deployment check: generation-rotation-images\n'
  inspect_selected_product_images
  printf 'deployment check: generation-rotation-queue\n'
  restored_queue_id=$(sole_queue_id)
  valid_queue_id "$restored_queue_id"
  inbound_signed_id=$restored_queue_id
  capture_queue_message "$inbound_signed_id" "$run_root/inbound-after-generation-rotation.eml"
  printf 'deployment check: generation-rotation-message\n'
  cmp \
    "$run_root/inbound-before-restart.eml" \
    "$run_root/inbound-after-generation-rotation.eml"
  verify_message \
    verify-inbound \
    "$root/$run_root/inbound-after-generation-rotation.eml"
  printf 'deployment check: generation-rotation-complete\n'

  compose run --rm --no-deps bootstrap rollback-rotation >/dev/null
  for route in inbound originator transit; do
    validate_route_state "$route"
  done
  stop_for_replacement
  validate_selected_image_authority
  start_stopped_stack
  printf 'deployment check: generation-rollback-images\n'
  inspect_selected_product_images
  printf 'deployment check: generation-rollback-queue\n'
  test "$(sole_queue_id)" = "$inbound_signed_id"
  capture_queue_message "$inbound_signed_id" "$run_root/inbound-after-generation-rollback.eml"
  printf 'deployment check: generation-rollback-message\n'
  cmp \
    "$run_root/inbound-before-restart.eml" \
    "$run_root/inbound-after-generation-rollback.eml"
  verify_message \
    verify-inbound \
    "$root/$run_root/inbound-after-generation-rollback.eml"
  printf 'deployment check: generation-rollback-complete\n'

  stop_for_replacement
  daemon_image_selected=$daemon_upgrade_image
  milter_image_selected=$milter_upgrade_image
  validate_selected_image_authority
  recreate_product_stack
  printf 'deployment check: image-upgrade-images\n'
  inspect_selected_product_images
  for route in inbound originator transit; do
    validate_route_state "$route"
  done
  printf 'deployment check: image-upgrade-queue\n'
  test "$(sole_queue_id)" = "$inbound_signed_id"
  capture_queue_message "$inbound_signed_id" "$run_root/inbound-after-upgrade.eml"
  printf 'deployment check: image-upgrade-message\n'
  cmp "$run_root/inbound-before-restart.eml" "$run_root/inbound-after-upgrade.eml"
  verify_message verify-inbound "$root/$run_root/inbound-after-upgrade.eml"
  printf 'deployment check: image-upgrade-complete\n'

  stop_for_replacement
  daemon_image_selected=$daemon_image
  milter_image_selected=$milter_image
  validate_selected_image_authority
  recreate_product_stack
  printf 'deployment check: image-rollback-images\n'
  inspect_selected_product_images
  for route in inbound originator transit; do
    validate_route_state "$route"
  done
  printf 'deployment check: image-rollback-queue\n'
  test "$(sole_queue_id)" = "$inbound_signed_id"
  capture_queue_message "$inbound_signed_id" "$run_root/inbound-after-rollback.eml"
  printf 'deployment check: image-rollback-message\n'
  cmp "$run_root/inbound-before-restart.eml" "$run_root/inbound-after-rollback.eml"
  verify_message verify-inbound "$root/$run_root/inbound-after-rollback.eml"
  printf 'deployment check: image-rollback-complete\n'
  clear_queue

  printf 'deployment phase: failure-behavior-%s\n' "$number"
  compose stop daemon-inbound >/dev/null
  test "$(run_postfix_fixture smtp-tempfail)" = "SMTP temporary failure passed"
  assert_empty_queue
  start_existing_service daemon-inbound
  wait_healthy daemon-inbound

  compose stop milter-inbound >/dev/null
  inspect_socket inbound absent
  test "$(run_postfix_fixture smtp-tempfail)" = "SMTP temporary failure passed"
  assert_empty_queue
  start_existing_service milter-inbound
  wait_healthy milter-inbound
  wait_socket inbound

  test "$(run_postfix_fixture smtp-overload)" = "SMTP overload admission passed"
  clear_queue

  test_socket_collision originator
  recover_forced_milter_stop transit

  compose stop milter-transit >/dev/null
  inspect_socket transit absent
  transit_container=$(compose ps --all --quiet milter-transit)
  test "$(docker inspect "$transit_container" --format '{{.State.ExitCode}}')" -eq 0
  start_existing_service milter-transit
  wait_healthy milter-transit
  wait_socket transit

  printf 'deployment phase: clean-shutdown-%s\n' "$number"
  for route in inbound originator transit; do
    compose stop milter-"$route" >/dev/null
    inspect_socket "$route" absent
    stopped=$(compose ps --all --quiet milter-"$route")
    test -n "$stopped"
    test "$(docker inspect "$stopped" --format '{{.State.ExitCode}}')" -eq 0
  done
  for route in inbound originator transit; do
    compose stop dns-"$route" >/dev/null
    stopped=$(compose ps --all --quiet dns-"$route")
    test -n "$stopped"
    test "$(docker inspect "$stopped" --format '{{.State.ExitCode}}')" -eq 0
  done
  for route in inbound originator transit; do
    compose stop daemon-"$route" >/dev/null
    stopped=$(compose ps --all --quiet daemon-"$route")
    test -n "$stopped"
    test "$(docker inspect "$stopped" --format '{{.State.ExitCode}}')" -eq 0
  done
  compose stop postfix >/dev/null
  stopped=$(compose ps --all --quiet postfix)
  test -n "$stopped"
  test "$(docker inspect "$stopped" --format '{{.State.ExitCode}}')" -eq 0
  bootstrap=$(compose ps --all --quiet bootstrap)
  test -n "$bootstrap"
  test "$(docker inspect "$bootstrap" --format '{{.State.ExitCode}}')" -eq 0

  printf 'deployment phase: protected-restore-and-negatives-%s\n' "$number"
  source_daemon="$project"_test-daemon-originator
  source_milter="$project"_test-milter-originator

  printf 'deployment check: restored-daemon-state\n'
  restored_daemon="$prefix"-"$number"-restored-daemon
  clone_volume "$source_daemon" "$restored_daemon"
  daemon_validation_result "$restored_daemon"

  printf 'deployment check: invalid-generation\n'
  invalid_generation="$prefix"-"$number"-invalid-generation
  clone_volume "$source_daemon" "$invalid_generation"
  mutate_volume "$invalid_generation" '
    sed "s/0123456789abcdef0123456789abcdef/0123456789abcdef0123456789abcde/" \
      /state/config.yaml >/state/config.yaml.new
    chown 2000:2000 /state/config.yaml.new
    chmod 0600 /state/config.yaml.new
    mv /state/config.yaml.new /state/config.yaml
  '
  if daemon_validation_result "$invalid_generation"; then
    exit 1
  fi

  printf 'deployment check: partial-generation\n'
  partial_generation="$prefix"-"$number"-partial-generation
  clone_volume "$source_daemon" "$partial_generation"
  mutate_volume "$partial_generation" \
    'rm /state/0123456789abcdef0123456789abcdef/private-manifest'
  if daemon_validation_result "$partial_generation"; then
    exit 1
  fi

  printf 'deployment check: wrong-protected-access\n'
  wrong_access="$prefix"-"$number"-wrong-access
  clone_volume "$source_daemon" "$wrong_access"
  mutate_volume "$wrong_access" '
    chown 0:0 /state/0123456789abcdef0123456789abcdef/capability
    chmod 0644 /state/0123456789abcdef0123456789abcdef/capability
  '
  if daemon_validation_result "$wrong_access"; then
    exit 1
  fi

  printf 'deployment check: restored-milter-state\n'
  restored_milter="$prefix"-"$number"-restored-milter
  clone_volume "$source_milter" "$restored_milter"
  milter_validation_result "$restored_milter" originator

  printf 'deployment check: missing-route-capability\n'
  missing_route_capability="$prefix"-"$number"-missing-route-capability
  clone_volume "$source_milter" "$missing_route_capability"
  mutate_volume "$missing_route_capability" 'rm /state/capability'
  if milter_validation_result "$missing_route_capability" originator; then
    exit 1
  fi

  for volume in \
    "$restored_daemon" "$invalid_generation" "$partial_generation" \
    "$wrong_access" "$restored_milter" "$missing_route_capability"; do
    docker volume rm "$volume" >/dev/null
  done

  candidate=$(GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/candidateid -root ..)
  revision=$(git rev-parse HEAD)
  daemon_subject=$(cat "$work/dkim2d.subject")
  daemon_config=$(cat "$work/dkim2d.config")
  milter_subject=$(cat "$work/dkim2-milter.subject")
  milter_config=$(cat "$work/dkim2-milter.config")
  helper_sha=$(shasum -a 256 "$output_root/deploymentfixture" | cut -d' ' -f1)

  jq -S -n \
    --arg platform "$platform" \
    --arg candidate "$candidate" \
    --arg revision "$revision" \
    --arg daemon_subject "$daemon_subject" \
    --arg daemon_config "$daemon_config" \
    --arg milter_subject "$milter_subject" \
    --arg milter_config "$milter_config" \
    --arg daemon_lifecycle_id "$daemon_image_id" \
    --arg milter_lifecycle_id "$milter_image_id" \
    --arg daemon_upgrade_id "$daemon_upgrade_image_id" \
    --arg milter_upgrade_id "$milter_upgrade_image_id" \
    --arg helper_sha "$helper_sha" \
    '{
      schema:"dkim2.postfix-deployment-report.v1",
      state:"pass",
      platform:$platform,
      candidate_snapshot_sha256:$candidate,
      source_revision:$revision,
      images:{
        dkim2d:{subject_digest:$daemon_subject,config_digest:$daemon_config},
        "dkim2-milter":{subject_digest:$milter_subject,config_digest:$milter_config}
      },
      lifecycle_images:{
        baseline:{
          dkim2d:$daemon_lifecycle_id,
          "dkim2-milter":$milter_lifecycle_id
        },
        upgrade:{
          dkim2d:$daemon_upgrade_id,
          "dkim2-milter":$milter_upgrade_id
        }
      },
      test_helper_sha256:$helper_sha,
      host_ports:0,
      postfix_rootfs:"upstream_entrypoint_writable",
      daemon_http:"canonical_loopback_only",
      milter_transport:"route_separated_owned_unix_sockets",
      postfix_milter_protocol:6,
      postfix_failure_policy:"tempfail",
      transit_listener:"postfix_container_loopback_only",
      cases:[
        "protected_state_validation",
        "smtp_unsigned_inbound_queue_acceptance",
        "local_originator_sign_public_verify",
        "ordinary_transit_revise_chain_public_verify","inbound_process_action",
        "signed_inbound_process_queue",
        "daemon_stopped_tempfail","milter_stopped_tempfail",
        "bounded_overload_tempfail","real_held_queue_persistence",
        "immutable_generation_rotation_rollback",
        "immutable_image_upgrade_rollback",
        "immutable_image_identity_retarget_closed",
        "component_consistent_queue_backup_restore",
        "component_consistent_protected_restore",
        "invalid_generation_closed","partial_generation_closed",
        "wrong_owner_mode_closed","missing_route_capability_closed",
        "old_new_socket_collision_closed",
        "bounded_forced_stop_socket_recovery",
        "route_socket_cleanup_recreation","namespace_isolation",
        "route_minimal_capabilities","bounded_resources","clean_shutdown",
        "seeded_privacy_markers_closed"
      ]
    }' >"$run_root/report.json"

  assert_privacy_markers \
    "$run_root/report.json" \
    "$run_root/inbound-after-rollback.eml" \
    "$work/product-logs-$number.txt"

  compose down --volumes --remove-orphans >/dev/null
  test -z "$(docker ps --all --quiet --filter "label=com.docker.compose.project=$project")"
  test -z "$(docker volume ls --quiet --filter "label=com.docker.compose.project=$project")"
}

run_once 1
run_once 2
cmp "$output_root/run-1/report.json" "$output_root/run-2/report.json"
shasum -a 256 "$output_root/run-1/report.json" |
  cut -d' ' -f1 >"$output_root/report.sha256"
echo "Postfix deployment runtime passed"
