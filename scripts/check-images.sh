#!/bin/sh
set -eu

containerfile=build/container/Containerfile
build_inputs=build/container/build-inputs.json
compose=deployments/postfix-compose/compose.yaml
override=deployments/postfix-compose/compose.demo.yaml
export DKIM2_REVISION=0000000000000000000000000000000000000000
export SOURCE_DATE_EPOCH=0
export DKIM2_CREATED=1970-01-01T00:00:00Z

test "$(grep -c '^FROM .* AS dkim2d$' "$containerfile")" -eq 1
test "$(grep -c '^FROM .* AS dkim2-milter$' "$containerfile")" -eq 1
test "$(grep -c '^FROM .* AS dkim2ctl$' "$containerfile")" -eq 1
test "$(grep -c '^FROM .* AS build-metadata$' "$containerfile")" -eq 1
test "$(grep -c '^FROM .* AS build$' "$containerfile")" -eq 1
test "$(grep -c '^COPY --from=build-metadata /validated /validated$' "$containerfile")" -eq 1
test "$(grep -c '^USER 2000:2000$' "$containerfile")" -eq 1
test "$(grep -c '^COPY --from=build /runtime/dkim2d/ /$' "$containerfile")" -eq 1
test "$(grep -c '^COPY --from=build /runtime/dkim2-milter/ /$' "$containerfile")" -eq 1
test "$(grep -c '^COPY --from=build /runtime/dkim2ctl/ /$' "$containerfile")" -eq 1
test "$(grep -c '^COPY cmd/dkim2-exim/go.mod cmd/dkim2-exim/go.sum ./cmd/dkim2-exim/$' "$containerfile")" -eq 1
test "$(grep -c '^!cmd/dkim2-exim/$' .dockerignore)" -eq 1
test "$(grep -c '^!cmd/dkim2-exim/go.mod$' .dockerignore)" -eq 1
test "$(grep -c '^!cmd/dkim2-exim/go.sum$' .dockerignore)" -eq 1
test "$(grep -c 'notices=/out/THIRD_PARTY_NOTICES.txt' "$containerfile")" -eq 1
test "$(grep -c '/usr/local/go/LICENSE /usr/local/go/PATENTS' "$containerfile")" -eq 1
test "$(grep -c 'find vendor -type f' "$containerfile")" -eq 1
test "$(grep -c 'THIRD_PARTY_NOTICES.txt\";' "$containerfile")" -eq 1
! grep -Eq '^COPY --from=build .* /usr/local/bin/' "$containerfile"
! grep -q '^ARG GO_IMAGE' "$containerfile"
grep -q 'org.opencontainers.image.created="${CREATED}"' "$containerfile"
! grep -q 'org.opencontainers.image.created="${SOURCE_DATE_EPOCH}"' "$containerfile"
! grep -Eq '^FROM [^#]*:(latest|[^ @]+)( |$)' "$containerfile"
! grep -Eq '(^|[[:space:]])(apk|apt|yum|dnf|curl|wget|git)[[:space:]]' "$containerfile"
! grep -Eq 'ENTRYPOINT[[:space:]]+[^\[]' "$containerfile"
metadata_stage_line=$(grep -n '^FROM .* AS build-metadata$' "$containerfile" |
  cut -d: -f1)
metadata_validation_line=$(grep -n '^RUN case "${VERSION}" in \\$' "$containerfile" |
  cut -d: -f1)
build_stage_line=$(grep -n '^FROM .* AS build$' "$containerfile" |
  cut -d: -f1)
validation_copy_line=$(grep -n \
  '^COPY --from=build-metadata /validated /validated$' "$containerfile" |
  cut -d: -f1)
source_copy_line=$(grep -n '^COPY go.work go.work.sum ./$' "$containerfile" |
  cut -d: -f1)
test "$metadata_stage_line" -lt "$metadata_validation_line"
test "$metadata_validation_line" -lt "$build_stage_line"
test "$build_stage_line" -lt "$validation_copy_line"
test "$validation_copy_line" -lt "$source_copy_line"
busybox_reference=$(jq -er \
  '.images[] | select(.name == "metadata-validator") |
   (.reference + "@sha256:" + .digest)' "$build_inputs")
go_reference=$(jq -er \
  '.images[] | select(.name == "go-builder") |
   (.reference + "@sha256:" + .digest)' "$build_inputs")
buildkit_reference=$(jq -er \
  '.images[] | select(.name == "buildkit") |
   (.reference + "@sha256:" + .digest)' "$build_inputs")
build_platform='$BUILDPLATFORM'
test "$(grep -Fxc \
  "FROM --platform=$build_platform $busybox_reference AS build-metadata" \
  "$containerfile")" -eq 1
test "$(grep -Fxc \
  "FROM --platform=$build_platform $go_reference AS build" \
  "$containerfile")" -eq 1
test "$buildkit_reference" = \
  "moby/buildkit:buildx-stable-1@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
jq -e '
  . == {
    schema:"dkim2-container-build-inputs-v1",
    images:[
      {
        name:"metadata-validator",
        uri:"docker-image://docker.io/library/busybox",
        reference:"busybox:1.37.0",
        digest:"9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028",
        purpose:"build-only metadata validation"
      },
      {
        name:"go-builder",
        uri:"docker-image://docker.io/library/golang",
        reference:"golang:1.26.5-bookworm",
        digest:"1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651",
        purpose:"build-only Go compilation"
      },
      {
        name:"buildkit",
        uri:"docker-image://moby/buildkit",
        reference:"moby/buildkit:buildx-stable-1",
        digest:"0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f",
        purpose:"isolated BuildKit executor"
      }
    ]
  }
' "$build_inputs" >/dev/null
grep -q '^\*\*$' .dockerignore
for forbidden in .git temp .artifacts .idea; do
  ! grep -q "^!$forbidden" .dockerignore
done

render=$(mktemp)
trap 'rm -f "$render"' EXIT HUP INT TERM
docker compose -f "$compose" config --format json >"$render"
jq -e '
  . as $root |
  ([$root.services[] | (.ports // [])[]] | length == 0) and
  all($root.services[];
    (.privileged // false) == false and
    (.cap_drop == ["ALL"]) and
    (.security_opt | index("no-new-privileges:true")) != null and
    (.network_mode // "") != "host") and
  ($root.services.postfix.read_only // false) == false and
  all($root.services | to_entries[] | select(.key != "postfix");
    .value.read_only == true) and
  $root.services["milter-inbound"].user == "2000:103" and
  $root.services["milter-originator"].user == "2000:103" and
  $root.services["milter-transit"].user == "2000:103" and
  $root.services.postfix.group_add == ["103"] and
  $root.services["milter-inbound"].network_mode == "service:daemon-inbound" and
  $root.services["milter-originator"].network_mode == "service:daemon-originator" and
  $root.services["milter-transit"].network_mode == "service:daemon-transit" and
  all(["inbound","originator","transit"][] as $route |
    ($root.services["milter-" + $route].healthcheck.test |
      . == ["CMD","/usr/local/bin/dkim2-milter","probe","--config",
        ("/etc/dkim2-milter/" + $route + ".yaml")]) and
    ([$root.services["milter-" + $route].volumes[] |
      select(.target == "/etc/dkim2-milter") | .source] as $mounts |
      ($mounts | length == 1) and
      ($mounts[0] | endswith("/deployments/postfix-compose/state/milter/" + $route))) and
    ([$root.services["daemon-" + $route].volumes[] |
      select(.target == "/var/lib/dkim2d") | .source] as $mounts |
      ($mounts | length == 1) and
      ($mounts[0] | endswith("/deployments/postfix-compose/state/daemon/" + $route))))
' "$render" >/dev/null
docker compose -f "$compose" -f "$override" config --format json >"$render"
jq -e '
  . as $root |
  [$root.services[] | (.ports // [])[]] as $ports |
  ($ports | length) == 1 and
  $ports[0].host_ip == "127.0.0.1" and
  $ports[0].published == "2525" and
  $ports[0].target == 25
' "$render" >/dev/null

test "$(grep -Ec 'uses: [^@[:space:]]+@[0-9a-f]{40}([[:space:]]+#.*)?$' .github/workflows/container-release.yml)" -ge 3
! grep -Eq 'uses: [^@[:space:]]+@(main|master|v[0-9]+([.]|$))' .github/workflows/container-release.yml
grep -Fq 'go-version: "1.26.5"' .github/workflows/container-release.yml
grep -Fq 'run: make check-container-release' .github/workflows/container-release.yml
! grep -Eq '(id-token|packages):[[:space:]]*write' .github/workflows/container-release.yml
! grep -Eq 'provenance-ci|trusted-ci-build' \
  .github/workflows/container-release.yml scripts/image-evidence.sh
grep -Fq '"$repository/$tools_dir/trivy" image \' scripts/image-evidence.sh
grep -Fq -- '--cache-dir "$repository/$tools_dir/trivy-cache" \' \
  scripts/image-evidence.sh
grep -Fq 'DOCKER_CONFIG="$repository/$docker_config" \' \
  scripts/image-evidence.sh
grep -Fq 'HOME="$repository/$work" \' scripts/image-evidence.sh
grep -Fq 'TMPDIR="$repository/$work" \' scripts/image-evidence.sh
jq -e '
  .schema == "dkim2-image-tool-allowlist-v1" and
  [.tools[].name] == ["syft","trivy"] and
  [.tools[].version] == ["1.46.0","0.72.0"] and
  all(.tools[];
    [.platforms[] | (.goos + "/" + .goarch)] ==
      ["darwin/amd64","darwin/arm64","linux/amd64","linux/arm64"] and
    all(.platforms[];
      (.asset | type == "string" and length > 0 and length <= 128) and
      (.archive_sha256 | test("^[0-9a-f]{64}$")) and
      (.binary_sha256 | test("^[0-9a-f]{64}$"))))
' build/container/image-tools.json >/dev/null
