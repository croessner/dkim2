#!/bin/sh
set -eu
umask 077

action=${1:-}
evidence=.artifacts/image-evidence
tools_dir=.artifacts/image-tools
tool_allowlist=build/container/image-tools.json
build_inputs=build/container/build-inputs.json
repository=$(pwd -P)
syft_version=$(jq -er \
  '[.tools[] | select(.name == "syft") | .version] |
    if length == 1 then .[0] else halt_error(1) end' \
  "$tool_allowlist")
trivy_version=$(jq -er \
  '[.tools[] | select(.name == "trivy") | .version] |
    if length == 1 then .[0] else halt_error(1) end' \
  "$tool_allowlist")
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory "$evidence"
work=$(mktemp -d .artifacts/.image-evidence-work.XXXXXX)
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

install_evidence() {
  source=$1
  target=$2
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. \
      -install "$source" -target "$target" -replace
}

subject_for() {
  product=$1
  platform=$2
  jq -er --arg platform "$platform" \
    '.platforms[] | select(.platform == $platform) | .manifest_digest' \
    "$evidence/$product.oci.json"
}

oci_version_for() {
  product=$1
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/imageevidence \
      -root .. -oci-version "$product"
}

ensure_inventory() {
  scripts/inspect-images.sh check
}

candidate_identity() {
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/candidateid -root ..
}

verify_tool() {
  name=$1
  version=$2
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. -file "$tools_dir/$name"
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. -file "$tools_dir/$name.identity.json"
  jq -e --arg name "$name" --arg version "$version" \
    '.schema == "dkim2-image-tool-v1" and .name == $name and .version == $version and
     (.asset | type == "string" and length > 0 and length <= 128) and
     (.archive_sha256 | test("^[0-9a-f]{64}$")) and
     (.binary_sha256 | test("^[0-9a-f]{64}$"))' \
    "$tools_dir/$name.identity.json" >/dev/null
  expected=$(jq -er .binary_sha256 "$tools_dir/$name.identity.json")
  actual=$(shasum -a 256 "$tools_dir/$name" | cut -d' ' -f1)
  test "$actual" = "$expected"
}

prepare_platform_layout() {
  product=$1
  platform=$2
  destination=$3
  archive=".artifacts/$product.oci.tar"
  manifest_digest=$(subject_for "$product" "$platform")
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/ocipolicy \
      -archive "../$archive" \
      -product "$product" \
      -export-platform "$platform" \
      -expected-manifest "$manifest_digest" \
      -export-oci-layout "../$destination"
}

case "$action" in
  sbom)
    ensure_inventory
    verify_tool syft "$syft_version"
    candidate=$(candidate_identity)
    syft_identity=$(jq -c . "$tools_dir/syft.identity.json")
    for product in dkim2d dkim2-milter dkim2ctl; do
      version=$(oci_version_for "$product")
      for architecture in amd64 arm64; do
        platform="linux/$architecture"
        subject=$(subject_for "$product" "$platform")
        layout="$work/$product-$architecture"
        prepare_platform_layout "$product" "$platform" "$layout"
        raw="$work/$product-$architecture.raw.spdx.json"
        output="$work/$product.$architecture.spdx.json"
        binding="$work/$product.$architecture.sbom-binding.json"
        (
          cd "$work"
          env -i \
            HOME="$(pwd -P)" \
            LANG=C \
            LC_ALL=C \
            PATH=/usr/bin:/bin \
            SYFT_CHECK_FOR_APP_UPDATE=false \
            TMPDIR="$(pwd -P)" \
            TZ=UTC \
            "$repository/$tools_dir/syft" "oci-dir:$repository/$layout" \
              --source-name "$product@$subject" \
              --source-version "$version" \
              -o "spdx-json=$repository/$raw"
        )
        namespace="https://github.com/croessner/dkim2/sbom/${subject#sha256:}"
        jq -S --arg namespace "$namespace" \
          '.creationInfo.created = "1970-01-01T00:00:00Z" |
           .documentNamespace = $namespace |
           .packages |= sort_by(.SPDXID) |
           .relationships |= sort_by(.spdxElementId,.relationshipType,.relatedSpdxElement)' \
          "$raw" >"$output"
        jq -e '
          .spdxVersion == "SPDX-2.3" and
          .dataLicense == "CC0-1.0" and
          (.packages | length) >= 1 and
          ([.packages[].licenseConcluded] | all(. != null and . != "")) and
          ([.packages[].licenseDeclared] | all(. != null and . != ""))
        ' "$output" >/dev/null
        sbom_digest=$(shasum -a 256 "$output" | cut -d' ' -f1)
        jq -S -n \
          --arg candidate "$candidate" \
          --arg product "$product" \
          --arg platform "$platform" \
          --arg subject "$subject" \
          --arg sbom "$sbom_digest" \
          --argjson tool "$syft_identity" \
          '{
            schema:"dkim2-image-sbom-binding-v1",
            candidate_snapshot_sha256:$candidate,
            product:$product,
            platform:$platform,
            subject_digest:$subject,
            sbom:{format:"SPDX-2.3",sha256:$sbom},
            tool:$tool
          }' >"$binding"
        install_evidence "$output" "$evidence/$product.$architecture.spdx.json"
        install_evidence "$binding" "$evidence/$product.$architecture.sbom-binding.json"
      done
    done
    ;;
  provenance)
    ensure_inventory
    candidate=$(candidate_identity)
    revision=$(git rev-parse HEAD)
    test "${#revision}" -eq 40
    evidence_class=local-test
    builder_id=local://dkim2/image-evidence
    resolved_build_inputs=$(jq -c '
      [.images[] | {uri:.uri,digest:{sha256:.digest}}]
    ' "$build_inputs")
    for product in dkim2d dkim2-milter dkim2ctl; do
      output="$work/$product.provenance.json"
      index_subject=$(jq -er .subject_digest "$evidence/$product.oci.json")
      amd64_subject=$(subject_for "$product" linux/amd64)
      arm64_subject=$(subject_for "$product" linux/arm64)
      jq -S -n \
        --arg product "$product" \
        --arg index_subject "${index_subject#sha256:}" \
        --arg amd64_subject "${amd64_subject#sha256:}" \
        --arg arm64_subject "${arm64_subject#sha256:}" \
        --arg revision "$revision" \
        --arg candidate "$candidate" \
        --arg evidence_class "$evidence_class" \
        --arg builder_id "$builder_id" \
        --argjson resolved_build_inputs "$resolved_build_inputs" \
        '{
          "_type":"https://in-toto.io/Statement/v1",
          "subject":[{"name":$product,"digest":{"sha256":$index_subject}}],
          "predicateType":"https://slsa.dev/provenance/v1",
          "predicate":{
            "buildDefinition":{
              "buildType":"https://github.com/croessner/dkim2/container-build/v1",
              "externalParameters":{"platforms":["linux/amd64","linux/arm64"]},
              "internalParameters":{
                "candidate_snapshot_sha256":$candidate,
                "evidence_class":$evidence_class,
                "publication_authority":false
              },
              "resolvedDependencies":
                ([{"uri":"git+https://github.com/croessner/dkim2","digest":{"gitCommit":$revision}}] +
                 $resolved_build_inputs)
            },
            "runDetails":{
              "builder":{"id":$builder_id},
              "metadata":{"invocationId":$evidence_class},
              "byproducts":[
                {"name":"linux/amd64","digest":{"sha256":$amd64_subject}},
                {"name":"linux/arm64","digest":{"sha256":$arm64_subject}}
              ]
            }
          }
        }' >"$output"
      install_evidence "$output" "$evidence/$product.provenance.json"
    done
    ;;
  vulnerability)
    ensure_inventory
    verify_tool trivy "$trivy_version"
    candidate=$(candidate_identity)
    trivy_identity=$(jq -c . "$tools_dir/trivy.identity.json")
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/safepath -root .. -directory "$tools_dir/trivy-cache"
    docker_config="$work/docker-config"
    mkdir -m 0700 "$docker_config"
    printf '%s\n' '{"auths":{}}' >"$docker_config/config.json"
    env -i \
      DOCKER_CONFIG="$repository/$docker_config" \
      HOME="$repository/$work" \
      LANG=C \
      LC_ALL=C \
      PATH=/usr/bin:/bin \
      TMPDIR="$repository/$work" \
      TZ=UTC \
      "$repository/$tools_dir/trivy" image \
        --cache-dir "$repository/$tools_dir/trivy-cache" \
        --no-progress --disable-telemetry --skip-version-check \
        --download-db-only
    scan_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/dbguard -root .. \
        -scan-time "$scan_time" -inspect >"$work/trivy-database.json"
    metadata_sha=$(jq -er '.vulnerability_database.files[0].sha256' "$work/trivy-database.json")
    database_content_sha=$(jq -er '.vulnerability_database.files[1].sha256' "$work/trivy-database.json")
    database_schema=$(jq -er '.vulnerability_database.schema_version' "$work/trivy-database.json")
    database_updated=$(jq -er '.vulnerability_database.updated_at' "$work/trivy-database.json")
    database_next=$(jq -er '.vulnerability_database.next_update' "$work/trivy-database.json")
    database_downloaded=$(jq -er '.vulnerability_database.downloaded_at' "$work/trivy-database.json")
    database_scan_time=$(jq -er '.scan_time' "$work/trivy-database.json")
    database_sha=$(shasum -a 256 "$work/trivy-database.json" | cut -d' ' -f1)
    for product in dkim2d dkim2-milter dkim2ctl; do
      for architecture in amd64 arm64; do
        platform="linux/$architecture"
        subject=$(subject_for "$product" "$platform")
        layout="$work/$product-$architecture"
        prepare_platform_layout "$product" "$platform" "$layout"
        raw="$work/$product.$architecture.raw.trivy.json"
        output="$work/$product.$architecture.trivy.json"
        binding="$work/$product.$architecture.trivy-binding.json"
        GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
          go -C tools run ./cmd/dbguard -root .. \
            -scan-time "$scan_time" \
            -input "$layout" \
            -output "$raw" >"$work/database-scan-identity.json"
        cmp "$work/trivy-database.json" "$work/database-scan-identity.json"
        jq -S --arg artifact "$product@$subject" --arg subject "$subject" '
          .CreatedAt = "1970-01-01T00:00:00Z" |
          .ArtifactName = $artifact |
          .ArtifactID = $subject |
          .Results = (
            (.Results // []) |
            sort_by(.Target,.Class,.Type) |
            map(
              .Vulnerabilities = (
                (.Vulnerabilities // []) |
                sort_by(.VulnerabilityID,.PkgName,.InstalledVersion)
              )
            )
          )
        ' "$raw" >"$output"
        if ! jq -e '[.Results[]?.Vulnerabilities[]?] | length == 0' \
          "$output" >/dev/null; then
          jq -r '
            .Results[]?.Vulnerabilities[]? |
            [.VulnerabilityID,.PkgName,.InstalledVersion,.FixedVersion,.Severity] |
            @tsv
          ' "$output" >&2
          exit 1
        fi
        report_sha=$(shasum -a 256 "$output" | cut -d' ' -f1)
        jq -S -n \
          --arg candidate "$candidate" \
          --arg product "$product" \
          --arg platform "$platform" \
          --arg subject "$subject" \
          --arg report "$report_sha" \
          --arg database "$database_sha" \
          --arg database_content "$database_content_sha" \
          --arg database_metadata "$metadata_sha" \
          --argjson database_schema "$database_schema" \
          --arg database_updated "$database_updated" \
          --arg database_next "$database_next" \
          --arg database_downloaded "$database_downloaded" \
          --arg database_scan_time "$database_scan_time" \
          --argjson tool "$trivy_identity" \
          '{
            schema:"dkim2-image-vulnerability-binding-v1",
            candidate_snapshot_sha256:$candidate,
            product:$product,
            platform:$platform,
            subject_digest:$subject,
            report:{format:("trivy-json-" + $tool.version),sha256:$report},
            database:{
              inventory_sha256:$database,
              content_sha256:$database_content,
              metadata_sha256:$database_metadata,
              scan_time:$database_scan_time,
              schema_version:$database_schema,
              updated_at:$database_updated,
              next_update:$database_next,
              downloaded_at:$database_downloaded
            },
            tool:$tool
          }' >"$binding"
        install_evidence "$output" "$evidence/$product.$architecture.trivy.json"
        install_evidence "$binding" "$evidence/$product.$architecture.trivy-binding.json"
      done
    done
    install_evidence "$work/trivy-database.json" "$evidence/trivy-database.json"
    ;;
  check)
    ensure_inventory
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/imageevidence -root ..
    ;;
  *) exit 2 ;;
esac
