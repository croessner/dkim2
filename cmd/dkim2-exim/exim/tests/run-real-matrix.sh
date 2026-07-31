#!/usr/bin/env bash
# Verifies one fresh, fixture-bound real Exim matrix execution.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd -P)
fixtures="$repository_root/cmd/dkim2-exim/exim/fixtures"
evidence_root=${DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT:-}
expected_run_id=${DKIM2_EXIM_REAL_MATRIX_RUN_ID:-}
expected_adapter_sha256=${DKIM2_EXIM_REAL_MATRIX_ADAPTER_SHA256:-}
expected_daemon_sha256=${DKIM2_EXIM_REAL_MATRIX_DAEMON_SHA256:-}
# shellcheck disable=SC1090,SC1091
source "$script_dir/real-matrix-contract.sh"

# fail emits one content-free matrix verification failure.
fail() {
  printf 'real Exim matrix verification failed: %s\n' "$1" >&2
  exit 1
}

# require_regular_file accepts only one non-empty direct evidence file.
require_regular_file() {
  local path=$1
  [[ ! -L $path && -f $path && -s $path ]] ||
    fail "required evidence is not one non-empty regular file"
}

# require_exact_line proves one fixture-derived field without accepting aliases.
require_exact_line() {
  local path=$1 line=$2
  grep -Fqx -- "$line" "$path" ||
    fail "evidence value does not match its authenticated fixture"
}

# manifest_value returns one unique non-empty key from an exact record.
manifest_value() {
  local path=$1 key=$2 value
  value=$(awk -F= -v key="$key" \
    '$1 == key { count++; value = substr($0, length(key) + 2) }
     END { if (count == 1) print value }' "$path")
  [[ -n $value ]] || fail "evidence has a missing or duplicate field"
  printf '%s\n' "$value"
}

# sha256_file computes one portable lowercase SHA-256 digest.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

# go_binary returns the container-pinned toolchain or the host Go executable.
go_binary() {
  if [[ -x /usr/local/go/bin/go ]]; then
    printf '%s\n' /usr/local/go/bin/go
    return
  fi
  command -v go || fail "Go toolchain is unavailable"
}

# validate_timestamp accepts only bounded second-resolution UTC timestamps.
validate_timestamp() {
  [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
    fail "evidence timestamp is not bounded UTC"
}

# validate_live_observation enforces exact case-specific transcript semantics.
validate_live_observation() {
  local category=$1 logical_case=$2 component=$3 observation=$4
  local first second
  case "$category:$logical_case:$component" in
    smtp:lf:exim)
      [[ $observation =~ ^smtp-final-250,deliveries-1,stable-input-sha256-([0-9a-f]{64}),stable-output-sha256-([0-9a-f]{64}),lf-count-([1-9][0-9]*),crlf-count-0$ ]] ||
        fail "LF observation is not exact"
      [[ ${BASH_REMATCH[1]} == "${BASH_REMATCH[2]}" ]] ||
        fail "LF observation did not preserve exact bytes"
      ;;
    smtp:crlf:exim)
      [[ $observation =~ ^smtp-final-250,deliveries-1,stable-input-sha256-([0-9a-f]{64}),stable-output-sha256-([0-9a-f]{64}),crlf-count-([1-9][0-9]*),bare-lf-count-0$ ]] ||
        fail "CRLF observation is not exact"
      [[ ${BASH_REMATCH[1]} == "${BASH_REMATCH[2]}" ]] ||
        fail "CRLF observation did not preserve exact bytes"
      ;;
    smtp:duplicate-folded:exim)
      [[ $observation =~ ^smtp-final-250,deliveries-1,header-order-sha256-[0-9a-f]{64},duplicate-count-2,folded-count-1$ ]] ||
        fail "duplicate/folded observation is not exact"
      ;;
    smtp:binary-body:exim)
      [[ $observation =~ ^smtp-final-250,deliveries-1,body-input-sha256-([0-9a-f]{64}),body-output-sha256-([0-9a-f]{64}),nul-count-([1-9][0-9]*)$ ]] ||
        fail "binary-body observation is not exact"
      [[ ${BASH_REMATCH[1]} == "${BASH_REMATCH[2]}" ]] ||
        fail "binary-body observation did not preserve exact bytes"
      ;;
    smtp:smtputf8-rfc6532:exim)
      [[ $observation =~ ^smtp-final-250,deliveries-1,stable-input-sha256-([0-9a-f]{64}),stable-output-sha256-([0-9a-f]{64}),nonascii-octets-([1-9][0-9]*)$ ]] ||
        fail "SMTPUTF8 observation is not exact"
      [[ ${BASH_REMATCH[1]} == "${BASH_REMATCH[2]}" ]] ||
        fail "SMTPUTF8 observation did not preserve exact bytes"
      ;;
    smtp:forged-authentication-results:adapter)
      [[ $observation =~ ^operation-process,incoming-local-claims-([1-9][0-9]*),removed-local-claims-([1-9][0-9]*),generated-top-1,header-order-sha256-[0-9a-f]{64}$ ]] ||
        fail "Authentication-Results observation is not exact"
      [[ ${BASH_REMATCH[1]} == "${BASH_REMATCH[2]}" ]] ||
        fail "Authentication-Results removal count is incomplete"
      ;;
    smtp:incoming-outgoing-envelope:adapter)
      [[ $observation =~ ^operation-process-revise,invocation-sha256-[0-9a-f]{64},incoming-envelope-sha256-([0-9a-f]{64}),outgoing-envelope-sha256-([0-9a-f]{64}),envelopes-distinct-1$ ]] ||
        fail "adapter envelope observation is not exact"
      [[ ${BASH_REMATCH[1]} != "${BASH_REMATCH[2]}" ]] ||
        fail "adapter incoming and outgoing envelopes alias"
      ;;
    smtp:incoming-outgoing-envelope:dkim2d)
      [[ $observation =~ ^route-process-revise,http-2xx-2,invocation-sha256-[0-9a-f]{64},incoming-envelope-sha256-([0-9a-f]{64}),outgoing-envelope-sha256-([0-9a-f]{64})$ ]] ||
        fail "daemon envelope observation is not exact"
      [[ ${BASH_REMATCH[1]} != "${BASH_REMATCH[2]}" ]] ||
        fail "daemon incoming and outgoing envelopes alias"
      ;;
    transport-filter:sign:exim | transport-filter:revise:exim)
      [[ $observation =~ ^transport-exit-0,deliveries-1,invocation-sha256-[0-9a-f]{64},authorized-fields-sha256-[0-9a-f]{64},output-sha256-[0-9a-f]{64},header-order-sha256-[0-9a-f]{64}$ ]] ||
        fail "Exim signing observation is not exact"
      ;;
    transport-filter:sign:adapter)
      [[ $observation =~ ^operation-sign,result-pass,invocation-sha256-[0-9a-f]{64},request-sha256-[0-9a-f]{64},response-sha256-[0-9a-f]{64},action-plan-sha256-[0-9a-f]{64},authorized-fields-sha256-[0-9a-f]{64},actions-2,action-order-message-instance-dkim2-signature,output-sha256-[0-9a-f]{64},header-order-sha256-[0-9a-f]{64}$ ]] ||
        fail "adapter signing observation is not exact"
      ;;
    transport-filter:revise:adapter)
      [[ $observation =~ ^operation-revise,result-pass,invocation-sha256-[0-9a-f]{64},request-sha256-[0-9a-f]{64},response-sha256-[0-9a-f]{64},action-plan-sha256-[0-9a-f]{64},authorized-fields-sha256-[0-9a-f]{64},actions-1,action-order-dkim2-signature,output-sha256-[0-9a-f]{64},header-order-sha256-[0-9a-f]{64}$ ]] ||
        fail "hash-unchanged revise observation is not exact"
      ;;
    transport-filter:sign:dkim2d)
      [[ $observation =~ ^route-sign,http-2xx-1,result-pass,invocation-sha256-[0-9a-f]{64},request-sha256-([0-9a-f]{64}),response-sha256-([0-9a-f]{64}),action-plan-sha256-[0-9a-f]{64},authorized-fields-sha256-[0-9a-f]{64},actions-2$ ]] ||
        fail "daemon signing observation is not exact"
      first=${BASH_REMATCH[1]}
      second=${BASH_REMATCH[2]}
      [[ $first != "$second" ]] || fail "daemon signing transcript aliases request and response"
      ;;
    transport-filter:revise:dkim2d)
      [[ $observation =~ ^route-revise,http-2xx-1,result-pass,invocation-sha256-[0-9a-f]{64},request-sha256-([0-9a-f]{64}),response-sha256-([0-9a-f]{64}),action-plan-sha256-[0-9a-f]{64},authorized-fields-sha256-[0-9a-f]{64},actions-1$ ]] ||
        fail "hash-unchanged revise daemon observation is not exact"
      first=${BASH_REMATCH[1]}
      second=${BASH_REMATCH[2]}
      [[ $first != "$second" ]] || fail "revise transcript aliases request and response"
      ;;
    transport-filter:bcc-safe:exim)
      [[ $observation =~ ^transport-exit-0,deliveries-1,invocation-sha256-[0-9a-f]{64},recipient-count-1,pipe-argv-count-1,bcc-marker-count-0,output-sha256-[0-9a-f]{64}$ ]] ||
        fail "Bcc-safe Exim observation is not exact"
      ;;
    transport-filter:bcc-safe:adapter)
      [[ $observation =~ ^operation-revise,result-pass,invocation-sha256-[0-9a-f]{64},recipient-count-1,pipe-argv-count-1,bcc-marker-count-0,output-sha256-[0-9a-f]{64}$ ]] ||
        fail "Bcc-safe observation is not exact"
      ;;
    transport-filter:bcc-safe:dkim2d)
      [[ $observation =~ ^route-revise,http-2xx-1,result-pass,invocation-sha256-[0-9a-f]{64},recipient-count-1,request-sha256-[0-9a-f]{64},response-sha256-[0-9a-f]{64}$ ]] ||
        fail "Bcc-safe daemon observation is not exact"
      ;;
    *)
      fail "live observation has no semantic validator"
      ;;
  esac
}

# observation_token_value returns one unique key suffix from a transcript.
observation_token_value() {
  local observation=$1 key=$2 token value='' count=0
  local -a tokens
  IFS=',' read -r -a tokens <<<"$observation"
  for token in "${tokens[@]}"; do
    if [[ $token == "$key-"* ]]; then
      value=${token#"$key-"}
      count=$((count + 1))
    fi
  done
  [[ $count -eq 1 && -n $value ]] ||
    fail "cross-component observation token is missing or duplicated"
  printf '%s\n' "$value"
}

# validate_cross_component_observations binds one live flow across its owners.
validate_cross_component_observations() {
  local category=$1 logical_case=$2 exim=$3 adapter=$4 dkim2d=$5
  local key exim_value adapter_value daemon_value
  case "$category:$logical_case" in
    smtp:incoming-outgoing-envelope)
      for key in invocation-sha256 incoming-envelope-sha256 \
        outgoing-envelope-sha256; do
        adapter_value=$(observation_token_value "$adapter" "$key")
        daemon_value=$(observation_token_value "$dkim2d" "$key")
        [[ $adapter_value == "$daemon_value" ]] ||
          fail "envelope flow is inconsistent across adapter and daemon"
      done
      ;;
    transport-filter:sign | transport-filter:revise)
      for key in invocation-sha256 authorized-fields-sha256 output-sha256 \
        header-order-sha256; do
        exim_value=$(observation_token_value "$exim" "$key")
        adapter_value=$(observation_token_value "$adapter" "$key")
        [[ $exim_value == "$adapter_value" ]] ||
          fail "signing output is inconsistent across Exim and adapter"
      done
      for key in invocation-sha256 request-sha256 response-sha256 \
        action-plan-sha256 authorized-fields-sha256; do
        adapter_value=$(observation_token_value "$adapter" "$key")
        daemon_value=$(observation_token_value "$dkim2d" "$key")
        [[ $adapter_value == "$daemon_value" ]] ||
          fail "signing authority is inconsistent across adapter and daemon"
      done
      ;;
    transport-filter:bcc-safe)
      for key in invocation-sha256 output-sha256 recipient-count \
        pipe-argv-count bcc-marker-count; do
        exim_value=$(observation_token_value "$exim" "$key")
        adapter_value=$(observation_token_value "$adapter" "$key")
        [[ $exim_value == "$adapter_value" ]] ||
          fail "Bcc flow is inconsistent across Exim and adapter"
      done
      exim_value=$(observation_token_value "$exim" invocation-sha256)
      daemon_value=$(observation_token_value "$dkim2d" invocation-sha256)
      [[ $exim_value == "$daemon_value" ]] ||
        fail "Bcc flow is inconsistent across Exim and daemon"
      adapter_value=$(observation_token_value "$adapter" recipient-count)
      daemon_value=$(observation_token_value "$dkim2d" recipient-count)
      [[ $adapter_value == "$daemon_value" ]] ||
        fail "Bcc recipient cardinality is inconsistent"
      ;;
  esac
}

# validate_exact_grammar proves ordered unique keys and non-empty values.
validate_exact_grammar() {
  local path=$1
  shift
  local expected_count=$#
  [[ $(wc -l <"$path" | tr -d ' ') == "$expected_count" ]] ||
    fail "evidence record does not have the exact line count"
  awk -v expected="$expected_count" -v keys="$*" '
    BEGIN { split(keys, ordered, " ") }
    {
      separator = index($0, "=")
      if (separator < 2 || substr($0, 1, separator - 1) != ordered[NR]) exit 1
      if (substr($0, separator + 1) == "") exit 1
    }
    END { if (NR != expected) exit 1 }
  ' "$path" || fail "evidence record grammar is not exact"
}

mapfile -t rows < <(real_matrix_rows)

# expected_case_inventory emits the only permitted case-evidence names.
expected_case_inventory() {
  local category name
  for category in smtp local-submission transport-filter; do
    while IFS= read -r name; do
      printf '%s--%s.case\n' "$category" "$name"
    done < <(real_matrix_cases "$category")
  done
}

# expected_artifact_inventory emits every required case-component artifact name.
expected_artifact_inventory() {
  local case_name component stem
  while IFS= read -r case_name; do
    stem=${case_name%.case}
    while IFS= read -r component; do
      printf '%s--%s.artifact\n' "$stem" "$component"
    done < <(real_matrix_components)
  done < <(expected_case_inventory)
}

# expected_transcript_inventory emits every required sanitized transcript name.
expected_transcript_inventory() {
  local artifact_name
  while IFS= read -r artifact_name; do
    printf '%s.transcript\n' "${artifact_name%.artifact}"
  done < <(expected_artifact_inventory)
}

# expected_row_readback_inventory emits the retained deployment readback names.
expected_row_readback_inventory() {
  printf '%s\n' \
    version.readback \
    exim-user.readback \
    exim-group.readback \
    spool-wireformat.readback \
    local-scan.readback \
    sign-transport.readback \
    revise-transport.readback
}

[[ -n $evidence_root && $evidence_root == /* ]] ||
  fail "DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT must be absolute"
[[ -n $expected_run_id && $expected_run_id =~ ^[0-9a-f]{64}$ ]] ||
  fail "DKIM2_EXIM_REAL_MATRIX_RUN_ID must be one lowercase SHA-256 value"
[[ $expected_adapter_sha256 =~ ^[0-9a-f]{64}$ ]] ||
  fail "DKIM2_EXIM_REAL_MATRIX_ADAPTER_SHA256 must be one lowercase SHA-256 value"
[[ $expected_daemon_sha256 =~ ^[0-9a-f]{64}$ ]] ||
  fail "DKIM2_EXIM_REAL_MATRIX_DAEMON_SHA256 must be one lowercase SHA-256 value"
[[ ! -L $evidence_root && -d $evidence_root ]] ||
  fail "evidence root must be one non-symlink directory"

run_manifest="$evidence_root/run-v1.txt"
require_regular_file "$run_manifest"
validate_exact_grammar "$run_manifest" \
  format run_id base_revision candidate_snapshot_sha256 matrix_helper_sha256 created_at
require_exact_line "$run_manifest" 'format=dkim2-exim-real-matrix-run-v1'
require_exact_line "$run_manifest" "run_id=$expected_run_id"

candidate_base_revision=$(git -C "$repository_root" rev-parse HEAD)
candidate_snapshot_sha256=$(
  "$(go_binary)" -C "$repository_root/tools" run ./cmd/candidateid -root ..
)
[[ $candidate_base_revision =~ ^[0-9a-f]{40}$ &&
  $candidate_snapshot_sha256 =~ ^[0-9a-f]{64}$ ]] ||
  fail "candidate identity is unavailable"
require_exact_line "$run_manifest" "base_revision=$candidate_base_revision"
require_exact_line "$run_manifest" \
  "candidate_snapshot_sha256=$candidate_snapshot_sha256"

module_sha256=$(sha256_file \
  "$repository_root/cmd/dkim2-exim/exim/dkim2_local_scan.c")
transport_filter_patch_sha256=$(sha256_file \
  "$repository_root/cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch")
runner_sha256=$(sha256_file "$script_dir/execute-real-matrix-linux.sh")
matrix_helper_sha256=$(sha256_file "$script_dir/real_matrix_service.py")
deployment_validator_sha256=$(sha256_file \
  "$repository_root/cmd/dkim2-exim/packaging/validate-deployment.sh")
require_exact_line "$run_manifest" \
  "matrix_helper_sha256=$matrix_helper_sha256"
created_at=$(manifest_value "$run_manifest" created_at)
validate_timestamp "$created_at"
expected_cases=$(expected_case_inventory | sort)
expected_case_count=$(expected_case_inventory | wc -l | tr -d ' ')

for row in "${rows[@]}"; do
  fixture="$fixtures/$row"
  source_manifest="$fixture/source-manifest-v1.txt"
  compatibility_manifest="$fixture/compatibility-manifest-v1.txt"
  require_regular_file "$source_manifest"
  require_regular_file "$compatibility_manifest"
  row_directory="$evidence_root/$row"
  [[ ! -L $row_directory && -d $row_directory ]] ||
    fail "row evidence directory is missing or a symlink"
  result="$row_directory/result-v1.txt"
  require_regular_file "$result"
  validate_exact_grammar "$result" \
    format row exim_version build_id source_manifest_sha256 \
    compatibility_manifest_sha256 module_sha256 transport_filter_patch_sha256 binary_sha256 \
    adapter_sha256 daemon_sha256 runner_sha256 matrix_helper_sha256 \
    deployment_validator_sha256 version_readback_sha256 exim_user_readback_sha256 \
    exim_group_readback_sha256 spool_wireformat_readback_sha256 \
    local_scan_readback_sha256 sign_transport_readback_sha256 \
    revise_transport_readback_sha256 run_id started_at finished_at \
    case_count privacy_scan status

  version=$(manifest_value "$compatibility_manifest" exim_version)
  build_id=$(manifest_value "$compatibility_manifest" build_id)
  source_hash=$(sha256_file "$source_manifest")
  compatibility_hash=$(sha256_file "$compatibility_manifest")
  binary_hash=$(manifest_value "$result" binary_sha256)
  started_at=$(manifest_value "$result" started_at)
  finished_at=$(manifest_value "$result" finished_at)
  validate_timestamp "$started_at"
  validate_timestamp "$finished_at"
  [[ $created_at < $started_at || $created_at == "$started_at" ]] ||
    fail "row result predates its run manifest"
  [[ $started_at < $finished_at || $started_at == "$finished_at" ]] ||
    fail "row result time interval is reversed"
  [[ $binary_hash =~ ^[0-9a-f]{64}$ ]] ||
    fail "row binary digest is not canonical"
  for hash_key in transport_filter_patch_sha256 adapter_sha256 daemon_sha256 runner_sha256 \
    matrix_helper_sha256 \
    deployment_validator_sha256 version_readback_sha256 \
    exim_user_readback_sha256 \
    exim_group_readback_sha256 spool_wireformat_readback_sha256 \
    local_scan_readback_sha256 sign_transport_readback_sha256 \
    revise_transport_readback_sha256; do
    [[ $(manifest_value "$result" "$hash_key") =~ ^[0-9a-f]{64}$ ]] ||
      fail "row readback digest is not canonical"
  done
  declare -A readback_files=(
    [version_readback_sha256]=version.readback
    [exim_user_readback_sha256]=exim-user.readback
    [exim_group_readback_sha256]=exim-group.readback
    [spool_wireformat_readback_sha256]=spool-wireformat.readback
    [local_scan_readback_sha256]=local-scan.readback
    [sign_transport_readback_sha256]=sign-transport.readback
    [revise_transport_readback_sha256]=revise-transport.readback
  )
  declare -A readback_observations=(
    [version_readback_sha256]="exim-version-$version"
    [exim_user_readback_sha256]=exim-user-Debian-exim
    [exim_group_readback_sha256]=exim-group-Debian-exim
    [spool_wireformat_readback_sha256]=spool-wireformat-false
    [local_scan_readback_sha256]="local-scan-build-id-$build_id"
    [sign_transport_readback_sha256]=sign-transport-validator-pass
    [revise_transport_readback_sha256]=revise-transport-validator-pass
  )
  for hash_key in "${!readback_files[@]}"; do
    readback_path="$row_directory/${readback_files[$hash_key]}"
    require_regular_file "$readback_path"
    validate_exact_grammar "$readback_path" observation
    require_exact_line "$readback_path" \
      "observation=${readback_observations[$hash_key]}"
    result_readback_hash=$(manifest_value "$result" "$hash_key")
    retained_readback_hash=$(sha256_file "$readback_path")
    [[ $result_readback_hash == "$retained_readback_hash" ]] ||
      fail "row readback digest does not match its retained transcript"
  done

  require_exact_line "$result" 'format=dkim2-exim-real-matrix-result-v1'
  require_exact_line "$result" "row=$row"
  require_exact_line "$result" "exim_version=$version"
  require_exact_line "$result" "build_id=$build_id"
  require_exact_line "$result" "source_manifest_sha256=$source_hash"
  require_exact_line "$result" "compatibility_manifest_sha256=$compatibility_hash"
  require_exact_line "$result" "module_sha256=$module_sha256"
  require_exact_line "$result" \
    "transport_filter_patch_sha256=$transport_filter_patch_sha256"
  require_exact_line "$result" "adapter_sha256=$expected_adapter_sha256"
  require_exact_line "$result" "daemon_sha256=$expected_daemon_sha256"
  require_exact_line "$result" "runner_sha256=$runner_sha256"
  require_exact_line "$result" "matrix_helper_sha256=$matrix_helper_sha256"
  require_exact_line "$result" \
    "deployment_validator_sha256=$deployment_validator_sha256"
  require_exact_line "$result" "run_id=$expected_run_id"
  require_exact_line "$result" "case_count=$expected_case_count"
  require_exact_line "$result" 'privacy_scan=passed'
  require_exact_line "$result" 'status=passed'

  actual_cases=$(
    find "$row_directory" -mindepth 1 -maxdepth 1 -name '*.case' \
      -exec basename {} \; | sort
  )
  [[ $actual_cases == "$expected_cases" ]] ||
    fail "row case inventory is not exact"
  expected_artifacts=$(expected_artifact_inventory | sort)
  actual_artifacts=$(
    find "$row_directory" -mindepth 1 -maxdepth 1 -name '*.artifact' \
      -exec basename {} \; | sort
  )
  [[ $actual_artifacts == "$expected_artifacts" ]] ||
    fail "row live artifact inventory is not exact"
  expected_transcripts=$(expected_transcript_inventory | sort)
  actual_transcripts=$(
    find "$row_directory" -mindepth 1 -maxdepth 1 -name '*.transcript' \
      -exec basename {} \; | sort
  )
  [[ $actual_transcripts == "$expected_transcripts" ]] ||
    fail "row sanitized transcript inventory is not exact"
  row_entries=$(
    find "$row_directory" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort
  )
  expected_row_entries=$(
    printf '%s\n%s\n%s\n%s\n%s\n' \
      result-v1.txt "$expected_cases" "$expected_artifacts" \
      "$expected_transcripts" "$(expected_row_readback_inventory)" | sort
  )
  [[ $row_entries == "$expected_row_entries" ]] ||
    fail "row evidence inventory is not exact"

  while IFS= read -r case_name; do
    case_path="$row_directory/$case_name"
    require_regular_file "$case_path"
    validate_exact_grammar "$case_path" \
      format row category case exim_version build_id binary_sha256 run_id \
      invocation_sha256 started_at finished_at exim_artifact_sha256 \
      adapter_artifact_sha256 dkim2d_artifact_sha256 fault_artifact_sha256 \
      readback_artifact_sha256 proof status
    category=${case_name%%--*}
    logical_case=${case_name#*--}
    logical_case=${logical_case%.case}
    case_started=$(manifest_value "$case_path" started_at)
    case_finished=$(manifest_value "$case_path" finished_at)
    case_invocation=$(manifest_value "$case_path" invocation_sha256)
    [[ $case_invocation =~ ^[0-9a-f]{64}$ ]] ||
      fail "case invocation identifier is not canonical"
    validate_timestamp "$case_started"
    validate_timestamp "$case_finished"
    [[ $started_at < $case_started || $started_at == "$case_started" ]] ||
      fail "case evidence predates its row"
    [[ $case_started < $case_finished || $case_started == "$case_finished" ]] ||
      fail "case evidence interval is reversed"
    [[ $case_finished < $finished_at || $case_finished == "$finished_at" ]] ||
      fail "case evidence postdates its row"
    contract=$(real_matrix_expected_contract "$category" "$logical_case") ||
      fail "case has no proof contract"
    read -r expected_proof expected_exim expected_adapter expected_dkim2d \
      expected_fault expected_readback <<<"$contract"
    proof=$(manifest_value "$case_path" proof)
    [[ $proof == "$expected_proof" ]] ||
      fail "case proof class does not match its exact contract"
    declare -A case_observations=()
    for component in exim adapter dkim2d fault readback; do
      artifact_path="$row_directory/${case_name%.case}--$component.artifact"
      require_regular_file "$artifact_path"
      validate_exact_grammar "$artifact_path" \
        format row category case component assertion producer_sha256 \
        transcript_sha256 run_id invocation_sha256 started_at finished_at \
        privacy_scan status
      artifact_started=$(manifest_value "$artifact_path" started_at)
      artifact_finished=$(manifest_value "$artifact_path" finished_at)
      validate_timestamp "$artifact_started"
      validate_timestamp "$artifact_finished"
      [[ $case_started < $artifact_started ||
        $case_started == "$artifact_started" ]] ||
        fail "live artifact predates its case"
      [[ $artifact_started < $artifact_finished ||
        $artifact_started == "$artifact_finished" ]] ||
        fail "live artifact time interval is reversed"
      [[ $artifact_finished < $case_finished ||
        $artifact_finished == "$case_finished" ]] ||
        fail "live artifact postdates its case"
      case "$component" in
        exim)
          expected_assertion=$expected_exim
          expected_producer=$binary_hash
          ;;
        adapter)
          expected_assertion=$expected_adapter
          expected_producer=$expected_adapter_sha256
          ;;
        dkim2d)
          expected_assertion=$expected_dkim2d
          expected_producer=$expected_daemon_sha256
          ;;
        fault)
          expected_assertion=$expected_fault
          expected_producer=$runner_sha256
          ;;
        readback)
          expected_assertion=$expected_readback
          expected_producer=$deployment_validator_sha256
          ;;
      esac
      transcript_path="$row_directory/${case_name%.case}--$component.transcript"
      require_regular_file "$transcript_path"
      validate_exact_grammar "$transcript_path" observation
      transcript_hash=$(sha256_file "$transcript_path")
      artifact_transcript_hash=$(
        manifest_value "$artifact_path" transcript_sha256
      )
      [[ $artifact_transcript_hash == "$transcript_hash" ]] ||
        fail "sanitized transcript digest does not match its artifact"
      observation=$(manifest_value "$transcript_path" observation)
      case_observations[$component]=$observation
      [[ ${#observation} -le 1024 &&
        $observation =~ ^[a-z0-9][a-z0-9._,:+-]*$ ]] ||
        fail "live artifact observation is outside the sanitized vocabulary"
      if real_matrix_observation_has_live_values \
        "$category" "$logical_case" "$component"; then
        validate_live_observation \
          "$category" "$logical_case" "$component" "$observation"
      else
        expected_observation=$(
          real_matrix_expected_observation \
            "$category" "$logical_case" "$component"
        ) || fail "case component has no live observation contract"
        [[ $observation == "$expected_observation" ]] ||
          fail "live artifact observation does not match its exact case contract"
      fi
      require_exact_line "$artifact_path" \
        'format=dkim2-exim-real-artifact-v1'
      require_exact_line "$artifact_path" "row=$row"
      require_exact_line "$artifact_path" "category=$category"
      require_exact_line "$artifact_path" "case=$logical_case"
      require_exact_line "$artifact_path" "component=$component"
      require_exact_line "$artifact_path" "assertion=$expected_assertion"
      require_exact_line "$artifact_path" "producer_sha256=$expected_producer"
      require_exact_line "$artifact_path" "run_id=$expected_run_id"
      require_exact_line "$artifact_path" \
        "invocation_sha256=$case_invocation"
      require_exact_line "$artifact_path" 'privacy_scan=passed'
      require_exact_line "$artifact_path" 'status=passed'
      artifact_hash=$(sha256_file "$artifact_path")
      case_artifact_hash=$(
        manifest_value "$case_path" "${component}_artifact_sha256"
      )
      [[ $case_artifact_hash == "$artifact_hash" ]] ||
        fail "live artifact digest does not match its case"
    done
    validate_cross_component_observations \
      "$category" "$logical_case" \
      "${case_observations[exim]}" \
      "${case_observations[adapter]}" \
      "${case_observations[dkim2d]}"
    require_exact_line "$case_path" 'format=dkim2-exim-real-case-v1'
    require_exact_line "$case_path" "row=$row"
    require_exact_line "$case_path" "category=$category"
    require_exact_line "$case_path" "case=$logical_case"
    require_exact_line "$case_path" "exim_version=$version"
    require_exact_line "$case_path" "build_id=$build_id"
    require_exact_line "$case_path" "binary_sha256=$binary_hash"
    require_exact_line "$case_path" "run_id=$expected_run_id"
    require_exact_line "$case_path" 'status=passed'
  done <<<"$expected_cases"
done

actual_entries=$(
  find "$evidence_root" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort
)
expected_entries=$(
  {
    printf '%s\n' run-v1.txt
    printf '%s\n' "${rows[@]}"
  } | sort
)
[[ $actual_entries == "$expected_entries" ]] ||
  fail "evidence root inventory is not exact"

set +e
LC_ALL=C grep -E -i -R -n \
  '(^|[^a-z])(message-id|subject|authorization|cookie|private[-_ ]?key|capability|bearer)([^a-z]|$)|@' \
  "$evidence_root" >/dev/null
privacy_status=$?
set -e
case "$privacy_status" in
  0) fail "privacy scan found an identity, mail, or secret marker" ;;
  1) ;;
  *) fail "privacy scan could not inspect the evidence root" ;;
esac

printf '%s\n' \
  'real Exim matrix result set is fixture-authenticated and case-complete'
