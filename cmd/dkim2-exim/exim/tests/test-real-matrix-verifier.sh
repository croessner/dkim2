#!/usr/bin/env bash
# Exercises the strict fixture-bound real-matrix evidence verifier.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd -P)
fixtures="$repository_root/cmd/dkim2-exim/exim/fixtures"
verifier="$script_dir/run-real-matrix.sh"
build_input_verifier="$script_dir/verify-real-matrix-build-input.sh"
# shellcheck disable=SC1090,SC1091
source "$script_dir/real-matrix-contract.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-exim-real-matrix-verifier.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
chmod 0700 "$work"
run_id=907dfa0f9748d82a8c7723ff6732ebbbd3cfaf409ef470e4cc97805587ca4f9c
mapfile -t rows < <(real_matrix_rows)

# sha256_file computes one portable lowercase SHA-256 digest.
sha256_file() {
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    read -r digest _ < <(sha256sum "$1") || return 1
  else
    read -r digest _ < <(shasum -a 256 "$1") || return 1
  fi
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

# synthetic_live_observation returns deterministic values for verifier tests only.
synthetic_live_observation() {
  local same=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local other=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  local request=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  local response=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  local plan=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  local output=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  local order=1111111111111111111111111111111111111111111111111111111111111111
  local authorized=2222222222222222222222222222222222222222222222222222222222222222
  case "$1:$2:$3" in
    smtp:lf:exim)
      printf '%s\n' \
        "smtp-final-250,deliveries-1,stable-input-sha256-$same,stable-output-sha256-$same,lf-count-5,crlf-count-0"
      ;;
    smtp:crlf:exim)
      printf '%s\n' \
        "smtp-final-250,deliveries-1,stable-input-sha256-$same,stable-output-sha256-$same,crlf-count-5,bare-lf-count-0"
      ;;
    smtp:duplicate-folded:exim)
      printf '%s\n' \
        "smtp-final-250,deliveries-1,header-order-sha256-$same,duplicate-count-2,folded-count-1"
      ;;
    smtp:binary-body:exim)
      printf '%s\n' \
        "smtp-final-250,deliveries-1,body-input-sha256-$same,body-output-sha256-$same,nul-count-1"
      ;;
    smtp:smtputf8-rfc6532:exim)
      printf '%s\n' \
        "smtp-final-250,deliveries-1,stable-input-sha256-$same,stable-output-sha256-$same,nonascii-octets-4"
      ;;
    smtp:forged-authentication-results:adapter)
      printf '%s\n' \
        "operation-process,incoming-local-claims-2,removed-local-claims-2,generated-top-1,header-order-sha256-$same"
      ;;
    smtp:incoming-outgoing-envelope:adapter)
      printf '%s\n' \
        "operation-process-revise,invocation-sha256-$plan,incoming-envelope-sha256-$same,outgoing-envelope-sha256-$other,envelopes-distinct-1"
      ;;
    smtp:incoming-outgoing-envelope:dkim2d)
      printf '%s\n' \
        "route-process-revise,http-2xx-2,invocation-sha256-$plan,incoming-envelope-sha256-$same,outgoing-envelope-sha256-$other"
      ;;
    transport-filter:sign:exim)
      printf '%s\n' \
        "transport-exit-0,deliveries-1,invocation-sha256-$same,authorized-fields-sha256-$authorized,output-sha256-$output,header-order-sha256-$order"
      ;;
    transport-filter:revise:exim)
      printf '%s\n' \
        "transport-exit-0,deliveries-1,invocation-sha256-$same,authorized-fields-sha256-$authorized,output-sha256-$output,header-order-sha256-$order"
      ;;
    transport-filter:sign:adapter)
      printf '%s\n' \
        "operation-sign,result-pass,invocation-sha256-$same,request-sha256-$request,response-sha256-$response,action-plan-sha256-$plan,authorized-fields-sha256-$authorized,actions-2,action-order-message-instance-dkim2-signature,output-sha256-$output,header-order-sha256-$order"
      ;;
    transport-filter:revise:adapter)
      printf '%s\n' \
        "operation-revise,result-pass,invocation-sha256-$same,request-sha256-$request,response-sha256-$response,action-plan-sha256-$plan,authorized-fields-sha256-$authorized,actions-1,action-order-dkim2-signature,output-sha256-$output,header-order-sha256-$order"
      ;;
    transport-filter:sign:dkim2d)
      printf '%s\n' \
        "route-sign,http-2xx-1,result-pass,invocation-sha256-$same,request-sha256-$request,response-sha256-$response,action-plan-sha256-$plan,authorized-fields-sha256-$authorized,actions-2"
      ;;
    transport-filter:revise:dkim2d)
      printf '%s\n' \
        "route-revise,http-2xx-1,result-pass,invocation-sha256-$same,request-sha256-$request,response-sha256-$response,action-plan-sha256-$plan,authorized-fields-sha256-$authorized,actions-1"
      ;;
    transport-filter:bcc-safe:exim)
      printf '%s\n' \
        "transport-exit-0,deliveries-1,invocation-sha256-$same,recipient-count-1,pipe-argv-count-1,bcc-marker-count-0,output-sha256-$output"
      ;;
    transport-filter:bcc-safe:adapter)
      printf '%s\n' \
        "operation-revise,result-pass,invocation-sha256-$same,recipient-count-1,pipe-argv-count-1,bcc-marker-count-0,output-sha256-$output"
      ;;
    transport-filter:bcc-safe:dkim2d)
      printf '%s\n' \
        "route-revise,http-2xx-1,result-pass,invocation-sha256-$same,recipient-count-1,request-sha256-$request,response-sha256-$response"
      ;;
    *)
      return 1
      ;;
  esac
}

# expect_rejection requires one mutated evidence tree to fail closed.
expect_rejection() {
  local name=$1
  if DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT="$work/$name" \
    DKIM2_EXIM_REAL_MATRIX_RUN_ID="$run_id" \
    DKIM2_EXIM_REAL_MATRIX_ADAPTER_SHA256="$adapter_sha256" \
    DKIM2_EXIM_REAL_MATRIX_DAEMON_SHA256="$daemon_sha256" \
    "$verifier" >/dev/null 2>&1; then
    printf 'real matrix verifier accepted negative case: %s\n' "$name" >&2
    exit 1
  fi
}

# expect_build_input_rejection requires one mutated build record to fail closed.
expect_build_input_rejection() {
  local path=$1
  if "$build_input_verifier" "$path" \
    "$candidate_base_revision" "$candidate_snapshot_sha256" \
    "$adapter_sha256" "$daemon_sha256" "$binary_sha256" \
    "$binary_sha256" "$transport_filter_patch_sha256" \
    >/dev/null 2>&1; then
    printf 'build-input verifier accepted negative case: %s\n' "$path" >&2
    exit 1
  fi
}

# replace_transcript_observation rebinds one synthetic negative artifact chain.
replace_transcript_observation() {
  local root=$1 row=$2 category=$3 logical_case=$4 component=$5 observation=$6
  local stem="$root/$row/$category--$logical_case"
  local transcript="$stem--$component.transcript"
  local artifact="$stem--$component.artifact"
  local case_path="$stem.case"
  local transcript_hash artifact_hash
  printf '%s\n' "observation=$observation" >"$transcript"
  transcript_hash=$(sha256_file "$transcript")
  sed -i.bak \
    "s/^transcript_sha256=.*/transcript_sha256=$transcript_hash/" \
    "$artifact"
  rm "$artifact.bak"
  artifact_hash=$(sha256_file "$artifact")
  sed -i.bak \
    "s/^${component}_artifact_sha256=.*/${component}_artifact_sha256=$artifact_hash/" \
    "$case_path"
  rm "$case_path.bak"
}

module_sha256=$(sha256_file \
  "$repository_root/cmd/dkim2-exim/exim/dkim2_local_scan.c")
transport_filter_patch_sha256=$(sha256_file \
  "$repository_root/cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch")
binary_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
adapter_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
daemon_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
runner_sha256=$(sha256_file "$script_dir/execute-real-matrix-linux.sh")
matrix_helper_sha256=$(sha256_file "$script_dir/real_matrix_service.py")
validator_sha256=$(sha256_file \
  "$repository_root/cmd/dkim2-exim/packaging/validate-deployment.sh")
candidate_base_revision=$(git -C "$repository_root" rev-parse HEAD)
candidate_snapshot_sha256=$(go -C "$repository_root/tools" run ./cmd/candidateid -root ..)
[[ $candidate_base_revision =~ ^[0-9a-f]{40}$ &&
  $candidate_snapshot_sha256 =~ ^[0-9a-f]{64}$ ]] || exit 1

build_input="$work/build-input-v1.txt"
printf '%s\n' \
  'format=dkim2-exim-container-build-input-v1' \
  'image=golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6' \
  'platform=linux-amd64' \
  'mta_uid=999' \
  "base_revision=$candidate_base_revision" \
  "candidate_snapshot_sha256=$candidate_snapshot_sha256" \
  "source_archive_sha256=$binary_sha256" \
  "transport_filter_patch_sha256=$transport_filter_patch_sha256" \
  "compiler_sha256=$binary_sha256" \
  "adapter_sha256=$adapter_sha256" \
  "daemon_sha256=$daemon_sha256" \
  "binary_sha256=$binary_sha256" \
  'input_state=complete' >"$build_input"
"$build_input_verifier" "$build_input" \
  "$candidate_base_revision" "$candidate_snapshot_sha256" \
  "$adapter_sha256" "$daemon_sha256" "$binary_sha256" \
  "$binary_sha256" "$transport_filter_patch_sha256"

cp "$build_input" "$work/build-input-stale-candidate"
sed -i.bak \
  's/^candidate_snapshot_sha256=.*/candidate_snapshot_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/build-input-stale-candidate"
rm "$work/build-input-stale-candidate.bak"
expect_build_input_rejection "$work/build-input-stale-candidate"

cp "$build_input" "$work/build-input-stale-base"
sed -i.bak \
  's/^base_revision=.*/base_revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/build-input-stale-base"
rm "$work/build-input-stale-base.bak"
expect_build_input_rejection "$work/build-input-stale-base"

cp "$build_input" "$work/build-input-stale-daemon"
sed -i.bak \
  's/^daemon_sha256=.*/daemon_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/build-input-stale-daemon"
rm "$work/build-input-stale-daemon.bak"
expect_build_input_rejection "$work/build-input-stale-daemon"

cp "$build_input" "$work/build-input-stale-source"
sed -i.bak \
  's/^source_archive_sha256=.*/source_archive_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/' \
  "$work/build-input-stale-source"
rm "$work/build-input-stale-source.bak"
expect_build_input_rejection "$work/build-input-stale-source"

cp "$build_input" "$work/build-input-stale-patch"
sed -i.bak \
  's/^transport_filter_patch_sha256=.*/transport_filter_patch_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/build-input-stale-patch"
rm "$work/build-input-stale-patch.bak"
expect_build_input_rejection "$work/build-input-stale-patch"

cp "$build_input" "$work/build-input-duplicate"
printf '%s\n' 'input_state=complete' >>"$work/build-input-duplicate"
expect_build_input_rejection "$work/build-input-duplicate"

cp "$build_input" "$work/build-input-reordered"
sed -i.bak '4{h;d;};5{p;g;d;}' "$work/build-input-reordered"
rm "$work/build-input-reordered.bak"
expect_build_input_rejection "$work/build-input-reordered"

build_input_content=$(<"$build_input")
printf '%s' "$build_input_content" >"$work/build-input-unterminated"
expect_build_input_rejection "$work/build-input-unterminated"

cp "$build_input" "$work/build-input-nul"
printf '\0' >>"$work/build-input-nul"
expect_build_input_rejection "$work/build-input-nul"

cp "$build_input" "$work/build-input-oversize"
for _ in {1..80}; do
  printf '%064d\n' 0 >>"$work/build-input-oversize"
done
expect_build_input_rejection "$work/build-input-oversize"

mkdir "$work/evidence"
chmod 0700 "$work/evidence"
printf '%s\n' \
  'format=dkim2-exim-real-matrix-run-v1' \
  "run_id=$run_id" \
  "base_revision=$candidate_base_revision" \
  "candidate_snapshot_sha256=$candidate_snapshot_sha256" \
  "matrix_helper_sha256=$matrix_helper_sha256" \
  'created_at=2026-07-27T14:00:00Z' >"$work/evidence/run-v1.txt"
chmod 0600 "$work/evidence/run-v1.txt"

for row in "${rows[@]}"; do
  fixture="$fixtures/$row"
  version=$(awk -F= '$1 == "exim_version" { print $2 }' \
    "$fixture/compatibility-manifest-v1.txt")
  build_id=$(awk -F= '$1 == "build_id" { print $2 }' \
    "$fixture/compatibility-manifest-v1.txt")
  source_hash=$(sha256_file "$fixture/source-manifest-v1.txt")
  compatibility_hash=$(sha256_file "$fixture/compatibility-manifest-v1.txt")
  mkdir "$work/evidence/$row"
  chmod 0700 "$work/evidence/$row"
  case_count=0
  for category in smtp local-submission transport-filter; do
    mapfile -t names < <(real_matrix_cases "$category")
    for logical_case in "${names[@]}"; do
      case_count=$((case_count + 1))
      invocation_sha256=$(
        printf '%s:%s:%s' "$row" "$category" "$logical_case" |
          sha256_file /dev/stdin
      )
      contract=$(real_matrix_expected_contract "$category" "$logical_case")
      read -r proof exim_assertion adapter_assertion dkim2d_assertion \
        fault_assertion readback_assertion < <(printf '%s\n' "$contract")
      declare -A artifact_hashes=()
      for component in exim adapter dkim2d fault readback; do
        case "$component" in
          exim)
            assertion=$exim_assertion
            producer=$binary_sha256
            ;;
          adapter)
            assertion=$adapter_assertion
            producer=$adapter_sha256
            ;;
          dkim2d)
            assertion=$dkim2d_assertion
            producer=$daemon_sha256
            ;;
          fault)
            assertion=$fault_assertion
            producer=$runner_sha256
            ;;
          readback)
            assertion=$readback_assertion
            producer=$validator_sha256
            ;;
        esac
        artifact="$work/evidence/$row/$category--$logical_case--$component.artifact"
        if real_matrix_observation_has_live_values \
          "$category" "$logical_case" "$component"; then
          observation=$(
            synthetic_live_observation \
              "$category" "$logical_case" "$component"
          )
        else
          observation=$(
            real_matrix_expected_observation \
              "$category" "$logical_case" "$component"
          )
        fi
        transcript="$work/evidence/$row/$category--$logical_case--$component.transcript"
        printf '%s\n' "observation=$observation" >"$transcript"
        chmod 0600 "$transcript"
        transcript_sha256=$(sha256_file "$transcript")
        printf '%s\n' \
          'format=dkim2-exim-real-artifact-v1' \
          "row=$row" \
          "category=$category" \
          "case=$logical_case" \
          "component=$component" \
          "assertion=$assertion" \
          "producer_sha256=$producer" \
          "transcript_sha256=$transcript_sha256" \
          "run_id=$run_id" \
          "invocation_sha256=$invocation_sha256" \
          'started_at=2026-07-27T14:00:00Z' \
          'finished_at=2026-07-27T14:00:01Z' \
          'privacy_scan=passed' \
          'status=passed' >"$artifact"
        chmod 0600 "$artifact"
        artifact_hashes[$component]=$(sha256_file "$artifact")
      done
      printf '%s\n' \
        'format=dkim2-exim-real-case-v1' \
        "row=$row" \
        "category=$category" \
        "case=$logical_case" \
        "exim_version=$version" \
        "build_id=$build_id" \
        "binary_sha256=$binary_sha256" \
        "run_id=$run_id" \
        "invocation_sha256=$invocation_sha256" \
        'started_at=2026-07-27T14:00:00Z' \
        'finished_at=2026-07-27T14:00:01Z' \
        "exim_artifact_sha256=${artifact_hashes[exim]}" \
        "adapter_artifact_sha256=${artifact_hashes[adapter]}" \
        "dkim2d_artifact_sha256=${artifact_hashes[dkim2d]}" \
        "fault_artifact_sha256=${artifact_hashes[fault]}" \
        "readback_artifact_sha256=${artifact_hashes[readback]}" \
        "proof=$proof" \
        'status=passed' \
        >"$work/evidence/$row/$category--$logical_case.case"
      chmod 0600 "$work/evidence/$row/$category--$logical_case.case"
    done
  done
  printf '%s\n' "observation=exim-version-$version" \
    >"$work/evidence/$row/version.readback"
  printf '%s\n' 'observation=exim-user-Debian-exim' \
    >"$work/evidence/$row/exim-user.readback"
  printf '%s\n' 'observation=exim-group-Debian-exim' \
    >"$work/evidence/$row/exim-group.readback"
  printf '%s\n' 'observation=spool-wireformat-false' \
    >"$work/evidence/$row/spool-wireformat.readback"
  printf '%s\n' "observation=local-scan-build-id-$build_id" \
    >"$work/evidence/$row/local-scan.readback"
  printf '%s\n' 'observation=sign-transport-validator-pass' \
    >"$work/evidence/$row/sign-transport.readback"
  printf '%s\n' 'observation=revise-transport-validator-pass' \
    >"$work/evidence/$row/revise-transport.readback"
  chmod 0600 "$work/evidence/$row"/*.readback
  version_readback_sha256=$(
    sha256_file "$work/evidence/$row/version.readback"
  )
  exim_user_readback_sha256=$(
    sha256_file "$work/evidence/$row/exim-user.readback"
  )
  exim_group_readback_sha256=$(
    sha256_file "$work/evidence/$row/exim-group.readback"
  )
  spool_wireformat_readback_sha256=$(
    sha256_file "$work/evidence/$row/spool-wireformat.readback"
  )
  local_scan_readback_sha256=$(
    sha256_file "$work/evidence/$row/local-scan.readback"
  )
  sign_transport_readback_sha256=$(
    sha256_file "$work/evidence/$row/sign-transport.readback"
  )
  revise_transport_readback_sha256=$(
    sha256_file "$work/evidence/$row/revise-transport.readback"
  )
  printf '%s\n' \
    'format=dkim2-exim-real-matrix-result-v1' \
    "row=$row" \
    "exim_version=$version" \
    "build_id=$build_id" \
    "source_manifest_sha256=$source_hash" \
    "compatibility_manifest_sha256=$compatibility_hash" \
    "module_sha256=$module_sha256" \
    "transport_filter_patch_sha256=$transport_filter_patch_sha256" \
    "binary_sha256=$binary_sha256" \
    "adapter_sha256=$adapter_sha256" \
    "daemon_sha256=$daemon_sha256" \
    "runner_sha256=$runner_sha256" \
    "matrix_helper_sha256=$matrix_helper_sha256" \
    "deployment_validator_sha256=$validator_sha256" \
    "version_readback_sha256=$version_readback_sha256" \
    "exim_user_readback_sha256=$exim_user_readback_sha256" \
    "exim_group_readback_sha256=$exim_group_readback_sha256" \
    "spool_wireformat_readback_sha256=$spool_wireformat_readback_sha256" \
    "local_scan_readback_sha256=$local_scan_readback_sha256" \
    "sign_transport_readback_sha256=$sign_transport_readback_sha256" \
    "revise_transport_readback_sha256=$revise_transport_readback_sha256" \
    "run_id=$run_id" \
    'started_at=2026-07-27T14:00:00Z' \
    'finished_at=2026-07-27T14:00:01Z' \
    "case_count=$case_count" \
    'privacy_scan=passed' \
    'status=passed' >"$work/evidence/$row/result-v1.txt"
  chmod 0600 "$work/evidence/$row/result-v1.txt"
done

verification_started=$SECONDS
DKIM2_EXIM_REAL_MATRIX_EVIDENCE_ROOT="$work/evidence" \
  DKIM2_EXIM_REAL_MATRIX_RUN_ID="$run_id" \
  DKIM2_EXIM_REAL_MATRIX_ADAPTER_SHA256="$adapter_sha256" \
  DKIM2_EXIM_REAL_MATRIX_DAEMON_SHA256="$daemon_sha256" \
  "$verifier" >/dev/null
verification_elapsed=$((SECONDS - verification_started))
[[ $verification_elapsed -lt 240 ]] || {
  printf 'real matrix verifier exceeded the four-minute regression bound\n' >&2
  exit 1
}

cp -R "$work/evidence" "$work/tampered-build"
sed -i.bak \
  's/^build_id=.*/build_id=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/' \
  "$work/tampered-build/upstream-4.99.5/result-v1.txt"
rm "$work/tampered-build/upstream-4.99.5/result-v1.txt.bak"
expect_rejection tampered-build

cp -R "$work/evidence" "$work/tampered-helper"
sed -i.bak \
  's/^matrix_helper_sha256=.*/matrix_helper_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/tampered-helper/run-v1.txt"
rm "$work/tampered-helper/run-v1.txt.bak"
expect_rejection tampered-helper

cp -R "$work/evidence" "$work/tampered-candidate"
sed -i.bak \
  's/^candidate_snapshot_sha256=.*/candidate_snapshot_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/tampered-candidate/run-v1.txt"
rm "$work/tampered-candidate/run-v1.txt.bak"
expect_rejection tampered-candidate

cp -R "$work/evidence" "$work/symlinked"
rm "$work/symlinked/upstream-4.99.5/result-v1.txt"
ln -s "$work/evidence/upstream-4.99.5/result-v1.txt" \
  "$work/symlinked/upstream-4.99.5/result-v1.txt"
expect_rejection symlinked

cp -R "$work/evidence" "$work/missing-case"
rm "$work/missing-case/upstream-4.99.5/smtp--lf.case"
expect_rejection missing-case

cp -R "$work/evidence" "$work/extra-case"
cp "$work/extra-case/upstream-4.99.5/smtp--lf.case" \
  "$work/extra-case/upstream-4.99.5/smtp--unexpected.case"
expect_rejection extra-case

cp -R "$work/evidence" "$work/wrong-run"
sed -i.bak \
  's/^run_id=.*/run_id=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/' \
  "$work/wrong-run/upstream-4.99.5/smtp--lf.case"
rm "$work/wrong-run/upstream-4.99.5/smtp--lf.case.bak"
expect_rejection wrong-run

cp -R "$work/evidence" "$work/wrong-invocation"
sed -i.bak \
  's/^invocation_sha256=.*/invocation_sha256=invalid/' \
  "$work/wrong-invocation/upstream-4.99.5/smtp--lf.case"
rm "$work/wrong-invocation/upstream-4.99.5/smtp--lf.case.bak"
expect_rejection wrong-invocation

cp -R "$work/evidence" "$work/reversed-time"
sed -i.bak 's/^started_at=.*/started_at=2026-07-27T14:00:02Z/' \
  "$work/reversed-time/upstream-4.99.5/smtp--lf.case"
rm "$work/reversed-time/upstream-4.99.5/smtp--lf.case.bak"
expect_rejection reversed-time

cp -R "$work/evidence" "$work/duplicate-field"
printf '%s\n' 'status=passed' \
  >>"$work/duplicate-field/upstream-4.99.5/smtp--lf.case"
expect_rejection duplicate-field

cp -R "$work/evidence" "$work/reordered-field"
sed -i.bak \
  '1{h;d;};2{p;g;d;}' \
  "$work/reordered-field/upstream-4.99.5/smtp--lf.case"
rm "$work/reordered-field/upstream-4.99.5/smtp--lf.case.bak"
expect_rejection reordered-field

cp -R "$work/evidence" "$work/unterminated-field"
unterminated_path="$work/unterminated-field/upstream-4.99.5/smtp--lf.case"
unterminated_input=$(<"$unterminated_path")
printf '%s' "$unterminated_input" >"$unterminated_path"
expect_rejection unterminated-field

cp -R "$work/evidence" "$work/nul-field"
printf '\0' \
  >>"$work/nul-field/upstream-4.99.5/smtp--lf.case"
expect_rejection nul-field

cp -R "$work/evidence" "$work/privacy-marker"
sed -i.bak 's/^proof=.*/proof=subject@example.test/' \
  "$work/privacy-marker/upstream-4.99.5/smtp--lf.case"
rm "$work/privacy-marker/upstream-4.99.5/smtp--lf.case.bak"
expect_rejection privacy-marker

cp -R "$work/evidence" "$work/wrong-proof"
sed -i.bak 's/^proof=.*/proof=deployment-readback/' \
  "$work/wrong-proof/upstream-4.99.5/transport-filter--sign.case"
rm "$work/wrong-proof/upstream-4.99.5/transport-filter--sign.case.bak"
expect_rejection wrong-proof

cp -R "$work/evidence" "$work/wrong-exact-build-proof"
sed -i.bak 's/^proof=.*/proof=deployment-readback/' \
  "$work/wrong-exact-build-proof/upstream-4.99.5/smtp--exact-build.case"
rm "$work/wrong-exact-build-proof/upstream-4.99.5/smtp--exact-build.case.bak"
expect_rejection wrong-exact-build-proof

cp -R "$work/evidence" "$work/wrong-revise-proof"
sed -i.bak 's/^proof=.*/proof=real-exim-transport/' \
  "$work/wrong-revise-proof/upstream-4.99.5/transport-filter--revise.case"
rm "$work/wrong-revise-proof/upstream-4.99.5/transport-filter--revise.case.bak"
expect_rejection wrong-revise-proof

cp -R "$work/evidence" "$work/missing-artifact"
rm "$work/missing-artifact/upstream-4.99.5/transport-filter--sign--dkim2d.artifact"
expect_rejection missing-artifact

cp -R "$work/evidence" "$work/extra-artifact"
cp \
  "$work/extra-artifact/upstream-4.99.5/transport-filter--sign--dkim2d.artifact" \
  "$work/extra-artifact/upstream-4.99.5/transport-filter--sign--extra.artifact"
expect_rejection extra-artifact

cp -R "$work/evidence" "$work/symlink-artifact"
rm "$work/symlink-artifact/upstream-4.99.5/transport-filter--sign--dkim2d.artifact"
ln -s \
  "$work/evidence/upstream-4.99.5/transport-filter--sign--dkim2d.artifact" \
  "$work/symlink-artifact/upstream-4.99.5/transport-filter--sign--dkim2d.artifact"
expect_rejection symlink-artifact

cp -R "$work/evidence" "$work/digest-mismatch"
sed -i.bak \
  's/^dkim2d_artifact_sha256=.*/dkim2d_artifact_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/digest-mismatch/upstream-4.99.5/transport-filter--sign.case"
rm "$work/digest-mismatch/upstream-4.99.5/transport-filter--sign.case.bak"
expect_rejection digest-mismatch

cp -R "$work/evidence" "$work/tampered-artifact"
sed -i.bak 's/^observation=.*/observation=tampered-live-observation/' \
  "$work/tampered-artifact/upstream-4.99.5/transport-filter--sign--dkim2d.transcript"
rm \
  "$work/tampered-artifact/upstream-4.99.5/transport-filter--sign--dkim2d.transcript.bak"
expect_rejection tampered-artifact

cp -R "$work/evidence" "$work/missing-transcript"
rm \
  "$work/missing-transcript/upstream-4.99.5/transport-filter--sign--dkim2d.transcript"
expect_rejection missing-transcript

cp -R "$work/evidence" "$work/extra-transcript"
cp \
  "$work/extra-transcript/upstream-4.99.5/transport-filter--sign--dkim2d.transcript" \
  "$work/extra-transcript/upstream-4.99.5/transport-filter--sign--extra.transcript"
expect_rejection extra-transcript

cp -R "$work/evidence" "$work/symlink-transcript"
rm \
  "$work/symlink-transcript/upstream-4.99.5/transport-filter--sign--dkim2d.transcript"
ln -s \
  "$work/evidence/upstream-4.99.5/transport-filter--sign--dkim2d.transcript" \
  "$work/symlink-transcript/upstream-4.99.5/transport-filter--sign--dkim2d.transcript"
expect_rejection symlink-transcript

cp -R "$work/evidence" "$work/transcript-digest-mismatch"
sed -i.bak \
  's/^transcript_sha256=.*/transcript_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$work/transcript-digest-mismatch/upstream-4.99.5/transport-filter--sign--dkim2d.artifact"
rm \
  "$work/transcript-digest-mismatch/upstream-4.99.5/transport-filter--sign--dkim2d.artifact.bak"
expect_rejection transcript-digest-mismatch

cp -R "$work/evidence" "$work/wrong-component"
wrong_component_artifact="$work/wrong-component/upstream-4.99.5/transport-filter--sign--dkim2d.artifact"
wrong_component_case="$work/wrong-component/upstream-4.99.5/transport-filter--sign.case"
sed -i.bak 's/^assertion=.*/assertion=not-reached/' "$wrong_component_artifact"
rm "$wrong_component_artifact.bak"
wrong_component_hash=$(sha256_file "$wrong_component_artifact")
sed -i.bak \
  "s/^dkim2d_artifact_sha256=.*/dkim2d_artifact_sha256=$wrong_component_hash/" \
  "$wrong_component_case"
rm "$wrong_component_case.bak"
expect_rejection wrong-component

cp -R "$work/evidence" "$work/wrong-observation"
wrong_observation_transcript="$work/wrong-observation/upstream-4.99.5/transport-filter--sign--adapter.transcript"
wrong_observation_artifact="$work/wrong-observation/upstream-4.99.5/transport-filter--sign--adapter.artifact"
wrong_observation_case="$work/wrong-observation/upstream-4.99.5/transport-filter--sign.case"
sed -i.bak 's/,actions-2,/,actions-1,/' "$wrong_observation_transcript"
rm "$wrong_observation_transcript.bak"
wrong_transcript_hash=$(sha256_file "$wrong_observation_transcript")
sed -i.bak \
  "s/^transcript_sha256=.*/transcript_sha256=$wrong_transcript_hash/" \
  "$wrong_observation_artifact"
rm "$wrong_observation_artifact.bak"
wrong_observation_hash=$(sha256_file "$wrong_observation_artifact")
sed -i.bak \
  "s/^adapter_artifact_sha256=.*/adapter_artifact_sha256=$wrong_observation_hash/" \
  "$wrong_observation_case"
rm "$wrong_observation_case.bak"
expect_rejection wrong-observation

cp -R "$work/evidence" "$work/wrong-producer"
wrong_producer_artifact="$work/wrong-producer/upstream-4.99.5/transport-filter--sign--adapter.artifact"
wrong_producer_case="$work/wrong-producer/upstream-4.99.5/transport-filter--sign.case"
sed -i.bak \
  's/^producer_sha256=.*/producer_sha256=9999999999999999999999999999999999999999999999999999999999999999/' \
  "$wrong_producer_artifact"
rm "$wrong_producer_artifact.bak"
wrong_producer_hash=$(sha256_file "$wrong_producer_artifact")
sed -i.bak \
  "s/^adapter_artifact_sha256=.*/adapter_artifact_sha256=$wrong_producer_hash/" \
  "$wrong_producer_case"
rm "$wrong_producer_case.bak"
expect_rejection wrong-producer

cp -R "$work/evidence" "$work/wrong-runner-producer"
sed -i.bak \
  's/^runner_sha256=.*/runner_sha256=9999999999999999999999999999999999999999999999999999999999999999/' \
  "$work/wrong-runner-producer/upstream-4.99.5/result-v1.txt"
rm "$work/wrong-runner-producer/upstream-4.99.5/result-v1.txt.bak"
expect_rejection wrong-runner-producer

cp -R "$work/evidence" "$work/wrong-validator-producer"
sed -i.bak \
  's/^deployment_validator_sha256=.*/deployment_validator_sha256=9999999999999999999999999999999999999999999999999999999999999999/' \
  "$work/wrong-validator-producer/upstream-4.99.5/result-v1.txt"
rm "$work/wrong-validator-producer/upstream-4.99.5/result-v1.txt.bak"
expect_rejection wrong-validator-producer

cp -R "$work/evidence" "$work/wrong-readback-digest"
sed -i.bak \
  's/^version_readback_sha256=.*/version_readback_sha256=9999999999999999999999999999999999999999999999999999999999999999/' \
  "$work/wrong-readback-digest/upstream-4.99.5/result-v1.txt"
rm "$work/wrong-readback-digest/upstream-4.99.5/result-v1.txt.bak"
expect_rejection wrong-readback-digest

cp -R "$work/evidence" "$work/missing-readback"
rm "$work/missing-readback/upstream-4.99.5/version.readback"
expect_rejection missing-readback

cp -R "$work/evidence" "$work/symlink-readback"
rm "$work/symlink-readback/upstream-4.99.5/version.readback"
ln -s "$work/evidence/upstream-4.99.5/version.readback" \
  "$work/symlink-readback/upstream-4.99.5/version.readback"
expect_rejection symlink-readback

cross_hash=2222222222222222222222222222222222222222222222222222222222222222

cp -R "$work/evidence" "$work/cross-sign-invocation"
replace_transcript_observation \
  "$work/cross-sign-invocation" upstream-4.99.5 transport-filter sign adapter \
  "operation-sign,result-pass,invocation-sha256-$cross_hash,request-sha256-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,response-sha256-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,action-plan-sha256-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee,authorized-fields-sha256-2222222222222222222222222222222222222222222222222222222222222222,actions-2,action-order-message-instance-dkim2-signature,output-sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,header-order-sha256-1111111111111111111111111111111111111111111111111111111111111111"
expect_rejection cross-sign-invocation

cp -R "$work/evidence" "$work/cross-sign-authorized-fields"
replace_transcript_observation \
  "$work/cross-sign-authorized-fields" upstream-4.99.5 \
  transport-filter sign adapter \
  "operation-sign,result-pass,invocation-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,request-sha256-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,response-sha256-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,action-plan-sha256-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee,authorized-fields-sha256-3333333333333333333333333333333333333333333333333333333333333333,actions-2,action-order-message-instance-dkim2-signature,output-sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,header-order-sha256-1111111111111111111111111111111111111111111111111111111111111111"
expect_rejection cross-sign-authorized-fields

cp -R "$work/evidence" "$work/cross-sign-output-fields"
replace_transcript_observation \
  "$work/cross-sign-output-fields" upstream-4.99.5 \
  transport-filter sign exim \
  "transport-exit-0,deliveries-1,invocation-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,authorized-fields-sha256-3333333333333333333333333333333333333333333333333333333333333333,output-sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,header-order-sha256-1111111111111111111111111111111111111111111111111111111111111111"
expect_rejection cross-sign-output-fields

cp -R "$work/evidence" "$work/cross-envelope"
replace_transcript_observation \
  "$work/cross-envelope" upstream-4.99.5 smtp incoming-outgoing-envelope adapter \
  "operation-process-revise,invocation-sha256-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee,incoming-envelope-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,outgoing-envelope-sha256-$cross_hash,envelopes-distinct-1"
expect_rejection cross-envelope

cp -R "$work/evidence" "$work/cross-bcc"
replace_transcript_observation \
  "$work/cross-bcc" upstream-4.99.5 transport-filter bcc-safe adapter \
  "operation-revise,result-pass,invocation-sha256-$cross_hash,recipient-count-1,pipe-argv-count-1,bcc-marker-count-0,output-sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
expect_rejection cross-bcc

printf '%s\n' 'real Exim matrix verifier regression cases passed'
