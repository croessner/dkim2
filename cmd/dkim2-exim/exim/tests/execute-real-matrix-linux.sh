#!/usr/bin/env bash
# Executes fresh real Exim inbound admission cases on a Linux qualification host.
set -euo pipefail
umask 077

if [[ $(uname -s) != Linux || $(id -u) -ne 0 || $# -ne 8 ]]; then
  printf '%s\n' 'usage: execute-real-matrix-linux.sh ROW EXIM VERSION BUILD_ID ADAPTER DAEMON EVIDENCE_ROOT RUN_ID' >&2
  exit 2
fi

row=$1
exim_binary=$2
expected_version=$3
expected_build_id=$4
adapter_binary=$5
daemon_binary=$6
evidence_root=$7
run_id=$8
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_dir/../../../.." && pwd -P)
contract="$script_dir/real-matrix-contract.sh"
matrix_helper="$script_dir/real_matrix_service.py"
[[ ! -L $contract && -f $contract && -s $contract ]] || {
  printf '%s\n' 'active real Exim matrix failed: qualification contract is unavailable' >&2
  exit 1
}
# shellcheck disable=SC1090,SC1091
source "$contract"

# fail emits one content-free qualification failure and exits closed.
fail() {
  printf 'active real Exim matrix failed: %s\n' "$1" >&2
  exit 1
}

for required_tool in awk base64 basename chmod chown cp curl date dd dirname \
  dnsmasq env find findmnt grep id journalctl mv nc nsenter openssl python3 \
  readlink rm sed sha256sum sort stat systemctl systemd-run tr wc; do
  command -v "$required_tool" >/dev/null 2>&1 ||
    fail "a required qualification tool is unavailable"
done

# require_absolute_regular accepts only one direct executable input.
require_absolute_regular() {
  [[ $1 == /* && ! -L $1 && -f $1 && -x $1 ]] ||
    fail "one executable is absent, relative, or symlinked"
}

# wait_for_path waits within one bounded startup or delivery interval.
wait_for_path() {
  local path=$1 kind=$2 attempt=0
  while (( attempt < 100 )); do
    if [[ $kind == socket && -S $path || $kind == file && -s $path ]]; then
      return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  return 1
}

# start_unit starts and records one owned transient qualification service.
start_unit() {
  local name=$1 uid=$2
  shift 2
  if [[ $uid == root ]]; then
    systemd-run --quiet --unit "$name" --property=Type=exec \
      --property=TimeoutStopSec=15s -- "$@"
  else
    systemd-run --quiet --unit "$name" --uid="$uid" --property=Type=exec \
      --property=TimeoutStopSec=15s -- "$@"
  fi
  active_units+=("$name")
  for _ in {1..100}; do
    [[ $(systemctl is-active "$name") == active ]] && return 0
    sleep 0.1
  done
  return 1
}

# start_daemon starts dkim2d with the sealed qualification resolver view.
start_daemon() {
  local name=$1
  systemd-run --quiet --unit "$name" --uid="$mta_user" \
    --property=Type=exec --property=TimeoutStopSec=15s \
    --property="BindReadOnlyPaths=$resolver_config:/etc/resolv.conf" -- \
    "$daemon_binary" serve --config "$config_root/dkim2d.yaml"
  active_units+=("$name")
  for _ in {1..100}; do
    [[ $(systemctl is-active "$name") == active ]] && return 0
    sleep 0.1
  done
  return 1
}

# stop_unit proves one owned transient service stopped successfully.
stop_unit() {
  local name=$1
  systemctl stop "$name"
  [[ $(systemctl show "$name" --property=Result --value) == success ]] ||
    fail "transient qualification unit did not stop successfully"
  [[ $(systemctl show "$name" --property=ExecMainStatus --value) == 0 ]] ||
    fail "transient qualification process did not exit zero"
  verified_stops+=("$name")
}

# finish_unit proves one self-terminating qualification service completed.
finish_unit() {
  local name=$1
  for _ in {1..200}; do
    [[ $(systemctl show "$name" --property=ActiveState --value) == inactive ]] &&
      break
    sleep 0.1
  done
  [[ $(systemctl show "$name" --property=ActiveState --value) == inactive &&
    $(systemctl show "$name" --property=Result --value) == success &&
    $(systemctl show "$name" --property=ExecMainStatus --value) == 0 ]] ||
    fail "self-terminating qualification unit did not complete successfully"
  verified_stops+=("$name")
}

# smtp_final_reply extracts the first reply after SMTP DATA content.
smtp_final_reply() {
  awk 'after_data { print; exit } /^354[ -]/ { after_data = 1 }' "$1"
}

# smtp_submit sends one bounded interactive SMTP message to real Exim.
smtp_submit() {
  local output=$1 sender=$2 recipient=$3 marker=$4
  printf 'EHLO matrix.example.test\r\nMAIL FROM:<%s>\r\nRCPT TO:<%s>\r\nDATA\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\n\r\nbody-%s\r\n.\r\nQUIT\r\n' \
    "$sender" "$recipient" "$sender" "$recipient" "$marker" "$marker" |
    nc -w 20 127.0.0.1 2525 >"$output"
}

# smtp_submit_file sends one prebuilt RFC 5322 message through real SMTP.
smtp_submit_file() {
  local output=$1 sender=$2 recipient=$3 message=$4 wire_format=${5:-crlf}
  local smtp_utf8=${6:-false}
  local -a smtp_utf8_flag=()
  [[ $smtp_utf8 == false || $smtp_utf8 == true ]] ||
    fail "SMTPUTF8 submission mode is invalid"
  [[ $smtp_utf8 == true ]] && smtp_utf8_flag=(--smtp-utf8)
  python3 "$runtime_helper" smtp-client --address 127.0.0.1 --port 2525 \
    --sender "$sender" --recipient "$recipient" --message "$message" \
    --wire-format "$wire_format" "${smtp_utf8_flag[@]}" --output "$output"
}

# start_smtp_capture starts one real downstream SMTP peer.
start_smtp_capture() {
  local unit=$1 output=$2 ready_output=$2.ready
  [[ ! -e $ready_output && ! -L $ready_output ]] ||
    fail "downstream SMTP readiness path was not fresh"
  start_unit "$unit" "$mta_user" python3 "$runtime_helper" smtp \
    --address 127.0.0.1 --port 2526 --output "$output" \
    --ready-output "$ready_output" --count 1 ||
    fail "downstream SMTP capture service did not become active"
  wait_for_path "$ready_output" file ||
    fail "downstream SMTP capture did not become live"
}

# start_smtp_abort_peer starts one bounded peer for a pre-delivery filter abort.
start_smtp_abort_peer() {
  local unit=$1 output=$2 ready_output=$2.ready
  [[ ! -e $output && ! -L $output &&
    ! -e $ready_output && ! -L $ready_output ]] ||
    fail "SMTP abort-peer paths were not fresh"
  start_unit "$unit" "$mta_user" python3 "$runtime_helper" smtp-abort \
    --address 127.0.0.1 --port 2526 --output "$output" \
    --ready-output "$ready_output" ||
    fail "SMTP abort peer did not become active"
  wait_for_path "$ready_output" file ||
    fail "SMTP abort peer did not publish readiness"
}

# finish_smtp_abort_peer proves one envelope attempt and no completed delivery.
finish_smtp_abort_peer() {
  local unit=$1 output=$2 measurement
  wait_for_path "$output" file ||
    fail "SMTP abort peer did not publish its structural measurement"
  finish_unit "$unit"
  measurement=$(tr '\n' ',' <"$output")
  [[ $(wc -l <"$output" | tr -d ' ') -eq 7 ]] &&
    grep -Fxq 'format=dkim2-exim-smtp-abort-v1' "$output" &&
    grep -Fxq 'connections=1' "$output" &&
    grep -Fxq 'ehlo=1' "$output" &&
    grep -Fxq 'mail=1' "$output" &&
    grep -Fxq 'rcpt=1' "$output" &&
    grep -Fxq 'data=1' "$output" &&
    grep -Fxq 'deliveries=0' "$output" ||
    fail "SMTP abort peer structural measurement changed: $measurement"
}

# transport_filter_defer_count counts exact exit-75 transport-filter markers.
transport_filter_defer_count() {
  awk 'index($0, "transport filter process failed (75)") { count++ }
    END { print count + 0 }' "$state_root"/exim-*.log
}

# queued_message_id returns the sole canonical identity in one Exim queue.
queued_message_id() {
  local unit=$1 queue_id
  [[ $(run_exim "$unit" -bpc) -eq 1 ]] ||
    fail "real Exim queue did not contain exactly one message"
  queue_id=$(
    run_exim "$unit" -bp |
      awk 'NF >= 3 && $3 ~ /^[0-9A-Za-z-]+$/ { count++; value = $3 }
        END { if (count == 1) print value }'
  )
  [[ $queue_id =~ ^[0-9A-Za-z-]+$ ]] ||
    fail "real Exim queue identity was missing or ambiguous"
  printf '%s\n' "$queue_id"
}

# start_fault_server starts one bounded local HTTP fault endpoint for an adapter probe.
start_fault_server() {
  local unit=$1 mode=$2
  start_unit "$unit" "$mta_user" python3 "$runtime_helper" http \
    --address 127.0.0.1 --port 18079 --mode "$mode" ||
    fail "local daemon fault endpoint did not become active"
  for _ in {1..100}; do
    nc -z 127.0.0.1 18079 >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  fail "local daemon fault endpoint did not become live"
}

# start_local_scan_fault starts one same-UID Linux peer for a real hook fault.
start_local_scan_fault() {
  local unit=$1 mode=$2 result=$3
  local ready=$result.ready
  [[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock &&
    ! -e $ready && ! -L $ready && ! -e $result && ! -L $result ]] ||
    fail "local-scan fault paths were not fresh"
  start_unit "$unit" "$mta_user" python3 "$runtime_helper" local-scan-fault \
    --path "$socket_root/local-scan.sock" --ready-output "$ready" \
    --result-output "$result" --mode "$mode" ||
    fail "local-scan fault peer did not become active"
  wait_for_path "$ready" file ||
    fail "local-scan fault peer did not publish readiness"
  wait_for_path "$socket_root/local-scan.sock" socket ||
    fail "local-scan fault socket did not become live"
}

# start_daemon_proxy restores the digesting local proxy after a fault probe.
start_daemon_proxy() {
  start_unit "$proxy_unit" "$mta_user" python3 "$runtime_helper" proxy \
    --address 127.0.0.1 --port 18079 --target-address 127.0.0.1 \
    --target-port 18080 --output "$state_root/daemon-proxy.log" ||
    fail "daemon digest proxy did not become active"
  for _ in {1..100}; do
    nc -z 127.0.0.1 18079 >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  fail "daemon digest proxy did not become live"
}

# daemon_metric returns one exact low-cardinality daemon counter value.
daemon_metric() {
  local operation=$1 value
  value=$(
    curl -fsS http://127.0.0.1:18080/metrics |
      awk -v operation="$operation" '
        $1 == "dkim2d_http_requests_total{operation=\"" operation \
          "\",status_class=\"2xx\"}" { count++; value = $2 }
        END {
          if (count == 0) print 0
          else if (count == 1 && value ~ /^[0-9]+$/) print value
        }
      '
  )
  [[ $value =~ ^[0-9]+$ ]] ||
    fail "daemon metric was missing, duplicated, or non-integral"
  printf '%s\n' "$value"
}

# proxy_route_count counts digest-bound calls made through the real daemon proxy.
proxy_route_count() {
  local route=$1
  if [[ ! -f $state_root/daemon-proxy.log ]]; then
    printf '%s\n' 0
    return
  fi
  awk -v route="$route" '$1 == "route=" route { count++ }
    END { print count + 0 }' "$state_root/daemon-proxy.log"
}

# proxy_route_digest returns one field from the latest exact route record.
proxy_route_digest() {
  local route=$1 field=$2 value
  value=$(
    awk -v route="$route" -v field="$field" '
      $1 == "route=" route {
        for (field_index = 1; field_index <= NF; field_index++) {
          split($field_index, pair, "=")
          if (pair[1] == field) value = pair[2]
        }
      }
      END { print value }
    ' "$state_root/daemon-proxy.log"
  )
  [[ $value =~ ^[0-9a-f]{64}$ ]] ||
    fail "daemon proxy digest was missing or noncanonical"
  printf '%s\n' "$value"
}

# proxy_route_value returns one bounded scalar from the latest route record.
proxy_route_value() {
  local route=$1 field=$2 value
  value=$(
    awk -v route="$route" -v field="$field" '
      $1 == "route=" route {
        for (field_index = 1; field_index <= NF; field_index++) {
          split($field_index, pair, "=")
          if (pair[1] == field) value = pair[2]
        }
      }
      END { print value }
    ' "$state_root/daemon-proxy.log"
  )
  [[ -n $value && $value =~ ^[a-zA-Z0-9._+-]+$ ]] ||
    fail "daemon proxy scalar was missing or noncanonical"
  printf '%s\n' "$value"
}

# adapter_event_count counts one exact redacted terminal event in a unit journal.
adapter_event_count() {
  local unit=$1 result=$2
  journalctl --quiet --unit "$unit" --output=cat |
    awk -v result="$result" '
      index($0, "\"event\":\"exim_adapter\"") &&
      index($0, "\"operation\":\"process\"") &&
      index($0, "\"result\":\"" result "\"") { count++ }
      END { print count + 0 }
    '
}

# delivery_marker_count counts one unique qualification body marker.
delivery_marker_count() {
  local marker=$1
  if [[ ! -f $state_root/delivered.mbox ]]; then
    printf '%s\n' 0
    return
  fi
  grep -aFc -- "body-$marker" "$state_root/delivered.mbox" || true
}

# authentication_results_count counts authoritative generated fields.
authentication_results_count() {
  if [[ ! -f $state_root/delivered.mbox ]]; then
    printf '%s\n' 0
    return
  fi
  grep -ac '^Authentication-Results: mx\.example\.test;' \
    "$state_root/delivered.mbox" || true
}

# sha256_text hashes one in-memory invocation binding without retaining inputs.
sha256_text() {
  printf '%s' "$1" | sha256sum | awk '{ print $1 }'
}

# metadata_value reads one unique non-empty helper metadata field.
metadata_value() {
  local path=$1 key=$2 value
  value=$(
    awk -F= -v key="$key" '
      $1 == key {
        count++
        value = substr($0, length(key) + 2)
      }
      END { if (count == 1) print value }
    ' "$path"
  )
  [[ -n $value ]] ||
    fail "capture metadata field was missing or duplicated"
  printf '%s\n' "$value"
}

# inspect_message writes one independent, content-free fixture or delivery measurement.
inspect_message() {
  local message=$1 wire_format=$2 metadata=$3
  python3 "$runtime_helper" inspect-message --message "$message" \
    --wire-format "$wire_format" --metadata-output "$metadata"
}

# run_fidelity_case proves one message byte class across fixture, daemon, and SMTP delivery.
run_fidelity_case() {
  local logical_case=$1 fixture=$2 wire_format=$3 smtp_utf8=${4:-false}
  local capture_unit="$unit_prefix-$logical_case-capture"
  local capture="$state_root/$logical_case.capture"
  local fixture_metadata="$state_root/$logical_case.fixture.metadata"
  local delivery_message="$state_root/$logical_case.delivery.eml"
  local delivery_metadata="$state_root/$logical_case.delivery.metadata"
  local started finished invocation process_before process_after event_before event_after
  local fixture_body delivery_body daemon_message delivery_message_hash
  local daemon_stable delivery_stable daemon_first_received delivery_first_received
  local fixture_lf fixture_crlf fixture_bare_lf delivery_duplicates delivery_folded
  local delivery_body_hash delivery_nonascii exim_observation
  inspect_message "$fixture" "$wire_format" "$fixture_metadata"
  start_smtp_capture "$capture_unit" "$capture"
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  process_before=$(daemon_metric process)
  event_before=$(adapter_event_count "$exact_adapter_unit" success)
  smtp_submit_file "$state_root/$logical_case.smtp" matrix@example.test \
    capture@fidelity.test "$fixture" "$wire_format" "$smtp_utf8"
  [[ $(smtp_final_reply "$state_root/$logical_case.smtp") =~ ^250[[:space:]-] ]] ||
    fail "fidelity SMTP submission was not accepted"
  run_exim "$exact_exim_unit" -qff
  wait_for_path "$capture" file ||
    fail "fidelity SMTP delivery did not reach the independent capture"
  finish_unit "$capture_unit"
  process_after=$(daemon_metric process)
  event_after=$(adapter_event_count "$exact_adapter_unit" success)
  [[ $process_after -eq $((process_before + 1)) &&
    $event_after -eq $((event_before + 1)) ]] ||
    fail "fidelity path did not make exactly one adapter and daemon call"
  python3 "$runtime_helper" unpack --capture "$capture" \
    --message-output "$delivery_message" \
    --metadata-output "$state_root/$logical_case.capture.metadata"
  inspect_message "$delivery_message" crlf "$delivery_metadata"
  fixture_body=$(metadata_value "$fixture_metadata" body_sha256)
  delivery_body=$(metadata_value "$delivery_metadata" body_sha256)
  daemon_message=$(proxy_route_digest process message_raw_sha256)
  delivery_message_hash=$(metadata_value "$delivery_metadata" canonical_sha256)
  daemon_stable=$(proxy_route_digest process message_stable_sha256)
  delivery_stable=$(metadata_value "$delivery_metadata" stable_sha256)
  daemon_first_received=$(
    proxy_route_value process message_first_header_received
  )
  delivery_first_received=$(
    metadata_value "$delivery_metadata" first_header_received
  )
  [[ $fixture_body == "$delivery_body" &&
    $daemon_first_received == 1 && $delivery_first_received == 1 &&
    $daemon_stable == "$delivery_stable" ]] ||
    fail "fidelity measurements disagree: case=$logical_case body=$([[ $fixture_body == "$delivery_body" ]] && printf match || printf mismatch) stable-message=$([[ $daemon_stable == "$delivery_stable" ]] && printf match || printf mismatch) received=$daemon_first_received:$delivery_first_received"
  fixture_lf=$(metadata_value "$fixture_metadata" raw_lf_count)
  fixture_crlf=$(metadata_value "$fixture_metadata" raw_crlf_count)
  fixture_bare_lf=$(metadata_value "$fixture_metadata" raw_bare_lf_count)
  delivery_duplicates=$(metadata_value "$delivery_metadata" x_duplicate_count)
  delivery_folded=$(metadata_value "$delivery_metadata" x_duplicate_folded_count)
  delivery_body_hash=$(metadata_value "$delivery_metadata" body_sha256)
  delivery_nonascii=$(metadata_value "$delivery_metadata" nonascii_octets)
  case "$logical_case" in
    lf)
      [[ $fixture_bare_lf -gt 0 && $fixture_crlf -eq 0 ]] ||
        fail "LF fixture measurement changed"
      exim_observation="smtp-final-250,deliveries-1,stable-input-sha256-$daemon_stable,stable-output-sha256-$delivery_stable,lf-count-$fixture_lf,crlf-count-$fixture_crlf"
      ;;
    crlf)
      [[ $fixture_crlf -gt 0 && $fixture_bare_lf -eq 0 ]] ||
        fail "CRLF fixture measurement changed"
      exim_observation="smtp-final-250,deliveries-1,stable-input-sha256-$daemon_stable,stable-output-sha256-$delivery_stable,crlf-count-$fixture_crlf,bare-lf-count-$fixture_bare_lf"
      ;;
    duplicate-folded)
      [[ $delivery_duplicates -eq 2 && $delivery_folded -eq 1 ]] ||
        fail "duplicate folded delivery readback changed"
      exim_observation="smtp-final-250,deliveries-1,header-order-sha256-$(metadata_value "$delivery_metadata" header_order_sha256),duplicate-count-$delivery_duplicates,folded-count-$delivery_folded"
      ;;
    binary-body)
      [[ $(metadata_value "$delivery_metadata" nul_count) -eq 1 ]] ||
        fail "binary delivery readback changed"
      exim_observation="smtp-final-250,deliveries-1,body-input-sha256-$fixture_body,body-output-sha256-$delivery_body_hash,nul-count-1"
      ;;
    smtputf8-rfc6532)
      [[ $delivery_nonascii -gt 0 ]] ||
        fail "SMTPUTF8 delivery readback changed"
      exim_observation="smtp-final-250,deliveries-1,stable-input-sha256-$daemon_stable,stable-output-sha256-$delivery_stable,nonascii-octets-$delivery_nonascii"
      ;;
    *) fail "fidelity case is outside the qualification contract" ;;
  esac
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text "$row:$logical_case:$daemon_message:$delivery_message_hash:$started")
  write_live_case smtp "$logical_case" "$invocation" "$started" "$finished" \
    "$exim_observation" \
    'operation-process,result-pass,actions-admitted' \
    'route-process,http-2xx-1,result-pass' \
    'fault-mode-none,outcome-not-applicable' \
    'version-match,build-id-match,validator-pass'
}

# run_forged_authentication_results_case proves local claims are replaced at capture.
run_forged_authentication_results_case() {
  local fixture=$1 capture_unit="$unit_prefix-forged-ar-capture"
  local capture="$state_root/forged-authentication-results.capture"
  local delivery="$state_root/forged-authentication-results.delivery.eml"
  local metadata="$state_root/forged-authentication-results.delivery.metadata"
  local started finished invocation process_before process_after event_before event_after
  local incoming_claims delivery_claims first_header header_order
  inspect_message "$fixture" crlf "$state_root/forged-authentication-results.fixture.metadata"
  incoming_claims=$(metadata_value "$state_root/forged-authentication-results.fixture.metadata" authentication_results_count)
  [[ $incoming_claims -eq 1 ]] || fail "forged fixture did not contain one local claim"
  start_smtp_capture "$capture_unit" "$capture"
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  process_before=$(daemon_metric process)
  event_before=$(adapter_event_count "$exact_adapter_unit" success)
  smtp_submit_file "$state_root/forged-authentication-results.smtp" \
    matrix@example.test capture@fidelity.test "$fixture" crlf
  [[ $(smtp_final_reply "$state_root/forged-authentication-results.smtp") =~ ^250[[:space:]-] ]] ||
    fail "forged Authentication-Results submission was not accepted"
  run_exim "$exact_exim_unit" -qff
  wait_for_path "$capture" file ||
    fail "forged Authentication-Results delivery did not reach capture"
  finish_unit "$capture_unit"
  process_after=$(daemon_metric process)
  event_after=$(adapter_event_count "$exact_adapter_unit" success)
  [[ $process_after -eq $((process_before + 1)) &&
    $event_after -eq $((event_before + 1)) ]] ||
    fail "forged Authentication-Results did not traverse exactly one authority path"
  python3 "$runtime_helper" unpack --capture "$capture" \
    --message-output "$delivery" --metadata-output "$state_root/forged-authentication-results.capture.metadata"
  inspect_message "$delivery" crlf "$metadata"
  delivery_claims=$(metadata_value "$metadata" authentication_results_count)
  first_header=$(metadata_value "$metadata" first_header)
  header_order=$(metadata_value "$metadata" header_order_sha256)
  [[ $delivery_claims -eq 1 && $first_header == authentication-results ]] ||
    fail "forged Authentication-Results claim was not replaced at the message top"
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text "$row:forged-authentication-results:$header_order:$started")
  write_live_case smtp forged-authentication-results "$invocation" "$started" "$finished" \
    'smtp-final-250,deliveries-1' \
    "operation-process,incoming-local-claims-$incoming_claims,removed-local-claims-$incoming_claims,generated-top-1,header-order-sha256-$header_order" \
    'route-process,http-2xx-1,result-pass' \
    'fault-mode-none,outcome-not-applicable' \
    'version-match,build-id-match,validator-pass'
}

# write_live_case binds sanitized transcripts to one measured case result.
write_live_case() {
  local category=$1 logical_case=$2 invocation=$3 case_started=$4
  local case_finished=$5
  shift 5
  local -a observations=("$@")
  local contract_value proof exim_assertion adapter_assertion
  local dkim2d_assertion fault_assertion readback_assertion
  local -a assertions components
  local component assertion observation producer transcript artifact
  local transcript_hash index
  local -A artifact_hashes=()
  [[ ${#observations[@]} -eq 5 ]] ||
    fail "live case does not contain every component observation"
  [[ $invocation =~ ^[0-9a-f]{64}$ ]] ||
    fail "live case invocation identifier is not canonical"
  contract_value=$(real_matrix_expected_contract "$category" "$logical_case") ||
    fail "live case is outside the qualification contract"
  read -r proof exim_assertion adapter_assertion dkim2d_assertion \
    fault_assertion readback_assertion <<<"$contract_value"
  assertions=(
    "$exim_assertion"
    "$adapter_assertion"
    "$dkim2d_assertion"
    "$fault_assertion"
    "$readback_assertion"
  )
  mapfile -t components < <(real_matrix_components)
  for index in "${!components[@]}"; do
    component=${components[index]}
    assertion=${assertions[index]}
    observation=${observations[index]}
    [[ ${#observation} -le 1024 &&
      $observation =~ ^[a-z0-9][a-z0-9._,:+-]*$ ]] ||
      fail "live case observation is not sanitized and bounded"
    case "$component" in
      exim) producer=$binary_sha256 ;;
      adapter) producer=$adapter_sha256 ;;
      dkim2d) producer=$daemon_sha256 ;;
      fault) producer=$runner_sha256 ;;
      readback) producer=$deployment_validator_sha256 ;;
      *) fail "live case component is outside the contract" ;;
    esac
    transcript="$evidence_stage/$category--$logical_case--$component.transcript"
    artifact="$evidence_stage/$category--$logical_case--$component.artifact"
    printf '%s\n' "observation=$observation" >"$transcript"
    chmod 0600 "$transcript"
    transcript_hash=$(sha256sum "$transcript" | awk '{ print $1 }')
    printf '%s\n' \
      'format=dkim2-exim-real-artifact-v1' \
      "row=$row" \
      "category=$category" \
      "case=$logical_case" \
      "component=$component" \
      "assertion=$assertion" \
      "producer_sha256=$producer" \
      "transcript_sha256=$transcript_hash" \
      "run_id=$run_id" \
      "invocation_sha256=$invocation" \
      "started_at=$case_started" \
      "finished_at=$case_finished" \
      'privacy_scan=passed' \
      'status=passed' >"$artifact"
    chmod 0600 "$artifact"
    artifact_hashes[$component]=$(
      sha256sum "$artifact" | awk '{ print $1 }'
    )
  done
  printf '%s\n' \
    'format=dkim2-exim-real-case-v1' \
    "row=$row" \
    "category=$category" \
    "case=$logical_case" \
    "exim_version=$expected_version" \
    "build_id=$expected_build_id" \
    "binary_sha256=$binary_sha256" \
    "run_id=$run_id" \
    "invocation_sha256=$invocation" \
    "started_at=$case_started" \
    "finished_at=$case_finished" \
    "exim_artifact_sha256=${artifact_hashes[exim]}" \
    "adapter_artifact_sha256=${artifact_hashes[adapter]}" \
    "dkim2d_artifact_sha256=${artifact_hashes[dkim2d]}" \
    "fault_artifact_sha256=${artifact_hashes[fault]}" \
    "readback_artifact_sha256=${artifact_hashes[readback]}" \
    "proof=$proof" \
    'status=passed' \
    >"$evidence_stage/$category--$logical_case.case"
  chmod 0600 "$evidence_stage/$category--$logical_case.case"
  case_count=$((case_count + 1))
}

# write_adapter_config seals one inbound configuration for the MTA identity.
write_adapter_config() {
  local build_id=$1 failure_mode=$2 authentication_results=${3:-true}
  local daemon_endpoint=${4:-http://127.0.0.1:18079} authserv_line=
  if [[ $authentication_results == true ]]; then
    authserv_line='  authserv_id: mx.example.test'
  fi
  chmod 0700 "$config_root"
  {
    printf '%s\n' \
      'version: dkim2-exim-config-v1' \
      'inbound:' \
      "  socket: $socket_root/local-scan.sock" \
      '  socket_mode: "0600"' \
      "  peer_uid: $mta_uid" \
      '  allowed_build_ids:' \
      "    - $build_id" \
      '  request_timeout: 3s' \
      '  max_connections: 4' \
      '  max_in_flight_messages: 1' \
      '  max_buffered_bytes: 268435456' \
      'daemon:' \
      "  endpoint: $daemon_endpoint" \
      "  process_capability_file: $adapter_cap_root/capability" \
      '  request_timeout: 2s' \
      'authentication_results:' \
      "  enabled: $authentication_results" \
      "$authserv_line" \
      'failure:' \
      "  inbound: $failure_mode" \
      'evidence:' \
      '  enabled: true' \
      "  root: $evidence_state_root" \
      "  key_file: $evidence_key_root/evidence.key" \
      "  readiness_file: $readiness_root/state" \
      '  retention: 1h0m0s' \
      '  max_records: 128' \
      '  max_bytes: 16777216' \
      'limits:' \
      '  message_bytes: 33554432' \
      '  header_bytes: 1048576' \
      '  header_count: 2000' \
      '  header_field_bytes: 65536' \
      '  recipient_count: 2000' \
      'observability:' \
      '  logging:' \
      '    level: info' \
      '    destination: stderr'
  } >"$config_root/dkim2-exim.yaml"
  chown "$mta_uid:$mta_gid" "$config_root/dkim2-exim.yaml"
  chmod 0400 "$config_root/dkim2-exim.yaml"
  chmod 0500 "$config_root"
}

# start_adapter starts the real adapter and proves its exact socket is live.
start_adapter() {
  local unit=$1
  [[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
    fail "adapter socket pathname was not clean before startup"
  systemd-run --quiet --unit "$unit" --uid="$mta_user" \
    --property=Type=exec --property=TimeoutStopSec=15s \
    --property="RootDirectory=$adapter_root" \
    --property='MountAPIVFS=yes' \
    --property="BindPaths=$runtime_parent:$runtime_parent" -- \
    "$adapter_binary" --config "$config_root/dkim2-exim.yaml" serve
  active_units+=("$unit")
  for _ in {1..100}; do
    [[ $(systemctl is-active "$unit") == active ]] && break
    sleep 0.1
  done
  [[ $(systemctl is-active "$unit") == active ]] || {
    journalctl --quiet --unit "$unit" --output=cat >&2
    fail "adapter transient unit did not become active"
  }
  wait_for_path "$socket_root/local-scan.sock" socket || {
    journalctl --quiet --unit "$unit" --output=cat >&2
    find "$socket_root" -maxdepth 1 -printf '%f:%y:%m\n' >&2
    fail "adapter socket did not become live"
  }
}

# start_exim starts the selected source-linked Exim and proves SMTP is live.
start_exim() {
  local unit=$1 selected_config=${2:-$config_root/exim.conf}
  [[ ! -L $selected_config && -f $selected_config ]] ||
    fail "real Exim configuration is unavailable"
  systemd-run --quiet --unit "$unit" --property=Type=exec \
    --property=TimeoutStopSec=15s \
    --property="RootDirectory=$adapter_root" \
    --property='MountAPIVFS=yes' \
    --property="BindReadOnlyPaths=$selected_config:/etc/exim.conf" \
    --property="BindReadOnlyPaths=/etc/passwd:/etc/passwd" \
    --property="BindReadOnlyPaths=/etc/group:/etc/group" \
    --property="BindReadOnlyPaths=/etc/nsswitch.conf:/etc/nsswitch.conf" \
    --property="BindReadOnlyPaths=/etc/services:/etc/services" \
    --property="BindReadOnlyPaths=/usr/bin/python3:/usr/bin/python3" \
    --property="BindReadOnlyPaths=/usr/lib:/usr/lib" \
    --property="BindReadOnlyPaths=/lib:/lib" \
    --property="BindReadOnlyPaths=/lib64:/lib64" \
    --property="BindPaths=$runtime_parent:$runtime_parent" \
    -- /usr/exim/bin/exim -bdf -oX 2525
  active_units+=("$unit")
  for _ in {1..100}; do
    [[ $(systemctl is-active "$unit") == active ]] && break
    sleep 0.1
  done
  [[ $(systemctl is-active "$unit") == active ]] || {
    journalctl --quiet --unit "$unit" --output=cat >&2
    fail "real Exim transient unit did not become active"
  }
  for _ in {1..100}; do
    nc -z 127.0.0.1 2525 >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  fail "real Exim listener did not become live"
}

# run_local_scan_fault_case measures one real source-linked SMTP hook failure.
run_local_scan_fault_case() {
  local logical_case=$1 selected_config=$2 helper_mode=${3:-}
  local exim_unit="$unit_prefix-$logical_case-exim"
  local helper_unit="$unit_prefix-$logical_case-peer"
  local helper_result="$state_root/$logical_case.peer"
  local started finished invocation transcript_hash peer_hash reply reply_code
  local expected_reply=451
  case "$logical_case" in
    smtp-timeout | smtp-crash) expected_reply=421 ;;
  esac
  if [[ -n $helper_mode ]]; then
    start_local_scan_fault "$helper_unit" "$helper_mode" "$helper_result"
  fi
  start_exim "$exim_unit" "$selected_config"
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit "$state_root/$logical_case.smtp" matrix@example.test \
    local@local.test "$logical_case"
  reply=$(smtp_final_reply "$state_root/$logical_case.smtp")
  if [[ ! $reply =~ ^${expected_reply}[[:space:]-] ]]; then
    reply_code=${reply:0:3}
    [[ $reply_code =~ ^[0-9]{3}$ ]] || reply_code=invalid
    case "$reply" in
      "") fail "real local-scan $logical_case case returned no final SMTP reply" ;;
      2*) fail "real local-scan $logical_case case accepted SMTP" ;;
      4*) fail "real local-scan $logical_case case returned SMTP $reply_code instead of $expected_reply" ;;
      5*) fail "real local-scan $logical_case case permanently rejected SMTP" ;;
      *) fail "real local-scan $logical_case case returned an invalid SMTP reply" ;;
    esac
  fi
  [[ $(delivery_marker_count "$logical_case") -eq 0 ]] ||
    fail "real local-scan fault reached delivery"
  if [[ -n $helper_mode ]]; then
    wait_for_path "$helper_result" file ||
      fail "local-scan fault peer did not measure the real caller"
    grep -Fxq "mode=$helper_mode" "$helper_result" &&
      grep -Fxq 'peer_uid_match=1' "$helper_result" &&
      grep -Fxq 'request_observed=1' "$helper_result" ||
      fail "local-scan fault peer readback changed"
    peer_hash=$(sha256sum "$helper_result" | awk '{ print $1 }')
  else
    [[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
      fail "C-to-Go unavailable case unexpectedly had a socket"
    peer_hash=$(sha256_text no-local-scan-peer)
  fi
  transcript_hash=$(sha256sum "$state_root/$logical_case.smtp" | awk '{ print $1 }')
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:$logical_case:$transcript_hash:$peer_hash:$started:$finished")
  stop_unit "$exim_unit"
  if [[ -n $helper_mode ]]; then
    finish_unit "$helper_unit"
    [[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
      fail "local-scan fault peer did not remove its owned socket"
  fi
  write_live_case smtp "$logical_case" "$invocation" "$started" "$finished" \
    "smtp-final-$expected_reply,deliveries-0" \
    'operation-process,result-tempfail,mail-output-0' \
    'authority-calls-0' \
    "fault-$logical_case,outcome-smtp-$expected_reply" \
    'version-match,build-id-match,validator-pass'
}

# run_non_smtp_fault_case proves official local-input drop and exit semantics.
run_non_smtp_fault_case() {
  local logical_case=$1 selected_config=$2 helper_mode=$3 log_pattern=$4
  local exim_unit="$unit_prefix-$logical_case-exim"
  local helper_unit="$unit_prefix-$logical_case-peer"
  local helper_result="$state_root/$logical_case.peer"
  local submission_output="$state_root/$logical_case.submission"
  local started finished invocation output_hash peer_hash status
  local log_before log_after queue_before queue_after exim_observation
  start_local_scan_fault "$helper_unit" "$helper_mode" "$helper_result"
  start_exim "$exim_unit" "$selected_config"
  queue_before=$(run_exim "$exim_unit" -bpc)
  [[ $queue_before -eq 0 ]] ||
    fail "non-SMTP fault case did not start with an empty queue"
  log_before=$(
    grep -Fac "$log_pattern" "$state_root/exim-main.log" 2>/dev/null || true
  )
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  set +e
  printf '%s\n' \
    'From: matrix@example.test' \
    'To: local@local.test' \
    "Subject: $logical_case" \
    '' \
    "body-$logical_case" |
    run_exim "$exim_unit" -odf -f matrix@example.test local@local.test \
      >"$submission_output" 2>&1
  status=$?
  set -e
  [[ $status -ne 0 ]] ||
    fail "non-SMTP local-scan fault unexpectedly exited successfully"
  queue_after=$(run_exim "$exim_unit" -bpc)
  [[ $queue_after -eq 0 ]] ||
    fail "non-SMTP local-scan fault retained a queued message"
  [[ $(delivery_marker_count "$logical_case") -eq 0 ]] ||
    fail "non-SMTP local-scan fault reached delivery"
  log_after=$(
    grep -Fac "$log_pattern" "$state_root/exim-main.log" 2>/dev/null || true
  )
  [[ $log_after -eq $((log_before + 1)) ]] ||
    fail "non-SMTP local-scan fault log readback changed"
  wait_for_path "$helper_result" file ||
    fail "non-SMTP fault peer did not measure the real caller"
  grep -Fxq "mode=$helper_mode" "$helper_result" &&
    grep -Fxq 'peer_uid_match=1' "$helper_result" &&
    grep -Fxq 'request_observed=1' "$helper_result" ||
    fail "non-SMTP fault peer readback changed"
  output_hash=$(sha256sum "$submission_output" | awk '{ print $1 }')
  peer_hash=$(sha256sum "$helper_result" | awk '{ print $1 }')
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:$logical_case:$status:$output_hash:$peer_hash:$started:$finished")
  stop_unit "$exim_unit"
  finish_unit "$helper_unit"
  [[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
    fail "non-SMTP fault peer did not remove its owned socket"
  case "$logical_case" in
    non-smtp-drop)
      exim_observation='submission-complete,message-dropped-1,deliveries-0'
      ;;
    nonzero-exit)
      exim_observation='submission-exit-nonzero,deliveries-0'
      ;;
    *)
      fail "non-SMTP fault case is outside the qualification contract"
      ;;
  esac
  write_live_case local-submission "$logical_case" "$invocation" \
    "$started" "$finished" \
    "$exim_observation" \
    'operation-process,result-drop,mail-output-0' \
    'authority-calls-0' \
    "fault-$logical_case,outcome-local-drop" \
    'version-match,build-id-match,validator-pass'
}

# run_transport_envelope_case proves the exact current transport reverse path.
run_transport_envelope_case() {
  local logical_case=$1 sender=$2 recipient=$3 expected_reverse=$4
  local capture_unit="$unit_prefix-$logical_case-capture"
  local capture="$state_root/$logical_case.capture"
  local smtp_output="$state_root/$logical_case.smtp"
  local started finished invocation transcript_hash capture_hash
  local sign_before sign_after proxy_before proxy_after observed_reverse
  local expected_reverse_hash
  start_smtp_capture "$capture_unit" "$capture"
  sign_before=$(daemon_metric sign)
  proxy_before=$(proxy_route_count sign)
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit "$smtp_output" "$sender" "$recipient" "$logical_case"
  [[ $(smtp_final_reply "$smtp_output") =~ ^250[[:space:]-] ]] ||
    fail "transport envelope case was not accepted into the real queue"
  run_exim "$exact_exim_unit" -qff
  wait_for_path "$capture" file ||
    fail "transport envelope case did not reach the downstream SMTP peer"
  finish_unit "$capture_unit"
  sign_after=$(daemon_metric sign)
  proxy_after=$(proxy_route_count sign)
  [[ $sign_after -eq $((sign_before + 1)) &&
    $proxy_after -eq $((proxy_before + 1)) ]] ||
    fail "transport envelope case did not traverse one signing authority"
  [[ $(grep -aFc "MAIL FROM:<$expected_reverse>" "$capture") -eq 1 ]] ||
    fail "downstream SMTP reverse path did not match the expected current path"
  if [[ -n $expected_reverse ]]; then
    expected_reverse_hash=$(
      printf '"<%s>"' "$expected_reverse" | sha256sum | awk '{ print $1 }'
    )
  else
    expected_reverse_hash=$(
      printf '"<>"' | sha256sum | awk '{ print $1 }'
    )
  fi
  observed_reverse=$(proxy_route_digest sign outgoing_reverse_sha256)
  [[ $observed_reverse == "$expected_reverse_hash" ]] ||
    fail "daemon reverse-path projection did not match downstream SMTP"
  [[ $(proxy_route_value sign actions) == 2 &&
    $(proxy_route_value sign status) == 200 ]] ||
    fail "transport envelope action plan changed"
  transcript_hash=$(sha256sum "$smtp_output" | awk '{ print $1 }')
  capture_hash=$(sha256sum "$capture" | awk '{ print $1 }')
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:$logical_case:$transcript_hash:$capture_hash:$observed_reverse:$started")
  write_live_case transport-filter "$logical_case" "$invocation" \
    "$started" "$finished" \
    'transport-exit-0,deliveries-1' \
    'operation-sign,result-pass,generated-fields-2' \
    'route-sign,http-2xx-1,result-pass,fields-2' \
    'fault-mode-none,outcome-not-applicable' \
    'version-match,build-id-match,validator-pass'
}

# run_bcc_safe_case proves one recipient and no Bcc disclosure per invocation.
run_bcc_safe_case() {
  local capture_unit="$unit_prefix-bcc-safe-capture"
  local capture="$state_root/bcc-safe.capture"
  local metadata="$state_root/bcc-safe.capture-set.metadata"
  local started finished invocation output_hash request_hash response_hash
  local revise_before revise_after proxy_before proxy_after
  start_smtp_capture "$capture_unit" "$capture"
  revise_before=$(daemon_metric revise)
  proxy_before=$(proxy_route_count revise)
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit_file "$state_root/bcc-safe.smtp" sender@origin.example.test \
    recipient@origin.example.test "$state_root/signed.eml"
  [[ $(smtp_final_reply "$state_root/bcc-safe.smtp") =~ ^250[[:space:]-] ]] ||
    fail "Bcc-safe fixture was not accepted into the real queue"
  run_exim "$exact_exim_unit" -qff
  wait_for_path "$capture" file ||
    fail "Bcc-safe delivery did not reach the downstream SMTP peer"
  finish_unit "$capture_unit"
  revise_after=$(daemon_metric revise)
  proxy_after=$(proxy_route_count revise)
  [[ $revise_after -eq $((revise_before + 1)) &&
    $proxy_after -eq $((proxy_before + 1)) ]] ||
    fail "Bcc-safe delivery did not traverse one revision authority"
  python3 "$runtime_helper" inspect-capture-set --capture "$capture" \
    --metadata-output "$metadata"
  [[ $(metadata_value "$metadata" delivery_count) == 1 &&
    $(metadata_value "$metadata" minimum_recipient_count) == 1 &&
    $(metadata_value "$metadata" maximum_recipient_count) == 1 &&
    $(metadata_value "$metadata" bcc_marker_count) == 0 ]] ||
    fail "Bcc-safe delivery exposed a batch or Bcc marker"
  output_hash=$(metadata_value "$metadata" payload_set_sha256)
  request_hash=$(proxy_route_digest revise request_sha256)
  response_hash=$(proxy_route_digest revise response_sha256)
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:bcc-safe:$output_hash:$request_hash:$response_hash:$started")
  write_live_case transport-filter bcc-safe "$invocation" \
    "$started" "$finished" \
    "transport-exit-0,deliveries-1,invocation-sha256-$invocation,recipient-count-1,pipe-argv-count-1,bcc-marker-count-0,output-sha256-$output_hash" \
    "operation-revise,result-pass,invocation-sha256-$invocation,recipient-count-1,pipe-argv-count-1,bcc-marker-count-0,output-sha256-$output_hash" \
    "route-revise,http-2xx-1,result-pass,invocation-sha256-$invocation,recipient-count-1,request-sha256-$request_hash,response-sha256-$response_hash" \
    'fault-mode-none,outcome-not-applicable' \
    'version-match,build-id-match,validator-pass'
}

# start_transport_fault_server starts one measured queue-time HTTP fault.
start_transport_fault_server() {
  local unit=$1 mode=$2 output=$3
  start_unit "$unit" "$mta_user" python3 "$runtime_helper" http \
    --address 127.0.0.1 --port 18078 --mode "$mode" --output "$output" ||
    fail "transport fault endpoint did not become active"
  for _ in {1..100}; do
    nc -z 127.0.0.1 18078 >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  fail "transport fault endpoint did not become live"
}

# run_transport_daemon_fault_case proves real Exim defers a reached HTTP fault.
run_transport_daemon_fault_case() {
  local logical_case=$1 helper_mode=$2
  local fault_unit="$unit_prefix-$logical_case-daemon-fault"
  local adapter_unit="$unit_prefix-$logical_case-adapter"
  local exim_unit="$unit_prefix-$logical_case-exim"
  local peer_unit="$unit_prefix-$logical_case-smtp-peer"
  local fault_output="$state_root/$logical_case.daemon-fault"
  local peer_output="$state_root/$logical_case.smtp-peer"
  local smtp_output="$state_root/$logical_case.smtp"
  local started finished invocation transcript_hash fault_hash peer_hash
  local queue_id_before queue_id_after
  local deferral_before deferral_after sign_before sign_after
  start_smtp_abort_peer "$peer_unit" "$peer_output"
  start_transport_fault_server "$fault_unit" "$helper_mode" "$fault_output"
  write_adapter_config "$expected_build_id" tempfail false
  start_adapter "$adapter_unit"
  start_exim "$exim_unit" "$config_root/exim-queue-fault.conf"
  [[ $(run_exim "$exim_unit" -bpc) -eq 0 ]] ||
    fail "transport daemon fault did not start with an empty queue"
  sign_before=$(daemon_metric sign)
  deferral_before=$(transport_filter_defer_count)
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit "$smtp_output" sender@origin.example.test \
    "$logical_case@origin.example.test" "$logical_case"
  [[ $(smtp_final_reply "$smtp_output") =~ ^250[[:space:]-] ]] ||
    fail "transport daemon fault fixture was not accepted into the real queue"
  queue_id_before=$(queued_message_id "$exim_unit")
  run_exim "$exim_unit" -qff
  queue_id_after=$(queued_message_id "$exim_unit")
  [[ $queue_id_after == "$queue_id_before" ]] ||
    fail "transport daemon fault replaced the original queued message"
  finish_smtp_abort_peer "$peer_unit" "$peer_output"
  sign_after=$(daemon_metric sign)
  [[ $sign_after -eq $sign_before ]] ||
    fail "transport fault endpoint unexpectedly reached the real daemon"
  deferral_after=$(transport_filter_defer_count)
  [[ $deferral_after -eq $((deferral_before + 1)) ]] ||
    fail "real Exim did not record one transport-filter exit-75 deferral"
  wait_for_path "$fault_output" file ||
    fail "transport fault endpoint did not record the filter request"
  [[ $(grep -Fxc "mode=$helper_mode calls=1" "$fault_output") -eq 1 ]] ||
    fail "transport fault endpoint request count changed"
  run_exim "$exim_unit" -Mrm "$queue_id_before" >/dev/null
  [[ $(run_exim "$exim_unit" -bpc) -eq 0 ]] ||
    fail "transport fault fixture did not leave an empty queue"
  transcript_hash=$(sha256sum "$smtp_output" | awk '{ print $1 }')
  fault_hash=$(sha256sum "$fault_output" | awk '{ print $1 }')
  peer_hash=$(sha256sum "$peer_output" | awk '{ print $1 }')
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:$logical_case:$transcript_hash:$fault_hash:$peer_hash:$started:$finished")
  stop_unit "$exim_unit"
  stop_unit "$adapter_unit"
  stop_unit "$fault_unit"
  write_live_case transport-filter "$logical_case" "$invocation" \
    "$started" "$finished" \
    'transport-exit-75,deliveries-0' \
    'operation-filter,result-defer,mail-output-not-accepted' \
    'route-filter,calls-1,fault-observed' \
    "fault-$logical_case,outcome-transport-deferred" \
    'version-match,build-id-match,validator-pass'
}

# run_nonascii_transport_case proves envelope rejection precedes sign authority.
run_nonascii_transport_case() {
  local adapter_unit="$unit_prefix-nonascii-envelope-adapter"
  local exim_unit="$unit_prefix-nonascii-envelope-exim"
  local peer_unit="$unit_prefix-nonascii-envelope-smtp-peer"
  local fixture="$state_root/nonascii-envelope.eml"
  local peer_output="$state_root/nonascii-envelope.smtp-peer"
  local smtp_output="$state_root/nonascii-envelope.smtp"
  local sender=$'s\303\244nder@origin.example.test'
  local started finished invocation transcript_hash peer_hash
  local queue_id_before queue_id_after
  local sign_before sign_after proxy_before proxy_after
  local deferral_before deferral_after
  printf '%s\n' \
    'From: sender@origin.example.test' \
    'To: nonascii-envelope@origin.example.test' \
    'Subject: nonascii-envelope' \
    '' \
    'body-nonascii-envelope' >"$fixture"
  start_smtp_abort_peer "$peer_unit" "$peer_output"
  write_adapter_config "$expected_build_id" tempfail false
  start_adapter "$adapter_unit"
  start_exim "$exim_unit" "$config_root/exim-queue-only.conf"
  [[ $(run_exim "$exim_unit" -bpc) -eq 0 ]] ||
    fail "non-ASCII transport case did not start with an empty queue"
  sign_before=$(daemon_metric sign)
  proxy_before=$(proxy_route_count sign)
  deferral_before=$(transport_filter_defer_count)
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit_file "$smtp_output" "$sender" \
    nonascii-envelope@origin.example.test "$fixture" lf true
  [[ $(smtp_final_reply "$smtp_output") =~ ^250[[:space:]-] ]] ||
    fail "non-ASCII envelope fixture was not accepted into the real queue"
  queue_id_before=$(queued_message_id "$exim_unit")
  run_exim "$exim_unit" -qff
  queue_id_after=$(queued_message_id "$exim_unit")
  [[ $queue_id_after == "$queue_id_before" ]] ||
    fail "non-ASCII envelope fault replaced the original queued message"
  finish_smtp_abort_peer "$peer_unit" "$peer_output"
  sign_after=$(daemon_metric sign)
  proxy_after=$(proxy_route_count sign)
  [[ $sign_after -eq $sign_before && $proxy_after -eq $proxy_before ]] ||
    fail "non-ASCII outgoing envelope reached signing authority"
  deferral_after=$(transport_filter_defer_count)
  [[ $deferral_after -eq $((deferral_before + 1)) ]] ||
    fail "non-ASCII outgoing envelope did not produce one exit-75 deferral"
  run_exim "$exim_unit" -Mrm "$queue_id_before" >/dev/null
  transcript_hash=$(sha256sum "$smtp_output" | awk '{ print $1 }')
  peer_hash=$(sha256sum "$peer_output" | awk '{ print $1 }')
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:nonascii-envelope:$transcript_hash:$peer_hash:$started:$finished")
  stop_unit "$exim_unit"
  stop_unit "$adapter_unit"
  write_live_case transport-filter nonascii-envelope "$invocation" \
    "$started" "$finished" \
    'transport-exit-75,deliveries-0' \
    'operation-rejected-before-authority,mail-output-0' \
    'authority-calls-0' \
    'fault-mode-none,outcome-not-applicable' \
    'version-match,build-id-match,validator-pass'
}

# run_filter_output_fault_case proves successful authority cannot mask exit 75.
run_filter_output_fault_case() {
  local logical_case=$1 selected_config=$2 expected_output_bytes=$3
  local adapter_unit="$unit_prefix-$logical_case-adapter"
  local exim_unit="$unit_prefix-$logical_case-exim"
  local peer_unit="$unit_prefix-$logical_case-smtp-peer"
  local result_output="$state_root/$logical_case.filter-fault"
  local peer_output="$state_root/$logical_case.smtp-peer"
  local smtp_output="$state_root/$logical_case.smtp"
  local started finished invocation transcript_hash result_hash peer_hash
  local queue_id_before queue_id_after
  local sign_before sign_after proxy_before proxy_after
  local deferral_before deferral_after
  start_smtp_abort_peer "$peer_unit" "$peer_output"
  write_adapter_config "$expected_build_id" tempfail false
  start_adapter "$adapter_unit"
  start_exim "$exim_unit" "$selected_config"
  [[ $(run_exim "$exim_unit" -bpc) -eq 0 ]] ||
    fail "filter output fault did not start with an empty queue"
  sign_before=$(daemon_metric sign)
  proxy_before=$(proxy_route_count sign)
  deferral_before=$(transport_filter_defer_count)
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit "$smtp_output" sender@origin.example.test \
    "$logical_case@origin.example.test" "$logical_case"
  [[ $(smtp_final_reply "$smtp_output") =~ ^250[[:space:]-] ]] ||
    fail "filter output fault fixture was not accepted into the real queue"
  queue_id_before=$(queued_message_id "$exim_unit")
  run_exim "$exim_unit" -qff
  queue_id_after=$(queued_message_id "$exim_unit")
  [[ $queue_id_after == "$queue_id_before" ]] ||
    fail "filter output fault replaced the original queued message"
  finish_smtp_abort_peer "$peer_unit" "$peer_output"
  sign_after=$(daemon_metric sign)
  proxy_after=$(proxy_route_count sign)
  [[ $sign_after -eq $((sign_before + 1)) &&
    $proxy_after -eq $((proxy_before + 1)) ]] ||
    fail "filter output fault did not traverse one successful real authority"
  wait_for_path "$result_output" file ||
    fail "filter output fault did not publish its bounded measurement"
  grep -Fxq 'child_exit=0' "$result_output" &&
    grep -Fxq "output_bytes=$expected_output_bytes" "$result_output" ||
    fail "filter output fault measurement changed"
  deferral_after=$(transport_filter_defer_count)
  [[ $deferral_after -eq $((deferral_before + 1)) ]] ||
    fail "filter output fault did not produce one exit-75 deferral"
  run_exim "$exim_unit" -Mrm "$queue_id_before" >/dev/null
  transcript_hash=$(sha256sum "$smtp_output" | awk '{ print $1 }')
  result_hash=$(sha256sum "$result_output" | awk '{ print $1 }')
  peer_hash=$(sha256sum "$peer_output" | awk '{ print $1 }')
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:$logical_case:$transcript_hash:$result_hash:$peer_hash:$started:$finished")
  stop_unit "$exim_unit"
  stop_unit "$adapter_unit"
  write_live_case transport-filter "$logical_case" "$invocation" \
    "$started" "$finished" \
    'transport-exit-75,deliveries-0' \
    'operation-filter,result-defer,mail-output-not-accepted' \
    'route-sign,http-2xx-1,result-pass,fields-2' \
    "fault-$logical_case,outcome-transport-deferred" \
    'version-match,build-id-match,validator-pass'
}

# run_daemon_unavailable_inbound_case proves the reached-service policy boundary.
run_daemon_unavailable_inbound_case() {
  local logical_case=$1 failure_mode=$2 expected_reply=$3
  local adapter_unit="$unit_prefix-$logical_case-adapter"
  local fault_unit="$unit_prefix-$logical_case-daemon-fault"
  local fault_output="$state_root/$logical_case.daemon-fault"
  local started finished invocation transcript_hash adapter_hash
  local process_before process_after warning_count fault_hash
  if [[ $failure_mode == fail_open ]]; then
    start_unit "$fault_unit" "$mta_user" python3 "$runtime_helper" http \
      --address 127.0.0.1 --port 18078 --mode timeout \
      --output "$fault_output" ||
      fail "reached-service fail-open endpoint did not become active"
    for _ in {1..100}; do
      nc -z 127.0.0.1 18078 >/dev/null 2>&1 && break
      sleep 0.1
    done
    nc -z 127.0.0.1 18078 >/dev/null 2>&1 ||
      fail "reached-service fail-open endpoint did not become live"
  fi
  write_adapter_config "$expected_build_id" "$failure_mode" true \
    http://127.0.0.1:18078
  start_adapter "$adapter_unit"
  process_before=$(daemon_metric process)
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit "$state_root/$logical_case.smtp" matrix@example.test \
    local@local.test "$logical_case"
  [[ $(smtp_final_reply "$state_root/$logical_case.smtp") =~ ^"$expected_reply"[[:space:]-] ]] ||
    fail "$logical_case inbound policy returned the wrong SMTP result"
  process_after=$(daemon_metric process)
  [[ $process_after -eq $process_before ]] ||
    fail "unavailable daemon case unexpectedly reached dkim2d"
  journalctl --quiet --unit "$adapter_unit" --output=cat \
    >"$state_root/$logical_case.adapter.log"
  if [[ $failure_mode == tempfail ]]; then
    grep -Eq '"event":"exim_adapter".*"result":"failure".*"failure":"unavailable".*"fail_open":false' \
      "$state_root/$logical_case.adapter.log" ||
      fail "closed daemon-unavailable event readback changed"
    [[ $(delivery_marker_count "$logical_case") -eq 0 ]] ||
      fail "closed daemon-unavailable case reached delivery"
  else
    warning_count=$(
      grep -Ec '"level":"WARN".*"event":"exim_adapter".*"failure":"unavailable".*"fail_open":true' \
        "$state_root/$logical_case.adapter.log" || true
    )
    [[ $warning_count -eq 1 ]] ||
      fail "reached-service fail-open did not record one mandatory warning"
    wait_for_path "$fault_output" file ||
      fail "reached-service fail-open endpoint did not record the request"
    [[ $(grep -Fxc 'mode=timeout calls=1' "$fault_output") -eq 1 ]] ||
      fail "reached-service fail-open request count changed"
    run_exim "$exact_exim_unit" -qff
    [[ $(delivery_marker_count "$logical_case") -eq 1 ]] ||
      fail "reached-service fail-open did not deliver exactly once"
  fi
  transcript_hash=$(sha256sum "$state_root/$logical_case.smtp" | awk '{ print $1 }')
  adapter_hash=$(sha256sum "$state_root/$logical_case.adapter.log" | awk '{ print $1 }')
  if [[ $failure_mode == fail_open ]]; then
    fault_hash=$(sha256sum "$fault_output" | awk '{ print $1 }')
  else
    fault_hash=$(sha256_text connection-refused)
  fi
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:$logical_case:$transcript_hash:$adapter_hash:$fault_hash:$started:$finished")
  stop_unit "$adapter_unit"
  if [[ $failure_mode == fail_open ]]; then
    stop_unit "$fault_unit"
  fi
  if [[ $failure_mode == tempfail ]]; then
    write_live_case smtp "$logical_case" "$invocation" "$started" "$finished" \
      'smtp-final-451,deliveries-0' \
      'operation-process,result-tempfail,mail-output-0' \
      'authority-calls-0' \
      'fault-daemon-unavailable-closed,outcome-smtp-451' \
      'version-match,build-id-match,validator-pass'
  else
    write_live_case smtp "$logical_case" "$invocation" "$started" "$finished" \
      'smtp-final-250,deliveries-1,fail-open-1' \
      'operation-process,result-pass,fail-open-warning-1' \
      'route-process,calls-1,fault-observed' \
      'fault-daemon-unavailable,outcome-fail-open-accepted' \
      'version-match,build-id-match,validator-pass'
  fi
}

# reset_evidence_runtime removes only owned qualification state while stopped.
reset_evidence_runtime() {
  find "$evidence_state_root" "$readiness_root" -mindepth 1 -maxdepth 1 \
    -delete
  [[ -z $(find "$evidence_state_root" "$readiness_root" -mindepth 1 \
    -maxdepth 1 -print -quit) ]] ||
    fail "owned evidence runtime did not reset cleanly"
}

# run_evidence_fault_case measures one real queue-time revision denial.
run_evidence_fault_case() {
  local logical_case=$1 mode=$2
  local adapter_unit="$unit_prefix-$logical_case-adapter"
  local exim_unit="$unit_prefix-$logical_case-exim"
  local peer_unit="$unit_prefix-$logical_case-smtp-peer"
  local peer_output="$state_root/$logical_case.smtp-peer"
  local smtp_output="$state_root/$logical_case.smtp"
  local started finished invocation record record_before record_after
  local queue_id_before queue_id_after transcript_hash peer_hash
  local process_before process_receive process_after
  local proxy_process_before proxy_process_receive proxy_process_after
  local revise_before revise_after deferral_before deferral_after
  local -a evidence_records
  reset_evidence_runtime
  start_smtp_abort_peer "$peer_unit" "$peer_output"
  write_adapter_config "$expected_build_id" tempfail false
  start_adapter "$adapter_unit"
  start_exim "$exim_unit" "$config_root/exim-queue-only.conf"
  [[ $(run_exim "$exim_unit" -bpc) -eq 0 ]] ||
    fail "evidence fault case did not start with an empty queue"
  process_before=$(daemon_metric process)
  proxy_process_before=$(proxy_route_count process)
  revise_before=$(daemon_metric revise)
  deferral_before=$(transport_filter_defer_count)
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  smtp_submit_file "$smtp_output" sender@origin.example.test \
    incoming@revise.test "$state_root/signed.eml"
  [[ $(smtp_final_reply "$smtp_output") =~ ^250[[:space:]-] ]] ||
    fail "evidence fault fixture was not accepted into the real queue"
  queue_id_before=$(queued_message_id "$exim_unit")
  process_receive=$(daemon_metric process)
  proxy_process_receive=$(proxy_route_count process)
  [[ $process_receive -eq $((process_before + 1)) ]] ||
    fail "evidence fault receive count changed: before=$process_before after=$process_receive"
  [[ $proxy_process_receive -eq $((proxy_process_before + 1)) ]] ||
    fail "evidence fault receive proxy count changed: before=$proxy_process_before after=$proxy_process_receive"
  mapfile -t evidence_records < <(
    find "$evidence_state_root" -mindepth 1 -maxdepth 1 -type f \
      -name '*.ev1' -print | sort
  )
  [[ ${#evidence_records[@]} -eq 1 ]] ||
    fail "evidence fault case did not publish exactly one record"
  record=${evidence_records[0]}
  record_before=$(sha256sum "$record" | awk '{ print $1 }')
  case "$mode" in
    missing)
      rm -f -- "$record"
      [[ ! -e $record && ! -L $record ]] ||
        fail "missing-evidence fault did not remove the exact record"
      record_after=$(sha256_text missing)
      ;;
    expired | tampered)
      python3 "$runtime_helper" evidence-fault --record "$record" \
        --key-file "$evidence_key_root/evidence.key" --mode "$mode"
      record_after=$(sha256sum "$record" | awk '{ print $1 }')
      [[ $record_after != "$record_before" ]] ||
        fail "evidence content fault did not change the exact record"
      ;;
    *)
      fail "evidence fault mode is outside the qualification contract"
      ;;
  esac
  run_exim "$exim_unit" -qff
  queue_id_after=$(queued_message_id "$exim_unit")
  [[ $queue_id_after == "$queue_id_before" ]] ||
    fail "evidence fault replaced the original queued message"
  finish_smtp_abort_peer "$peer_unit" "$peer_output"
  process_after=$(daemon_metric process)
  proxy_process_after=$(proxy_route_count process)
  revise_after=$(daemon_metric revise)
  [[ $process_after -eq $process_receive &&
    $proxy_process_after -eq $proxy_process_receive ]] ||
    fail "evidence fault unexpectedly created a second process authority call"
  [[ $revise_after -eq $revise_before ]] ||
    fail "evidence fault unexpectedly reached revision authority"
  deferral_after=$(transport_filter_defer_count)
  [[ $deferral_after -eq $((deferral_before + 1)) ]] ||
    fail "evidence fault did not record one transport-filter exit-75 deferral"
  run_exim "$exim_unit" -Mrm "$queue_id_before" >/dev/null
  [[ $(run_exim "$exim_unit" -bpc) -eq 0 ]] ||
    fail "owned evidence fixture did not leave an empty queue"
  transcript_hash=$(sha256sum "$smtp_output" | awk '{ print $1 }')
  peer_hash=$(sha256sum "$peer_output" | awk '{ print $1 }')
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  invocation=$(sha256_text \
    "$row:$logical_case:$transcript_hash:$record_before:$record_after:$peer_hash:$started:$finished")
  stop_unit "$exim_unit"
  stop_unit "$adapter_unit"
  reset_evidence_runtime
  write_live_case smtp "$logical_case" "$invocation" "$started" "$finished" \
    'smtp-final-250,transport-exit-75,deliveries-0' \
    'operation-revise,result-defer,mail-output-0' \
    'authority-calls-0' \
    "fault-$logical_case,outcome-transport-deferred" \
    'version-match,build-id-match,validator-pass'
}

# run_exim executes one command inside the trusted daemon config mount view.
run_exim() {
  local unit=$1 pid
  shift
  pid=$(systemctl show "$unit" --property=MainPID --value)
  [[ $pid =~ ^[1-9][0-9]*$ ]] ||
    fail "real Exim daemon PID is unavailable"
  nsenter -t "$pid" -m -r -- /usr/exim/bin/exim "$@"
}

require_absolute_regular "$exim_binary"
require_absolute_regular "$adapter_binary"
require_absolute_regular "$daemon_binary"
require_absolute_regular "$matrix_helper"
deployment_validator="$repository_root/cmd/dkim2-exim/packaging/validate-deployment.sh"
require_absolute_regular "$deployment_validator"
binary_sha256=$(sha256sum "$exim_binary" | awk '{ print $1 }')
adapter_sha256=$(sha256sum "$adapter_binary" | awk '{ print $1 }')
daemon_sha256=$(sha256sum "$daemon_binary" | awk '{ print $1 }')
runner_sha256=$(sha256sum "$0" | awk '{ print $1 }')
matrix_helper_sha256=$(sha256sum "$matrix_helper" | awk '{ print $1 }')
deployment_validator_sha256=$(
  sha256sum "$deployment_validator" | awk '{ print $1 }'
)
[[ $expected_build_id =~ ^[0-9a-f]{64}$ ]] ||
  fail "expected build identifier is not canonical"
[[ $run_id =~ ^[0-9a-f]{64}$ ]] ||
  fail "matrix run identifier is not canonical"
[[ $expected_version =~ ^[0-9][0-9A-Za-z.+:~_-]{0,127}$ ]] ||
  fail "expected Exim version is not bounded canonical text"
case "$row" in
  upstream-4.99.5 | debian-4.98.2-1+deb13u3 | debian-4.98.2-1+deb13u4 | \
    ubuntu-4.99.1-1ubuntu1.3 | ubuntu-4.99.1-1ubuntu1.4) ;;
  *) fail "row is outside the authenticated five-row matrix" ;;
esac
[[ $evidence_root == /* && ! -e $evidence_root && ! -L $evidence_root ]] ||
  fail "evidence root must be one fresh absolute path"
id "$row" >/dev/null 2>&1 && fail "row name collides with an account"
row_token=$(printf '%s' "$row" | sha256sum | awk '{ print substr($1, 1, 8) }')
dns_octet=$((32 + 16#${run_id:0:2} % 192))
dns_address="127.0.0.$dns_octet"
evidence_parent=$(dirname -- "$evidence_root")
evidence_name=$(basename -- "$evidence_root")
[[ $evidence_name != . && $evidence_name != .. &&
  $(readlink -f -- "$evidence_parent") == "$evidence_parent" &&
  ! -L $evidence_parent && -d $evidence_parent &&
  $(stat -c '%u:%a' "$evidence_parent") == 0:700 ]] ||
  fail "evidence parent must be one canonical root-owned mode-0700 directory"
evidence_stage="$evidence_parent/.$evidence_name.stage-$row_token"
[[ ! -e $evidence_stage && ! -L $evidence_stage ]] ||
  fail "evidence staging path is not fresh"

mta_user=Debian-exim
runtime_parent=${DKIM2_EXIM_REAL_MATRIX_RUNTIME_PARENT:-/run}
case "$runtime_parent" in
  /run | /q) ;;
  *) fail "runtime parent is outside the qualification allowlist" ;;
esac
[[ $(readlink -f -- "$runtime_parent") == "$runtime_parent" &&
  ! -L $runtime_parent && -d $runtime_parent &&
  $(stat -c '%u:%a' "$runtime_parent") == 0:755 ]] ||
  fail "runtime parent must be the canonical root-owned mode-0755 system runtime"
runtime_token=${run_id:0:32}
runtime_root="$runtime_parent/dkim2-exim-real-$runtime_token-$row_token"
[[ ! -e $runtime_root && ! -L $runtime_root ]] ||
  fail "qualification runtime path is not fresh"
config_root="$runtime_root/config"
adapter_root="$runtime_root/adapter-root"
socket_root="$runtime_root/socket"
adapter_cap_root="$runtime_root/adapter-process-cap"
adapter_sign_cap_root="$runtime_root/adapter-sign-cap"
adapter_revise_cap_root="$runtime_root/adapter-revise-cap"
evidence_key_root="$runtime_root/evidence-key"
daemon_parent="$runtime_root/daemon-protected"
generation=0123456789abcdef0123456789abcdef
daemon_generation="$daemon_parent/$generation"
state_root="$runtime_root/state"
spool_root="$runtime_root/spool"
evidence_state_root="$runtime_root/evidence"
readiness_root="$runtime_root/readiness"
runtime_helper="$runtime_root/real_matrix_service.py"
resolver_config="$daemon_generation/resolv.conf"
dns_config="$daemon_generation/dnsmasq.conf"
dns_records="$daemon_generation/dns-records.txt"
datasource_file="$daemon_generation/datasource.json"
private_manifest_file="$daemon_generation/private-manifest.json"
origin_private_key="$daemon_generation/origin.pem"
transit_private_key="$daemon_generation/transit.pem"
unit_prefix="dkim2-exim-qual-${run_id:0:8}-$row_token"
dns_unit="$unit_prefix-dns"
daemon_unit="$unit_prefix-daemon"
proxy_unit="$unit_prefix-proxy"
mismatch_adapter_unit="$unit_prefix-mismatch-adapter"
mismatch_exim_unit="$unit_prefix-mismatch-exim"
exact_adapter_unit="$unit_prefix-exact-adapter"
revise_adapter_unit="$unit_prefix-revise-adapter"
exact_exim_unit="$unit_prefix-exact-exim"
second_adapter_unit="$unit_prefix-second-adapter"
active_units=()
verified_stops=()
finalized=0
runtime_created=0
stage_created=0
stage_identity=
case_count=0

# finalize_runtime proves process and mount quiescence before owned cleanup.
finalize_runtime() (
  local failed=0 unsafe=0 index unit resolved mount_targets load_state active_state
  local main_pid control_pid control_group cgroup_procs cgroup_status
  local attempt stop_verified verified
  set +e
  set +u
  if (( runtime_created == 0 )); then
    ((${#active_units[@]} == 0)) || return 1
    return 0
  fi
  for ((index=${#active_units[@]} - 1; index >= 0; index--)); do
    unit=${active_units[index]}
    stop_verified=0
    for verified in "${verified_stops[@]}"; do
      [[ $verified == "$unit" ]] && stop_verified=1
    done
    load_state=$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)
    if [[ -z $load_state || $load_state == not-found ]]; then
      (( stop_verified == 1 )) || failed=1
      continue
    fi
    active_state=$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null)
    case "$active_state" in
      inactive | failed) ;;
      *) systemctl stop "$unit" >/dev/null || failed=1 ;;
    esac
    for ((attempt = 0; attempt < 150; attempt++)); do
      active_state=$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null)
      main_pid=$(systemctl show "$unit" --property=MainPID --value 2>/dev/null)
      control_pid=$(systemctl show "$unit" --property=ControlPID --value 2>/dev/null)
      if [[ $active_state == inactive || $active_state == failed ]] &&
        [[ $main_pid == 0 && $control_pid == 0 ]]; then
        break
      fi
      sleep 0.1
    done
    if [[ $active_state != inactive && $active_state != failed ||
      $main_pid != 0 || $control_pid != 0 ]]; then
      unsafe=1
      continue
    fi
    control_group=$(systemctl show "$unit" --property=ControlGroup --value 2>/dev/null)
    if [[ -n $control_group ]]; then
      cgroup_procs=/sys/fs/cgroup"$control_group"/cgroup.procs
      if [[ ! -f $cgroup_procs || ! -r $cgroup_procs ]]; then
        unsafe=1
        continue
      fi
      grep -Eq '^[0-9]+$' "$cgroup_procs"
      cgroup_status=$?
      if (( cgroup_status == 0 )); then
        unsafe=1
        continue
      fi
      if (( cgroup_status != 1 )); then
        unsafe=1
        continue
      fi
    fi
    [[ $(systemctl show "$unit" --property=Result --value 2>/dev/null) == success ]] ||
      failed=1
    [[ $(systemctl show "$unit" --property=ExecMainStatus --value 2>/dev/null) == 0 ]] ||
      failed=1
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  done
  [[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
    unsafe=1
  resolved=$(readlink -f -- "$runtime_root" 2>/dev/null)
  mount_targets=$(findmnt -rn -o TARGET 2>/dev/null) || unsafe=1
  [[ $resolved == "$runtime_root" &&
    $runtime_root == "$runtime_parent"/dkim2-exim-real-"$runtime_token"-"$row_token" &&
    -d $runtime_root && ! -L $runtime_root ]] ||
    unsafe=1
  if awk -v root="$runtime_root" \
      '$0 == root || index($0, root "/") == 1 { found = 1 } END { exit found ? 0 : 1 }' \
      <<<"$mount_targets"; then
    unsafe=1
  fi
  if (( unsafe == 0 )); then
    rm -rf --one-file-system -- "$runtime_root" || failed=1
    [[ ! -e $runtime_root && ! -L $runtime_root ]] || failed=1
  fi
  (( unsafe == 0 )) || failed=1
  return "$failed"
)

# cleanup finalizes owned runtime state and retracts evidence after failure.
cleanup() {
  local status=$?
  set +e
  set +u
  if (( finalized == 0 )) && ! finalize_runtime; then
    status=1
  fi
  if (( status != 0 && stage_created == 1 )) &&
    [[ -n $stage_identity && -d $evidence_root && ! -L $evidence_root &&
    $(stat -c '%d:%i:%u:%a' "$evidence_root" 2>/dev/null) == "$stage_identity" ]]; then
    rm -rf --one-file-system -- "$evidence_root"
  fi
  if (( status != 0 && stage_created == 1 )) &&
    [[ -d $evidence_stage && ! -L $evidence_stage ]]; then
    if [[ -z $stage_identity ||
      $(stat -c '%d:%i:%u:%a' "$evidence_stage" 2>/dev/null) == "$stage_identity" ]]; then
      rm -rf --one-file-system -- "$evidence_stage"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

mkdir "$evidence_stage"
stage_created=1
chmod 0700 "$evidence_stage"
stage_identity=$(stat -c '%d:%i:%u:%a' "$evidence_stage")

mta_uid=$(id -u "$mta_user")
mta_gid=$(id -g "$mta_user")
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mkdir "$runtime_root"
runtime_created=1
mkdir "$config_root" "$adapter_root" "$socket_root" "$adapter_cap_root" \
  "$adapter_sign_cap_root" "$adapter_revise_cap_root" "$evidence_key_root" \
  "$daemon_parent" "$state_root" "$spool_root" "$evidence_state_root" \
  "$readiness_root"
mkdir "$daemon_generation"
chown -R "$mta_uid:$mta_gid" "$runtime_root"
mkdir -p "$adapter_root/qualification" "$adapter_root/etc" "$adapter_root/tmp" \
  "$adapter_root/usr/exim/bin" "$adapter_root/usr/lib"
chown root:root "$adapter_root" "$adapter_root/qualification" \
  "$adapter_root/etc" "$adapter_root/tmp" "$adapter_root/usr" "$adapter_root/usr/exim" "$adapter_root/usr/exim/bin" \
  "$adapter_root/usr/lib"
chmod 0755 "$adapter_root" "$adapter_root/qualification" "$adapter_root/etc" "$adapter_root/usr" \
  "$adapter_root/usr/exim" "$adapter_root/usr/exim/bin" "$adapter_root/usr/lib"
chmod 1777 "$adapter_root/tmp"
touch "$adapter_root/etc/exim.conf" "$adapter_root/etc/passwd" "$adapter_root/etc/group" \
  "$adapter_root/etc/nsswitch.conf"
cp "$exim_binary" "$adapter_root/usr/exim/bin/exim"
chown root:root "$adapter_root/usr/exim/bin/exim"
chmod 4755 "$adapter_root/usr/exim/bin/exim"
mkdir -p "$adapter_root$(dirname -- "$adapter_binary")"
cp "$adapter_binary" "$adapter_root$adapter_binary"
chown root:root "$adapter_root$adapter_binary"
chmod 0755 "$adapter_root$adapter_binary"
find "$adapter_root/qualification" -type d -exec chmod 0755 {} +
cp "$matrix_helper" "$runtime_helper"
chown "$mta_uid:$mta_gid" "$runtime_helper"
chmod 0500 "$runtime_helper"
chmod 0700 "$runtime_root" "$config_root" "$socket_root" \
  "$adapter_cap_root" "$adapter_sign_cap_root" "$adapter_revise_cap_root" \
  "$evidence_key_root" "$daemon_parent" "$state_root" "$spool_root"
chmod 0700 "$evidence_state_root" "$readiness_root"
chmod 0500 "$daemon_generation"
dd if=/dev/urandom of="$adapter_cap_root/capability" bs=32 count=1 status=none
dd if=/dev/urandom of="$adapter_sign_cap_root/capability" bs=32 count=1 status=none
dd if=/dev/urandom of="$adapter_revise_cap_root/capability" bs=32 count=1 status=none
dd if=/dev/urandom of="$evidence_key_root/evidence.key" bs=32 count=1 status=none
cp "$adapter_cap_root/capability" "$daemon_generation/process.capability"
cp "$adapter_sign_cap_root/capability" "$daemon_generation/sign.capability"
cp "$adapter_revise_cap_root/capability" "$daemon_generation/revise.capability"
chown "$mta_uid:$mta_gid" "$adapter_cap_root/capability" \
  "$adapter_sign_cap_root/capability" "$adapter_revise_cap_root/capability" \
  "$evidence_key_root/evidence.key" "$daemon_generation/process.capability" \
  "$daemon_generation/sign.capability" "$daemon_generation/revise.capability"
chmod 0400 "$adapter_cap_root/capability" \
  "$adapter_sign_cap_root/capability" "$adapter_revise_cap_root/capability" \
  "$evidence_key_root/evidence.key" "$daemon_generation/process.capability" \
  "$daemon_generation/sign.capability" "$daemon_generation/revise.capability"
chmod 0500 "$adapter_cap_root" "$adapter_sign_cap_root" \
  "$adapter_revise_cap_root" "$evidence_key_root"

openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$origin_private_key"
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$transit_private_key"
origin_spki=$(
  openssl pkey -in "$origin_private_key" -pubout -outform DER |
    base64 -w0
)
transit_spki=$(
  openssl pkey -in "$transit_private_key" -pubout -outform DER |
    base64 -w0
)
origin_digest=$(
  openssl pkey -in "$origin_private_key" -pubout -outform DER |
    openssl dgst -sha256 -binary |
    base64 -w0
)
transit_digest=$(
  openssl pkey -in "$transit_private_key" -pubout -outform DER |
    openssl dgst -sha256 -binary |
    base64 -w0
)
origin_dns=$(
  openssl pkey -in "$origin_private_key" -pubout -outform DER |
    openssl rsa -pubin -RSAPublicKey_out -outform DER 2>/dev/null |
    base64 -w0
)
transit_dns=$(
  openssl pkey -in "$transit_private_key" -pubout -outform DER |
    openssl rsa -pubin -RSAPublicKey_out -outform DER 2>/dev/null |
    base64 -w0
)
printf '%s' \
  '{"version":"dkim2-datasource-v1","handles":[{"id":"origin-key"},{"id":"transit-key"}],"profiles":[{"id":"origin-profile","domain":"origin.example.test","status":"active","credentials":[{"algorithm":"rsa-sha256","selector":"origin","public_key_spki":"'"$origin_spki"'","handle_id":"origin-key"}]},{"id":"transit-profile","domain":"origin.example.test","status":"active","credentials":[{"algorithm":"rsa-sha256","selector":"transit","public_key_spki":"'"$transit_spki"'","handle_id":"transit-key"}]}],"policies":[{"tenant_id":"tenant-a","domain":"origin.example.test","use":"originator","profile_id":"origin-profile","status":"active","rollout":"enforce","compatibility":"strict"},{"tenant_id":"tenant-a","domain":"origin.example.test","use":"ordinary_transit","profile_id":"transit-profile","status":"active","rollout":"enforce","compatibility":"strict"}]}' \
  >"$datasource_file"
printf '%s' \
  '{"version":"dkim2-private-keys-v1","entries":[{"tenant_id":"tenant-a","domain":"origin.example.test","use":"originator","handle_id":"origin-key","algorithm":"rsa-sha256","public_spki_sha256":"'"$origin_digest"'","private_key_file":"origin.pem"},{"tenant_id":"tenant-a","domain":"origin.example.test","use":"ordinary_transit","handle_id":"transit-key","algorithm":"rsa-sha256","public_spki_sha256":"'"$transit_digest"'","private_key_file":"transit.pem"}]}' \
  >"$private_manifest_file"
printf '%s\n' \
  "origin._domainkey.origin.example.test.=p=$origin_dns" \
  "transit._domainkey.origin.example.test.=p=$transit_dns" \
  >"$dns_records"
printf '%s\n' \
  'port=53' \
  "listen-address=$dns_address" \
  'bind-interfaces' \
  'no-resolv' \
  'no-hosts' \
  'local-ttl=30' \
  "txt-record=origin._domainkey.origin.example.test,\"p=$origin_dns\"" \
  "txt-record=transit._domainkey.origin.example.test,\"p=$transit_dns\"" \
  >"$dns_config"
printf '%s\n' \
  "nameserver $dns_address" \
  'options timeout:1 attempts:1' >"$resolver_config"
chown "$mta_uid:$mta_gid" "$origin_private_key" "$transit_private_key" \
  "$datasource_file" "$private_manifest_file" "$dns_records" \
  "$resolver_config"
chown root:root "$dns_config"
chmod 0400 "$origin_private_key" "$transit_private_key" "$datasource_file" \
  "$private_manifest_file" "$dns_records" "$dns_config" "$resolver_config"

{
  printf '%s\n' \
    'config:' \
    '  version: dkim2d-config-v1' \
    'protected:' \
    "  generation: $generation" \
    'server:' \
    '  listen: 127.0.0.1:18080' \
    "  capability_file: $daemon_generation/process.capability" \
    "  sign_capability_file: $daemon_generation/sign.capability" \
    "  revise_capability_file: $daemon_generation/revise.capability" \
    '  max_in_flight: 2' \
    'policy:' \
    '  mode: permissive' \
    'dns:' \
    '  lookup_timeout: 2s' \
    '  max_concurrent_lookups: 2' \
    'replay:' \
    '  backend: disabled' \
    'signing:' \
    '  backend: flat_file' \
    "  datasource_file: $datasource_file" \
    "  private_manifest_file: $private_manifest_file" \
    '  reload_interval: 30s' \
    '  allow_recipient_group: false'
} >"$config_root/dkim2d.yaml"
chown "$mta_uid:$mta_gid" "$config_root/dkim2d.yaml"
chmod 0400 "$config_root/dkim2d.yaml"

{
  printf '%s\n' \
    'version: dkim2-exim-config-v1' \
    'daemon:' \
    '  endpoint: http://127.0.0.1:18079' \
    "  sign_capability_file: $adapter_sign_cap_root/capability" \
    '  request_timeout: 3s' \
    'signing:' \
    '  tenant: tenant-a' \
    '  domain: origin.example.test' \
    'limits:' \
    '  message_bytes: 33554432' \
    '  header_bytes: 1048576' \
    '  header_count: 2000' \
    '  header_field_bytes: 65536' \
    '  recipient_count: 1' \
    'observability:' \
    '  logging:' \
    '    level: info' \
    '    destination: none'
} >"$config_root/sign.yaml"
sed 's|endpoint: http://127.0.0.1:18079|endpoint: http://127.0.0.1:18078|' \
  "$config_root/sign.yaml" >"$config_root/sign-fault.yaml"
{
  printf '%s\n' \
    'version: dkim2-exim-config-v1' \
    'daemon:' \
    '  endpoint: http://127.0.0.1:18079' \
    "  revise_capability_file: $adapter_revise_cap_root/capability" \
    '  request_timeout: 3s' \
    'signing:' \
    '  tenant: tenant-a' \
    '  domain: origin.example.test' \
    'evidence:' \
    '  enabled: true' \
    "  root: $evidence_state_root" \
    "  key_file: $evidence_key_root/evidence.key" \
    "  readiness_file: $readiness_root/state" \
    '  retention: 1h0m0s' \
    '  max_records: 128' \
    '  max_bytes: 16777216' \
    'limits:' \
    '  message_bytes: 33554432' \
    '  header_bytes: 1048576' \
    '  header_count: 2000' \
    '  header_field_bytes: 65536' \
    '  recipient_count: 1' \
    'observability:' \
    '  logging:' \
    '    level: info' \
    '    destination: none'
} >"$config_root/revise.yaml"
chown "$mta_uid:$mta_gid" "$config_root/sign.yaml" "$config_root/sign-fault.yaml" \
  "$config_root/revise.yaml"
chmod 0400 "$config_root/sign.yaml" "$config_root/sign-fault.yaml" \
  "$config_root/revise.yaml"

{
  printf '%s\n' \
    'primary_hostname = matrix.example.test' \
    'exim_user = Debian-exim' \
    'exim_group = Debian-exim' \
    'local_scan_timeout = 12s' \
    'spool_wireformat = false' \
    "spool_directory = $spool_root" \
    "log_file_path = $state_root/exim-%s.log" \
    'daemon_smtp_ports = 2525' \
    'local_interfaces = 127.0.0.1' \
    'smtp_accept_max = 4' \
    'smtp_accept_max_per_host = 4' \
    'acl_smtp_rcpt = acl_check_rcpt' \
    'domainlist local_domains = local.test' \
    'begin acl' \
    'acl_check_rcpt:' \
    '  accept' \
    'begin routers' \
    'matrix_envelope_redirect:' \
    '  driver = redirect' \
    '  domains = revise.test' \
    '  local_parts = incoming' \
    '  data = outgoing@revise.test' \
    'matrix_fidelity_capture:' \
    '  driver = manualroute' \
    '  domains = fidelity.test' \
    '  route_list = * 127.0.0.1::2526' \
    '  self = send' \
    '  transport = matrix_capture' \
    '  no_more' \
    'matrix_revise_signed:' \
    '  driver = redirect' \
    '  domains = origin.example.test' \
    '  local_parts = recipient' \
    '  condition = ${if def:h_DKIM2-Signature: {yes}{no}}' \
    '  data = outgoing@revise.test' \
    'matrix_divergent_return_path:' \
    '  driver = manualroute' \
    '  domains = origin.example.test' \
    '  local_parts = divergent' \
    '  errors_to = outgoing@origin.example.test' \
    '  route_list = * 127.0.0.1::2526' \
    '  self = send' \
    '  transport = dkim2_sign' \
    '  no_more' \
    'matrix_sign:' \
    '  driver = manualroute' \
    '  domains = origin.example.test' \
    '  route_list = * 127.0.0.1::2526' \
    '  self = send' \
    '  transport = dkim2_sign' \
    '  no_more' \
    'matrix_revise:' \
    '  driver = manualroute' \
    '  domains = revise.test' \
    '  route_list = * 127.0.0.1::2526' \
    '  self = send' \
    '  transport = dkim2_revise' \
    '  no_more' \
    'matrix_local:' \
    '  driver = accept' \
    '  domains = +local_domains' \
    '  transport = matrix_appendfile' \
    '  no_more' \
    'begin transports' \
    'matrix_appendfile:' \
    '  driver = appendfile' \
    "  file = $state_root/delivered.mbox" \
    '  mode = 0600' \
    'matrix_capture:' \
    '  driver = smtp' \
    "  user = $mta_user" \
    "  group = $mta_user" \
    'dkim2_sign:' \
    '  driver = smtp' \
    "  transport_filter = $adapter_binary --config $config_root/sign.yaml filter sign -- '\$dkim2_transport_filter_return_path' '\$pipe_addresses'" \
    '  max_rcpt = 1' \
    '  size_addition = -1' \
    '  transport_filter_timeout = 11s' \
    "  user = $mta_user" \
    "  group = $mta_user" \
    'dkim2_revise:' \
    '  driver = smtp' \
    "  transport_filter = $adapter_binary --config $config_root/revise.yaml filter revise -- '\$local_scan_data' '\$dkim2_transport_filter_return_path' '\$pipe_addresses'" \
    '  max_rcpt = 1' \
    '  size_addition = -1' \
    '  transport_filter_timeout = 11s' \
    "  user = $mta_user" \
    "  group = $mta_user" \
    'begin retry' \
    'begin rewrite' \
    'begin authenticators' \
    'begin local_scan' \
    "dkim2_socket = $socket_root/local-scan.sock" \
    'dkim2_spool_format = unix_lf' \
    'dkim2_timeout = 11s' \
    'dkim2_failure_mode = tempfail' \
    'dkim2_max_message_bytes = 33554432'
} >"$config_root/exim.conf"
sed 's/size_addition = -1/size_addition = 0/g' \
  "$config_root/exim.conf" >"$config_root/exim-zero-size.conf"
sed 's/size_addition = -1/size_addition = 1/g' \
  "$config_root/exim.conf" >"$config_root/exim-positive-size.conf"
sed 's/local_scan_timeout = 12s/local_scan_timeout = 1s/' \
  "$config_root/exim.conf" >"$config_root/exim-local-scan-timeout.conf"
sed 's/dkim2_timeout = 11s/dkim2_timeout = 1s/' \
  "$config_root/exim.conf" >"$config_root/exim-ipc-timeout.conf"
sed '/^primary_hostname = /a queue_only = true' \
  "$config_root/exim.conf" >"$config_root/exim-queue-only.conf"
sed "s|$config_root/sign.yaml|$config_root/sign-fault.yaml|g" \
  "$config_root/exim-queue-only.conf" >"$config_root/exim-queue-fault.conf"
sed "s|transport_filter = $adapter_binary --config $config_root/sign.yaml filter sign --|transport_filter = /usr/bin/python3 $runtime_helper filter-fault --mode nonzero --result-output $state_root/nonzero-deferral.filter-fault -- $adapter_binary --config $config_root/sign.yaml filter sign --|" \
  "$config_root/exim-queue-only.conf" >"$config_root/exim-filter-nonzero.conf"
sed "s|transport_filter = $adapter_binary --config $config_root/sign.yaml filter sign --|transport_filter = /usr/bin/python3 $runtime_helper filter-fault --mode partial --result-output $state_root/partial-output.filter-fault -- $adapter_binary --config $config_root/sign.yaml filter sign --|" \
  "$config_root/exim-queue-only.conf" >"$config_root/exim-filter-partial.conf"
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'exec "$EXIM_REAL" -C "$EXIM_CONFIG" "$@"' \
  >"$config_root/exim-wrapper"
chown root:"$mta_gid" "$config_root/exim.conf"
chown root:"$mta_gid" "$config_root/exim-zero-size.conf" \
  "$config_root/exim-positive-size.conf" \
  "$config_root/exim-local-scan-timeout.conf" \
  "$config_root/exim-ipc-timeout.conf" \
  "$config_root/exim-queue-only.conf" "$config_root/exim-queue-fault.conf" \
  "$config_root/exim-filter-nonzero.conf" "$config_root/exim-filter-partial.conf" \
  "$config_root/exim-wrapper"
chmod 0440 "$config_root/exim.conf" "$config_root/exim-zero-size.conf" \
  "$config_root/exim-positive-size.conf" \
  "$config_root/exim-local-scan-timeout.conf" \
  "$config_root/exim-ipc-timeout.conf" \
  "$config_root/exim-queue-only.conf" "$config_root/exim-queue-fault.conf" \
  "$config_root/exim-filter-nonzero.conf" "$config_root/exim-filter-partial.conf"
chmod 0500 "$config_root/exim-wrapper"
chmod 0500 "$config_root"

if ! version_output=$("$exim_binary" -C "$config_root/exim.conf" -bV 2>&1); then
  printf '%s\n' "$version_output" >&2
  fail "running Exim version readback failed"
fi
grep -Fq "Exim version ${expected_version%%-*} " <<<"$version_output" ||
  fail "running Exim version differs from the authenticated row"
grep -aFq "$expected_build_id" "$exim_binary" ||
  fail "running Exim binary omits the exact source-generated build identifier"

validator_environment=(
  "EXIM=$config_root/exim-wrapper"
  "EXIM_REAL=$exim_binary"
  "DKIM2_BINARY=$adapter_binary"
  "SIGN_CONFIG=$config_root/sign.yaml"
  "REVISE_CONFIG=$config_root/revise.yaml"
  "SERVICE_USER=$mta_user"
  "SERVICE_GROUP=$mta_user"
  "SOCKET_DIR=$socket_root"
  "STATE_DIR=$state_root"
  "EVIDENCE_DIR=$evidence_state_root"
  "READINESS_DIR=$readiness_root"
)
readback_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EXIM_CONFIG="$config_root/exim.conf" \
  env "${validator_environment[@]}" bash "$deployment_validator" \
  >"$state_root/deployment-validator.log" || {
    sed -n '1,80p' "$state_root/deployment-validator.log" >&2
    fail "real deployment readback validation failed"
  }
grep -Fxq 'dkim2-exim deployment validation passed' \
  "$state_root/deployment-validator.log" ||
  fail "deployment validator did not publish its closed success"
readback_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
readback_invocation=$(
  sha256_text "$row:$binary_sha256:$deployment_validator_sha256:readback"
)
zero_size_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if EXIM_CONFIG="$config_root/exim-zero-size.conf" \
  env "${validator_environment[@]}" bash "$deployment_validator" \
    >"$state_root/zero-size-validator.log" 2>&1; then
  fail "deployment validator accepted zero size_addition"
fi
zero_size_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
zero_size_invocation=$(
  sha256_text "$row:$binary_sha256:$deployment_validator_sha256:zero-size"
)
positive_size_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if EXIM_CONFIG="$config_root/exim-positive-size.conf" \
  env "${validator_environment[@]}" bash "$deployment_validator" \
    >"$state_root/positive-size-validator.log" 2>&1; then
  fail "deployment validator accepted positive size_addition"
fi
positive_size_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
positive_size_invocation=$(
  sha256_text "$row:$binary_sha256:$deployment_validator_sha256:positive-size"
)
for readback_case in empty-smtp-return-path sender-address-rejected \
  max-rcpt-one pipe-addresses negative-size-addition; do
  case "$readback_case" in
    empty-smtp-return-path)
      readback_observation='smtp-return-path-unset,validator-pass'
      ;;
    sender-address-rejected)
      readback_observation='sender-address-substitution-rejected,validator-pass'
      ;;
    max-rcpt-one)
      readback_observation='max-rcpt-1,validator-pass'
      ;;
    pipe-addresses)
      readback_observation='pipe-addresses-separate-argv,validator-pass'
      ;;
    negative-size-addition)
      readback_observation='size-addition-negative,validator-pass'
      ;;
  esac
  write_live_case transport-filter "$readback_case" "$readback_invocation" \
    "$readback_started" "$readback_finished" \
    'deployment-readback-complete,runtime-not-run' \
    'deployment-validator-pass,runtime-not-run' \
    'authority-not-applicable' \
    'fault-mode-none,outcome-not-applicable' \
    "$readback_observation"
done
write_live_case transport-filter zero-size-rejected "$zero_size_invocation" \
  "$zero_size_started" "$zero_size_finished" \
  'deployment-readback-complete,runtime-not-run' \
  'deployment-validator-pass,runtime-not-run' \
  'authority-not-applicable' \
  'fault-mode-none,outcome-not-applicable' \
  'size-addition-zero,rejected'
write_live_case transport-filter positive-size-rejected \
  "$positive_size_invocation" "$positive_size_started" \
  "$positive_size_finished" \
  'deployment-readback-complete,runtime-not-run' \
  'deployment-validator-pass,runtime-not-run' \
  'authority-not-applicable' \
  'fault-mode-none,outcome-not-applicable' \
  'size-addition-positive,rejected'

start_unit "$dns_unit" root dnsmasq --no-daemon --conf-file="$dns_config" || {
  journalctl --quiet --unit "$dns_unit" --output=cat >&2
  fail "qualification DNS service did not become active"
}
start_daemon "$daemon_unit" || {
  journalctl --quiet --unit "$daemon_unit" --output=cat >&2
  fail "real dkim2d transient unit did not become active"
}
for _ in {1..100}; do
  curl -fsS http://127.0.0.1:18080/readyz >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS http://127.0.0.1:18080/readyz >/dev/null || {
  journalctl --quiet --unit "$daemon_unit" --output=cat >&2
  fail "real dkim2d readiness did not become live"
}
start_unit "$proxy_unit" "$mta_user" python3 "$runtime_helper" proxy \
  --address 127.0.0.1 --port 18079 --target-address 127.0.0.1 \
  --target-port 18080 --output "$state_root/daemon-proxy.log" ||
  fail "daemon digest proxy did not become active"
for _ in {1..100}; do
  nc -z 127.0.0.1 18079 >/dev/null 2>&1 && break
  sleep 0.1
done
nc -z 127.0.0.1 18079 >/dev/null 2>&1 ||
  fail "daemon digest proxy did not become live"

write_adapter_config \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa tempfail
start_adapter "$mismatch_adapter_unit"
start_exim "$mismatch_exim_unit"
mismatch_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mismatch_process_before=$(daemon_metric process)
mismatch_event_before=$(
  journalctl --quiet --unit "$mismatch_adapter_unit" --output=cat |
    grep -Ec '"failure":"contract".*"admission":"accepted"' || true
)
smtp_submit "$state_root/mismatch.smtp" matrix@example.test local@local.test mismatch
[[ $(smtp_final_reply "$state_root/mismatch.smtp") =~ ^451[[:space:]-] ]] ||
  fail "mismatched build did not close the SMTP transaction"
[[ ! -e $state_root/delivered.mbox ]] ||
  fail "mismatched build reached delivery"
mismatch_process_after=$(daemon_metric process)
[[ $mismatch_process_after -eq $mismatch_process_before ]] ||
  fail "mismatched build reached dkim2d"
journalctl --quiet --unit "$mismatch_adapter_unit" --output=cat >"$state_root/mismatch-adapter.log"
mismatch_event_after=$(
  grep -Ec '"failure":"contract".*"admission":"accepted"' \
    "$state_root/mismatch-adapter.log" || true
)
[[ $mismatch_event_after -eq $((mismatch_event_before + 1)) ]] ||
  fail "mismatched build did not derive the adapter contract admission event"
mismatch_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mismatch_invocation=$(
  sha256_text "$row:$binary_sha256:mismatch:$mismatch_started:$mismatch_finished"
)
stop_unit "$mismatch_exim_unit"
stop_unit "$mismatch_adapter_unit"
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "mismatch adapter did not remove its exact socket"
write_live_case smtp build-mismatch "$mismatch_invocation" \
  "$mismatch_started" "$mismatch_finished" \
  'smtp-final-451,deliveries-0' \
  'operation-process,contract-rejected,daemon-calls-0' \
  'authority-calls-0' \
  'fault-build-id-mismatch,outcome-smtp-451' \
  'version-match,build-id-mismatch,validator-pass'

write_adapter_config "$expected_build_id" tempfail
start_adapter "$exact_adapter_unit"
start_exim "$exact_exim_unit"
exact_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
exact_process_before=$(daemon_metric process)
exact_event_before=$(adapter_event_count "$exact_adapter_unit" success)
exact_ar_before=$(authentication_results_count)
smtp_submit "$state_root/exact.smtp" matrix@example.test local@local.test exact
[[ $(smtp_final_reply "$state_root/exact.smtp") =~ ^250[[:space:]-] ]] ||
  fail "exact build did not accept the SMTP transaction"
run_exim "$exact_exim_unit" -qff
wait_for_path "$state_root/delivered.mbox" file ||
  fail "exact build did not reach real Exim delivery"
[[ $(delivery_marker_count exact) -eq 1 ]] ||
  fail "exact build marker did not reach exactly one delivery"
exact_process_after=$(daemon_metric process)
exact_event_after=$(adapter_event_count "$exact_adapter_unit" success)
exact_ar_after=$(authentication_results_count)
[[ $exact_process_after -eq $((exact_process_before + 1)) ]] ||
  fail "exact process case did not make exactly one daemon request"
[[ $exact_event_after -eq $((exact_event_before + 1)) ]] ||
  fail "exact process case did not emit exactly one adapter success event"
[[ $exact_ar_after -eq $((exact_ar_before + 1)) ]] ||
  fail "exact process action did not add one authoritative header"
exact_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
exact_invocation=$(
  sha256_text "$row:$binary_sha256:exact:$exact_started:$exact_finished"
)
write_live_case smtp exact-build "$exact_invocation" \
  "$exact_started" "$exact_finished" \
  'smtp-final-250,deliveries-1,authentication-results-1' \
  'operation-process,result-pass,actions-1' \
  'route-process,http-2xx-1,result-pass' \
  'fault-mode-none,outcome-not-applicable' \
  'version-match,build-id-match,validator-pass'

interactive_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
interactive_process_before=$(daemon_metric process)
interactive_event_before=$(adapter_event_count "$exact_adapter_unit" success)
interactive_ar_before=$(authentication_results_count)
smtp_submit "$state_root/interactive.smtp" matrix@example.test \
  local@local.test interactive
[[ $(smtp_final_reply "$state_root/interactive.smtp") =~ ^250[[:space:]-] ]] ||
  fail "interactive SMTP case did not accept the transaction"
run_exim "$exact_exim_unit" -qff
[[ $(delivery_marker_count interactive) -eq 1 ]] ||
  fail "interactive SMTP marker did not reach exactly one delivery"
interactive_process_after=$(daemon_metric process)
interactive_event_after=$(adapter_event_count "$exact_adapter_unit" success)
interactive_ar_after=$(authentication_results_count)
[[ $interactive_process_after -eq $((interactive_process_before + 1)) ]] ||
  fail "interactive SMTP case did not make exactly one daemon request"
[[ $interactive_event_after -eq $((interactive_event_before + 1)) ]] ||
  fail "interactive SMTP case did not emit exactly one adapter success event"
[[ $interactive_ar_after -eq $((interactive_ar_before + 1)) ]] ||
  fail "interactive SMTP case did not add exactly one authoritative header"
interactive_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
interactive_invocation=$(
  sha256_text \
    "$row:$binary_sha256:interactive:$interactive_started:$interactive_finished"
)
write_live_case smtp interactive-smtp "$interactive_invocation" \
  "$interactive_started" "$interactive_finished" \
  'smtp-final-250,deliveries-1' \
  'operation-process,result-pass,actions-admitted' \
  'route-process,http-2xx-1,result-pass' \
  'fault-mode-none,outcome-not-applicable' \
  'version-match,build-id-match,validator-pass'

stop_unit "$exact_exim_unit"
stop_unit "$exact_adapter_unit"
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "adapter socket persisted before local-scan fault cases"
run_local_scan_fault_case smtp-timeout \
  "$config_root/exim-local-scan-timeout.conf" timeout
run_local_scan_fault_case smtp-crash "$config_root/exim.conf" crash
run_local_scan_fault_case local-timeout \
  "$config_root/exim-ipc-timeout.conf" timeout
run_local_scan_fault_case local-crash "$config_root/exim.conf" close
run_local_scan_fault_case c-to-go-unavailable "$config_root/exim.conf"
run_non_smtp_fault_case non-smtp-drop \
  "$config_root/exim-local-scan-timeout.conf" timeout \
  'local_scan() function timed out'
run_non_smtp_fault_case nonzero-exit "$config_root/exim.conf" crash \
  'local_scan() function crashed with signal'

start_exim "$exact_exim_unit"
write_adapter_config "$expected_build_id" tempfail false
start_adapter "$exact_adapter_unit"
printf '%s\n' \
  'From: matrix@example.test' \
  'To: capture@fidelity.test' \
  'Subject: fidelity-lf' \
  '' \
  'body-fidelity-lf' >"$state_root/lf.eml"
run_fidelity_case lf "$state_root/lf.eml" lf
printf 'From: matrix@example.test\r\nTo: capture@fidelity.test\r\nSubject: fidelity-crlf\r\n\r\nbody-fidelity-crlf\r\n' \
  >"$state_root/crlf.eml"
run_fidelity_case crlf "$state_root/crlf.eml" crlf
printf 'From: matrix@example.test\r\nTo: capture@fidelity.test\r\nSubject: fidelity-duplicate\r\nX-Duplicate: first\r\nX-Duplicate: second\r\n\tfolded\r\n\r\nbody-fidelity-duplicate\r\n' \
  >"$state_root/duplicate-folded.eml"
run_fidelity_case duplicate-folded "$state_root/duplicate-folded.eml" crlf
printf 'From: matrix@example.test\r\nTo: capture@fidelity.test\r\nSubject: fidelity-binary\r\n\r\nbody-fidelity-binary\000tail\r\n' \
  >"$state_root/binary-body.eml"
run_fidelity_case binary-body "$state_root/binary-body.eml" crlf
printf 'From: matrix@example.test\r\nTo: capture@fidelity.test\r\nSubject: fidelity-utf8-\303\244\r\n\r\nbody-fidelity-utf8-\303\244\r\n' \
  >"$state_root/smtputf8-rfc6532.eml"
run_fidelity_case smtputf8-rfc6532 "$state_root/smtputf8-rfc6532.eml" crlf true
stop_unit "$exact_adapter_unit"
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "adapter socket persisted after unsigned fidelity cases"
write_adapter_config "$expected_build_id" tempfail
start_adapter "$exact_adapter_unit"
printf 'Authentication-Results: mx.example.test; forged=fail\r\nFrom: matrix@example.test\r\nTo: capture@fidelity.test\r\nSubject: forged-authentication-results\r\n\r\nbody-forged-authentication-results\r\n' \
  >"$state_root/forged-authentication-results.eml"
run_forged_authentication_results_case "$state_root/forged-authentication-results.eml"

stop_unit "$exact_adapter_unit"
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "adapter socket persisted before daemon availability cases"
run_daemon_unavailable_inbound_case daemon-unavailable-closed tempfail 451
run_daemon_unavailable_inbound_case \
  daemon-unavailable-reached-fail-open fail_open 250
write_adapter_config "$expected_build_id" tempfail
start_adapter "$exact_adapter_unit"

local_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
local_process_before=$(daemon_metric process)
local_event_before=$(adapter_event_count "$exact_adapter_unit" success)
local_ar_before=$(authentication_results_count)
set +e
printf '%s\n' \
  'From: matrix@example.test' \
  'To: local@local.test' \
  'Subject: local-submission' \
  '' \
  'body-local-submission' |
  run_exim "$exact_exim_unit" -odf \
    -f matrix@example.test local@local.test \
    >"$state_root/local-submission.output" 2>&1
local_submission_status=$?
set -e
[[ $local_submission_status -eq 0 ]] ||
  fail "real local submission did not exit successfully"
run_exim "$exact_exim_unit" -qff
for _ in {1..100}; do
  [[ $(delivery_marker_count local-submission) -eq 1 ]] && break
  sleep 0.1
done
[[ $(delivery_marker_count local-submission) -eq 1 ]] ||
  fail "real local submission did not reach exactly one delivery"
local_process_after=$(daemon_metric process)
local_event_after=$(adapter_event_count "$exact_adapter_unit" success)
local_ar_after=$(authentication_results_count)
[[ $local_process_after -eq $((local_process_before + 1)) ]] ||
  fail "local submission did not make exactly one daemon request"
[[ $local_event_after -eq $((local_event_before + 1)) ]] ||
  fail "local submission did not emit exactly one adapter success event"
[[ $local_ar_after -eq $((local_ar_before + 1)) ]] ||
  fail "local submission did not add exactly one authoritative header"
local_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
local_invocation=$(
  sha256_text "$row:$binary_sha256:local:$local_started:$local_finished"
)
write_live_case smtp local-submission "$local_invocation" \
  "$local_started" "$local_finished" \
  'submission-exit-0,deliveries-1' \
  'operation-process,result-pass,actions-admitted' \
  'route-process,http-2xx-1,result-pass' \
  'fault-mode-none,outcome-not-applicable' \
  'version-match,build-id-match,validator-pass'

sign_capture_unit="$unit_prefix-sign-capture"
sign_capture="$state_root/sign.capture"
start_smtp_capture "$sign_capture_unit" "$sign_capture"
sign_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sign_metric_before=$(daemon_metric sign)
sign_proxy_before=$(proxy_route_count sign)
smtp_submit "$state_root/sign.smtp" sender@origin.example.test \
  recipient@origin.example.test sign
[[ $(smtp_final_reply "$state_root/sign.smtp") =~ ^250[[:space:]-] ]] ||
  fail "real sign transport submission was not accepted"
run_exim "$exact_exim_unit" -qff
wait_for_path "$sign_capture" file || {
  fail "real sign transport did not reach the downstream SMTP peer"
}
finish_unit "$sign_capture_unit"
sign_metric_after=$(daemon_metric sign)
sign_proxy_after=$(proxy_route_count sign)
[[ $sign_metric_after -eq $((sign_metric_before + 1)) &&
  $sign_proxy_after -eq $((sign_proxy_before + 1)) ]] ||
  fail "real sign transport did not traverse one digest-bound daemon route"
[[ $(grep -ac '^Message-Instance:' "$sign_capture") -eq 1 &&
  $(grep -ac '^DKIM2-Signature:' "$sign_capture") -eq 1 ]] ||
  fail "real sign transport did not add exactly two owned fields"
sign_header_sequence=$(
  grep -aE '^(Message-Instance|DKIM2-Signature):' "$sign_capture" |
    sed 's/:.*//' |
    tr '\n' ','
)
[[ $sign_header_sequence == 'Message-Instance,DKIM2-Signature,' ]] ||
  fail "real sign transport changed the owned action order"
sign_request_hash=$(proxy_route_digest sign request_sha256)
sign_response_hash=$(proxy_route_digest sign response_sha256)
[[ $sign_request_hash != "$sign_response_hash" ]] ||
  fail "real sign request and response digests unexpectedly alias"
python3 "$runtime_helper" unpack --require-owned-fields --capture "$sign_capture" \
  --message-output "$state_root/signed.eml" \
  --metadata-output "$state_root/sign-capture.metadata"
[[ $(metadata_value "$state_root/sign-capture.metadata" format) == \
  dkim2-exim-capture-inspection-v1 ]] ||
  fail "real sign capture metadata format changed"
sign_output_hash=$(
  metadata_value "$state_root/sign-capture.metadata" message_lf_sha256
)
sign_header_hash=$(
  metadata_value "$state_root/sign-capture.metadata" header_order_sha256
)
sign_plan_hash=$(proxy_route_digest sign action_plan_sha256)
sign_authorized_fields_hash=$(
  proxy_route_digest sign authorized_fields_sha256
)
sign_output_fields_hash=$(
  metadata_value "$state_root/sign-capture.metadata" \
    new_owned_fields_sha256
)
[[ $(proxy_route_value sign actions) == 2 &&
  $(proxy_route_value sign status) == 200 ]] ||
  fail "real sign proxy did not independently prove the exact action plan"
[[ $(metadata_value "$state_root/sign-capture.metadata" owned_field_sequence) == \
  message-instance,dkim2-signature ]] ||
  fail "real sign output did not contain the exact owned field sequence"
sign_header_count=$(
  metadata_value "$state_root/sign-capture.metadata" header_field_count
)
sign_owned_indexes=$(
  metadata_value "$state_root/sign-capture.metadata" owned_field_indexes
)
[[ $sign_header_count =~ ^[1-9][0-9]*$ ]] &&
(( sign_header_count >= 2 )) &&
[[ \
  $sign_owned_indexes == \
  "$((sign_header_count - 2)),$((sign_header_count - 1))" &&
  $sign_authorized_fields_hash == "$sign_output_fields_hash" ]] ||
  fail "real sign fields were not adjacent, final, and authority-exact"
sign_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sign_invocation=$(
  sha256_text \
    "$row:$sign_request_hash:$sign_response_hash:$sign_output_hash:$sign_started"
)
write_live_case transport-filter sign "$sign_invocation" \
  "$sign_started" "$sign_finished" \
  "transport-exit-0,deliveries-1,invocation-sha256-$sign_invocation,authorized-fields-sha256-$sign_output_fields_hash,output-sha256-$sign_output_hash,header-order-sha256-$sign_header_hash" \
  "operation-sign,result-pass,invocation-sha256-$sign_invocation,request-sha256-$sign_request_hash,response-sha256-$sign_response_hash,action-plan-sha256-$sign_plan_hash,authorized-fields-sha256-$sign_authorized_fields_hash,actions-2,action-order-message-instance-dkim2-signature,output-sha256-$sign_output_hash,header-order-sha256-$sign_header_hash" \
  "route-sign,http-2xx-1,result-pass,invocation-sha256-$sign_invocation,request-sha256-$sign_request_hash,response-sha256-$sign_response_hash,action-plan-sha256-$sign_plan_hash,authorized-fields-sha256-$sign_authorized_fields_hash,actions-2" \
  'fault-mode-none,outcome-not-applicable' \
  'version-match,build-id-match,validator-pass'
run_transport_envelope_case return-path sender@origin.example.test \
  return-path@origin.example.test sender@origin.example.test
run_transport_envelope_case empty-bounce '' \
  empty-bounce@origin.example.test ''
run_transport_envelope_case divergent-sender incoming@origin.example.test \
  divergent@origin.example.test outgoing@origin.example.test

stop_unit "$exact_adapter_unit"
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "sign adapter did not remove its exact socket before revision"
write_adapter_config "$expected_build_id" tempfail false
start_adapter "$revise_adapter_unit"

chown "$mta_uid:$mta_gid" "$state_root/signed.eml"
chmod 0600 "$state_root/signed.eml"
revise_capture_unit="$unit_prefix-revise-capture"
revise_capture="$state_root/revise.capture"
start_smtp_capture "$revise_capture_unit" "$revise_capture"
revise_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
revise_metric_before=$(daemon_metric revise)
revise_proxy_before=$(proxy_route_count revise)
revise_process_before=$(daemon_metric process)
smtp_submit_file "$state_root/revise.smtp" sender@origin.example.test \
  recipient@origin.example.test "$state_root/signed.eml"
[[ $(smtp_final_reply "$state_root/revise.smtp") =~ ^250[[:space:]-] ]] ||
  fail "real revise transport submission was not accepted"
run_exim "$exact_exim_unit" -qff
wait_for_path "$revise_capture" file ||
  fail "real revise transport did not reach the downstream SMTP peer"
finish_unit "$revise_capture_unit"
revise_metric_after=$(daemon_metric revise)
revise_proxy_after=$(proxy_route_count revise)
revise_process_after=$(daemon_metric process)
[[ $revise_metric_after -eq $((revise_metric_before + 1)) &&
  $revise_proxy_after -eq $((revise_proxy_before + 1)) &&
  $revise_process_after -eq $((revise_process_before + 1)) ]] ||
  fail "real revise transport did not traverse process and revise authority"

[[ $(grep -ac '^Message-Instance:' "$revise_capture") -eq 1 &&
  $(grep -ac '^DKIM2-Signature:' "$revise_capture") -eq 2 ]] ||
  fail "real revise transport did not preserve and append owned fields"
revise_request_hash=$(proxy_route_digest revise request_sha256)
revise_response_hash=$(proxy_route_digest revise response_sha256)
[[ $revise_request_hash != "$revise_response_hash" ]] ||
  fail "real revise request and response digests unexpectedly alias"
python3 "$runtime_helper" unpack --require-owned-fields --capture "$revise_capture" \
  --message-output "$state_root/revised.eml" \
  --metadata-output "$state_root/revise-capture.metadata"
[[ $(metadata_value "$state_root/revise-capture.metadata" format) == \
  dkim2-exim-capture-inspection-v1 ]] ||
  fail "real revise capture metadata format changed"
revise_output_hash=$(
  metadata_value "$state_root/revise-capture.metadata" message_lf_sha256
)
revise_header_hash=$(
  metadata_value "$state_root/revise-capture.metadata" header_order_sha256
)
revise_plan_hash=$(proxy_route_digest revise action_plan_sha256)
revise_authorized_fields_hash=$(
  proxy_route_digest revise authorized_fields_sha256
)
revise_actions=$(proxy_route_value revise actions)
[[ $revise_actions == 1 && $(proxy_route_value revise status) == 200 ]] ||
  fail "real revise proxy did not independently prove the exact action plan"
revise_header_count=$(
  metadata_value "$state_root/revise-capture.metadata" header_field_count
)
revise_owned_indexes=$(
  metadata_value "$state_root/revise-capture.metadata" owned_field_indexes
)
revise_first_fields_hash=$(
  metadata_value "$state_root/revise-capture.metadata" \
    first_owned_fields_sha256
)
case "$revise_actions" in
  1)
    revise_output_fields_hash=$(
      metadata_value "$state_root/revise-capture.metadata" last_owned_field_sha256
    )
    revise_action_order='action-order-dkim2-signature'
    [[ $(metadata_value \
      "$state_root/revise-capture.metadata" owned_field_sequence) == \
      message-instance,dkim2-signature,dkim2-signature ]] &&
      [[ $revise_header_count =~ ^[1-9][0-9]*$ ]] &&
      (( revise_header_count >= 3 )) &&
      [[ $revise_owned_indexes == \
        "$((revise_header_count - 3)),$((revise_header_count - 2)),$((revise_header_count - 1))" &&
        $revise_first_fields_hash == "$sign_output_fields_hash" &&
        $revise_authorized_fields_hash == "$revise_output_fields_hash" ]] ||
      fail "real hash-unchanged revise fields were not preserved and appended exactly"
    ;;
  *)
    fail "real revise proxy returned an unsupported action count"
    ;;
esac
revise_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
revise_invocation=$(
  sha256_text \
    "$row:$revise_request_hash:$revise_response_hash:$revise_output_hash:$revise_started"
)
write_live_case transport-filter revise "$revise_invocation" \
  "$revise_started" "$revise_finished" \
  "transport-exit-0,deliveries-1,invocation-sha256-$revise_invocation,authorized-fields-sha256-$revise_output_fields_hash,output-sha256-$revise_output_hash,header-order-sha256-$revise_header_hash" \
  "operation-revise,result-pass,invocation-sha256-$revise_invocation,request-sha256-$revise_request_hash,response-sha256-$revise_response_hash,action-plan-sha256-$revise_plan_hash,authorized-fields-sha256-$revise_authorized_fields_hash,actions-$revise_actions,$revise_action_order,output-sha256-$revise_output_hash,header-order-sha256-$revise_header_hash" \
  "route-revise,http-2xx-1,result-pass,invocation-sha256-$revise_invocation,request-sha256-$revise_request_hash,response-sha256-$revise_response_hash,action-plan-sha256-$revise_plan_hash,authorized-fields-sha256-$revise_authorized_fields_hash,actions-$revise_actions" \
  'fault-mode-none,outcome-not-applicable' \
  'version-match,build-id-match,validator-pass'
run_bcc_safe_case
incoming_envelope_hash=$(
  proxy_route_digest revise incoming_envelope_sha256
)
outgoing_envelope_hash=$(
  proxy_route_digest revise outgoing_envelope_sha256
)
[[ $incoming_envelope_hash != "$outgoing_envelope_hash" ]] ||
  fail "real incoming and outgoing envelope projections alias"
write_live_case smtp incoming-outgoing-envelope "$revise_invocation" \
  "$revise_started" "$revise_finished" \
  'smtp-final-250,deliveries-1' \
  "operation-process-revise,invocation-sha256-$revise_invocation,incoming-envelope-sha256-$incoming_envelope_hash,outgoing-envelope-sha256-$outgoing_envelope_hash,envelopes-distinct-1" \
  "route-process-revise,http-2xx-2,invocation-sha256-$revise_invocation,incoming-envelope-sha256-$incoming_envelope_hash,outgoing-envelope-sha256-$outgoing_envelope_hash" \
  'fault-mode-none,outcome-not-applicable' \
  'version-match,build-id-match,validator-pass'

journalctl --quiet --unit "$revise_adapter_unit" --output=cat \
  >"$state_root/revise-adapter.log"
stop_unit "$exact_exim_unit"
stop_unit "$revise_adapter_unit"
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "adapter socket persisted before evidence lifecycle cases"
run_evidence_fault_case missing-evidence missing
run_evidence_fault_case expired-evidence expired
run_evidence_fault_case tampered-evidence tampered
run_transport_daemon_fault_case daemon-unavailable close
run_transport_daemon_fault_case daemon-timeout timeout
run_transport_daemon_fault_case daemon-malformed malformed
run_transport_daemon_fault_case daemon-overflow overflow
run_nonascii_transport_case
run_filter_output_fault_case nonzero-deferral \
  "$config_root/exim-filter-nonzero.conf" 0
run_filter_output_fault_case partial-output \
  "$config_root/exim-filter-partial.conf" 64

curl -fsS http://127.0.0.1:18080/metrics >"$state_root/metrics.txt"
journalctl --quiet --unit "$daemon_unit" --output=cat >"$state_root/daemon.log"
if grep -E -i -n \
  'matrix@example\.test|body-(mismatch|exact|interactive|local-submission)|^subject:|authorization|cookie|private[-_ ]?key|capability' \
  "$state_root/mismatch-adapter.log" "$state_root/revise-adapter.log" \
  "$state_root/daemon.log" "$state_root/metrics.txt" >/dev/null; then
  fail "adapter or daemon diagnostics exposed a mail, identity, or secret marker"
fi
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "exact adapter did not remove its exact socket"
reset_evidence_runtime
write_adapter_config "$expected_build_id" tempfail false
start_adapter "$second_adapter_unit"
stop_unit "$second_adapter_unit"
[[ ! -e $socket_root/local-scan.sock && ! -L $socket_root/local-scan.sock ]] ||
  fail "repeated adapter stop did not remove its exact socket"

finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
expected_case_count=$(
  {
    real_matrix_cases smtp
    real_matrix_cases local-submission
    real_matrix_cases transport-filter
  } | wc -l | tr -d ' '
)
[[ $case_count -eq $expected_case_count ]] ||
  fail "qualification case coverage is incomplete"
grep -Fxq 'exim_user = Debian-exim' \
  <("$exim_binary" -C "$config_root/exim.conf" -bP exim_user 2>/dev/null) ||
  fail "real Exim user readback changed"
grep -Fxq 'exim_group = Debian-exim' \
  <("$exim_binary" -C "$config_root/exim.conf" -bP exim_group 2>/dev/null) ||
  fail "real Exim group readback changed"
printf '%s\n' "observation=exim-version-$expected_version" \
  >"$evidence_stage/version.readback"
printf '%s\n' 'observation=exim-user-Debian-exim' \
  >"$evidence_stage/exim-user.readback"
printf '%s\n' 'observation=exim-group-Debian-exim' \
  >"$evidence_stage/exim-group.readback"
printf '%s\n' 'observation=spool-wireformat-false' \
  >"$evidence_stage/spool-wireformat.readback"
printf '%s\n' "observation=local-scan-build-id-$expected_build_id" \
  >"$evidence_stage/local-scan.readback"
printf '%s\n' 'observation=sign-transport-validator-pass' \
  >"$evidence_stage/sign-transport.readback"
printf '%s\n' 'observation=revise-transport-validator-pass' \
  >"$evidence_stage/revise-transport.readback"
chmod 0600 "$evidence_stage"/*.readback
source_manifest="$repository_root/cmd/dkim2-exim/exim/fixtures/$row/source-manifest-v1.txt"
compatibility_manifest="$repository_root/cmd/dkim2-exim/exim/fixtures/$row/compatibility-manifest-v1.txt"
[[ ! -L $source_manifest && -s $source_manifest &&
  ! -L $compatibility_manifest && -s $compatibility_manifest ]] ||
  fail "authenticated row manifests are unavailable"
source_manifest_sha256=$(sha256sum "$source_manifest" | awk '{ print $1 }')
compatibility_manifest_sha256=$(
  sha256sum "$compatibility_manifest" | awk '{ print $1 }'
)
module_sha256=$(
  sha256sum "$repository_root/cmd/dkim2-exim/exim/dkim2_local_scan.c" |
    awk '{ print $1 }'
)
transport_filter_patch_sha256=$(
  sha256sum "$repository_root/cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch" |
    awk '{ print $1 }'
)
version_readback_sha256=$(
  sha256sum "$evidence_stage/version.readback" | awk '{ print $1 }'
)
exim_user_readback_sha256=$(
  sha256sum "$evidence_stage/exim-user.readback" | awk '{ print $1 }'
)
exim_group_readback_sha256=$(
  sha256sum "$evidence_stage/exim-group.readback" | awk '{ print $1 }'
)
spool_wireformat_readback_sha256=$(
  sha256sum "$evidence_stage/spool-wireformat.readback" | awk '{ print $1 }'
)
local_scan_readback_sha256=$(
  sha256sum "$evidence_stage/local-scan.readback" | awk '{ print $1 }'
)
sign_transport_readback_sha256=$(
  sha256sum "$evidence_stage/sign-transport.readback" | awk '{ print $1 }'
)
revise_transport_readback_sha256=$(
  sha256sum "$evidence_stage/revise-transport.readback" | awk '{ print $1 }'
)
printf '%s\n' \
  'format=dkim2-exim-real-matrix-result-v1' \
  "row=$row" \
  "exim_version=$expected_version" \
  "build_id=$expected_build_id" \
  "source_manifest_sha256=$source_manifest_sha256" \
  "compatibility_manifest_sha256=$compatibility_manifest_sha256" \
  "module_sha256=$module_sha256" \
  "transport_filter_patch_sha256=$transport_filter_patch_sha256" \
  "binary_sha256=$binary_sha256" \
  "adapter_sha256=$adapter_sha256" \
  "daemon_sha256=$daemon_sha256" \
  "runner_sha256=$runner_sha256" \
  "matrix_helper_sha256=$matrix_helper_sha256" \
  "deployment_validator_sha256=$deployment_validator_sha256" \
  "version_readback_sha256=$version_readback_sha256" \
  "exim_user_readback_sha256=$exim_user_readback_sha256" \
  "exim_group_readback_sha256=$exim_group_readback_sha256" \
  "spool_wireformat_readback_sha256=$spool_wireformat_readback_sha256" \
  "local_scan_readback_sha256=$local_scan_readback_sha256" \
  "sign_transport_readback_sha256=$sign_transport_readback_sha256" \
  "revise_transport_readback_sha256=$revise_transport_readback_sha256" \
  "run_id=$run_id" \
  "started_at=$started_at" \
  "finished_at=$finished_at" \
  "case_count=$case_count" \
  'privacy_scan=passed' \
  'status=passed' >"$evidence_stage/result-v1.txt"
chmod 0600 "$evidence_stage/result-v1.txt"
if grep -E -i -R -n \
  '(^|[^a-z])(message-id|subject|authorization|cookie|private[-_ ]?key|capability|bearer)([^a-z]|$)|@' \
  "$evidence_stage" >/dev/null; then
  fail "published evidence contains a privacy marker"
fi
finalize_runtime || fail "qualification runtime did not finalize cleanly"
finalized=1
mv "$evidence_stage" "$evidence_root"
printf '%s\n' "$run_id"
