#!/bin/sh
# Copyright 2026 Christian Roessner
# SPDX-License-Identifier: Apache-2.0
# This fixture is sourced by the canonical runner and shares only its private Compose invocation.

# observation_control changes only the independent learning fault mode through atomic replacement.
observation_control() {
  jq --arg mode "$1" '.observation_mode = $mode' \
    "$RUNTIME_DIR/state/policy-observer-control.json" >"$RUNTIME_DIR/state/observation-control.next"
  mv "$RUNTIME_DIR/state/observation-control.next" "$RUNTIME_DIR/state/policy-observer-control.json"
}

# learned_snapshot reports only the bounded digest of actual Nauthilus reputation state.
learned_snapshot() {
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" exec -T policy-observer python3 /fixture/reputation_probe.py snapshot
}

# wait_observation waits for one opaque event's explicit delivery evidence within a finite fixture deadline.
wait_observation() {
  OBSERVATION_WAIT=0
  while ! jq -e --arg digest "$OBSERVATION_DIGEST" --arg field "$1" --argjson minimum "$2" \
    '(.observations[$digest][$field] // 0) >= $minimum' \
    "$RUNTIME_DIR/state/policy-observer-state.json" >/dev/null; do
    OBSERVATION_WAIT=$((OBSERVATION_WAIT + 1))
    test "$OBSERVATION_WAIT" -lt 160 || {
      echo "observation recovery evidence deadline exceeded: $1" >&2
      return 1
    }
    sleep 0.25
  done
}

# prove_observation_recovery checks storage-before-completion, process crash, Redis crash and lost acknowledgement.
prove_observation_recovery() {
  observation_control unavailable
  SNAPSHOT_BEFORE=$(learned_snapshot)
  printf '%s' "$SNAPSHOT_BEFORE" | jq -e '.state_keys >= 4' >/dev/null
  UNSIGNED_LOG="$RUNTIME_DIR/state/unsigned-recovery.log"
  if ! run_scan scan-unsigned.lua >"$UNSIGNED_LOG" 2>&1; then
    cat "$UNSIGNED_LOG" >&2
    return 1
  fi
  grep -q 'DKIM2_OBSERVATION_PERSISTED' "$UNSIGNED_LOG"
  if grep -q 'DKIM2_OBSERVATION_UNAVAILABLE' "$UNSIGNED_LOG"; then
    return 1
  fi
  OBSERVATION_WAIT=0
  until OBSERVATION_DIGEST=$(jq -er '.last_observation' "$RUNTIME_DIR/state/policy-observer-state.json"); do
    OBSERVATION_WAIT=$((OBSERVATION_WAIT + 1))
    test "$OBSERVATION_WAIT" -lt 80 || return 1
    sleep 0.25
  done
  wait_observation received 1
  test "$(learned_snapshot)" = "$SNAPSHOT_BEFORE"
  jq -e --arg digest "$OBSERVATION_DIGEST" \
    '.observations | length == 1' "$RUNTIME_DIR/state/policy-observer-state.json" >/dev/null
  test "$(stub_calls)" -eq 0
  test "$(observer_value calls)" -eq 0

  # Only this invocation's disposable services are crashed; AOF and protected keys remain mounted.
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" kill -s SIGKILL rspamd outbox-redis >/dev/null
  observation_control drop_ack
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" up -d --wait --wait-timeout 90 outbox-redis rspamd >/dev/null
  wait_observation forwarded 1
  jq -e --arg digest "$OBSERVATION_DIGEST" \
    '.observations[$digest] | .last_status == 200 and .last_effect == "permit"' \
    "$RUNTIME_DIR/state/policy-observer-state.json" >/dev/null
  SNAPSHOT_ADMITTED=$(learned_snapshot)
  test "$SNAPSHOT_ADMITTED" != "$SNAPSHOT_BEFORE"
  observation_control forward
  wait_observation forwarded 2
  test "$(learned_snapshot)" = "$SNAPSHOT_ADMITTED"
  jq -e --arg digest "$OBSERVATION_DIGEST" \
    '(.observations | length) == 1 and .last_observation == $digest and .observations[$digest].preceding_decisions == 0' \
    "$RUNTIME_DIR/state/policy-observer-state.json" >/dev/null
  echo 'observation_persist_before_smtp=PASS crash_replay_same_bytes=PASS lost_ack_single_state_change=PASS'
}

# wait_outbox_empty requires acknowledged removal of all persisted records before inspecting learned state.
wait_outbox_empty() {
  OUTBOX_DRAIN_WAIT=0
  until docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
      -f "$COMPOSE_FILE" exec -T policy-observer python3 /fixture/reputation_probe.py outbox-empty; do
    OUTBOX_DRAIN_WAIT=$((OUTBOX_DRAIN_WAIT + 1))
    test "$OUTBOX_DRAIN_WAIT" -lt 160 || return 1
    sleep 0.25
  done
}

# wait_learning_drain requires an empty durable queue and successful admission for every captured observation.
wait_learning_drain() {
  wait_outbox_empty
  OBSERVATION_WAIT=0
  while ! jq -e '.observations | length > 0 and all(.[]; .forwarded >= 1 and .last_status == 200 and .last_effect == "permit")' \
      "$RUNTIME_DIR/state/policy-observer-state.json" >/dev/null; do
    OBSERVATION_WAIT=$((OBSERVATION_WAIT + 1))
    test "$OBSERVATION_WAIT" -lt 160 || return 1
    sleep 0.25
  done
}

# prove_later_reputation requires a completed current decision before its independent evidence affects the next one.
prove_later_reputation() {
  test "$(observer_value last_upstream_code)" = permit
  OBSERVATION_WAIT=0
  while test "$(observer_value observation_calls)" -le "$OBSERVATIONS_BEFORE_REJECT"; do
    OBSERVATION_WAIT=$((OBSERVATION_WAIT + 1))
    test "$OBSERVATION_WAIT" -lt 160 || return 1
    sleep 0.25
  done
  wait_learning_drain
  learned_snapshot | jq -e '.mail_risk_mass > 20' >/dev/null
  clear_retry_scenario
  run_scan scan-learned-peer-reject.lua
  test "$(observer_value last_upstream_code)" = policy_denied
  echo 'current_event_not_self_observed=PASS later_dkim2_uses_independent_reputation=PASS policy_reject_not_learning_signal=PASS'
}

# seed_signer admits controlled evidence only through the fixture seeder's real authenticated source policy.
seed_signer() {
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" exec -T policy-observer python3 /fixture/reputation_probe.py \
    seed --password-file /probe/seed-password --signer-only "$@"
}

# prove_hop_reputation compares producer-bound same/split-hop and current/historical identity controls.
prove_hop_reputation() {
  seed_signer --domain historical.example.test --signal fixture.risk --count 20
  seed_signer --domain google.example
  seed_signer --domain other.example.test
  seed_signer --domain aged.example.test --age-seconds 43200
  for SCENARIO in same_hop_risk split_hop_risk historical_provider current_provider aged_reputation; do
    clear_retry_scenario
    set_dkim_mode "$SCENARIO"
    run_scan "scan-$SCENARIO.lua"
    assert_policy_request 203.0.113.25 greylist "$RUNTIME_DIR/projections/$SCENARIO.json"
    case "$SCENARIO" in
      same_hop_risk) EXPECTED_CODE=policy_denied ;;
      historical_provider) EXPECTED_CODE=no_match_deny ;;
      *) EXPECTED_CODE=permit ;;
    esac
    test "$(observer_value last_upstream_code)" = "$EXPECTED_CODE"
  done
  set_dkim_mode default
  clear_retry_scenario
  echo 'same_hop_risk_denied=PASS split_hop_risk_not_denied=PASS historical_provider_not_permitted=PASS current_provider_control=PASS numeric_reputation_decay=PASS trusted_geoip_exact_binding=PASS'
}

# restart_policy reloads this invocation's immutable native providers against the current local data snapshot.
restart_policy() {
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" restart nauthilus-policy >/dev/null
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" up -d --wait --wait-timeout 90 nauthilus-policy >/dev/null
}

# age_geoip changes only the timestamp of the synthetic mounted database; real data never enters this lane.
age_geoip() {
  python3 - "$RUNTIME_DIR/geoip.json" "$1" <<'PY_AGE'
import os
import sys
import time
age = int(sys.argv[2])
assert age in (0, 8640000)
observed = time.time() - age
os.utime(sys.argv[1], (observed, observed))
PY_AGE
}

# prove_provider_outages requires explicit denial for unavailable geography and SMTP failure without outbox persistence.
prove_provider_outages() {
  wait_learning_drain
  observation_control unavailable
  clear_retry_scenario
  age_geoip 8640000
  restart_policy
  run_scan scan-geoip-unavailable.lua
  test "$(observer_value last_upstream_code)" = policy_denied
  age_geoip 0
  restart_policy
  clear_retry_scenario
  run_scan scan-geoip-restored.lua
  test "$(observer_value last_upstream_code)" = permit
  observation_control forward
  wait_learning_drain

  # Stop the separate outbox authority while keeping the decision and verifier authorities available.
  clear_retry_scenario
  BEFORE_OUTBOX_FAILURE=$(observer_value observation_calls)
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" stop outbox-redis >/dev/null
  OUTBOX_FAILURE_LOG="$RUNTIME_DIR/state/outbox-failure.log"
  if ! run_scan scan-outbox-unavailable.lua >"$OUTBOX_FAILURE_LOG" 2>&1; then
    cat "$OUTBOX_FAILURE_LOG" >&2
    return 1
  fi
  grep -q DKIM2_OBSERVATION_UNAVAILABLE "$OUTBOX_FAILURE_LOG"
  if grep -q DKIM2_OBSERVATION_PERSISTED "$OUTBOX_FAILURE_LOG"; then
    return 1
  fi
  test "$(observer_value observation_calls)" -eq "$BEFORE_OUTBOX_FAILURE"
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" up -d --wait --wait-timeout 90 outbox-redis >/dev/null
  OUTBOX_RECOVERY_LOG="$RUNTIME_DIR/state/outbox-recovery.log"
  if ! run_scan scan-outbox-restored.lua >"$OUTBOX_RECOVERY_LOG" 2>&1; then
    cat "$OUTBOX_RECOVERY_LOG" >&2
    return 1
  fi
  grep -q DKIM2_OBSERVATION_PERSISTED "$OUTBOX_RECOVERY_LOG"
  grep -q GREYLIST "$OUTBOX_RECOVERY_LOG"
  if grep -q DKIM2_OBSERVATION_UNAVAILABLE "$OUTBOX_RECOVERY_LOG"; then
    return 1
  fi
  echo 'geoip_unavailable_denied=PASS geoip_fresh_recovery=PASS outbox_persistence_outage_tempfail=PASS outbox_recovery=PASS'
}
