#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DKIM2_REPO=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
WORKSPACE_ROOT=$(dirname "$DKIM2_REPO")
NAUTHILUS_REPO=${NAUTHILUS_REPO:-"$WORKSPACE_ROOT/nauthilus"}
MILTERTEST_REPO=${MILTERTEST_REPO:-"$WORKSPACE_ROOT/miltertest-go"}
RUNTIME_DIR=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-policy-e2e.XXXXXX")
PROJECT_SUFFIX=$(basename "$RUNTIME_DIR" | tr '[:upper:].' '[:lower:]-')
PROJECT_NAME="dkim2-policy-e2e-$PROJECT_SUFFIX"
COMPOSE_FILE="$SCRIPT_DIR/policy-e2e/docker-compose.yml"
ENV_FILE="$RUNTIME_DIR/compose.env"
REUSED_NAUTHILUS_IMAGE=${POLICY_E2E_REUSE_NAUTHILUS_IMAGE:-}
NAUTHILUS_IMAGE=${REUSED_NAUTHILUS_IMAGE:-"$PROJECT_NAME-nauthilus"}
MILTERTEST_IMAGE="$PROJECT_NAME-miltertest"

cleanup() {
  STATUS=$?
  if test "$STATUS" -ne 0 && test -f "$ENV_FILE"; then
    if test -f "$RUNTIME_DIR/state/policy-observer-state.json"; then
      jq '{calls, forwarded_calls, last_mode, last_upstream_status, last_upstream_error}' \
        "$RUNTIME_DIR/state/policy-observer-state.json" >&2 || true
    fi
    docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
      -f "$COMPOSE_FILE" logs --no-color --tail 240 2>&1 |
      grep -Ei 'dkim2|policy|HTTP request|error|warn|task_write_log' |
      tail -120 >&2 || true
  fi
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
  chmod -R u+w "$RUNTIME_DIR" >/dev/null 2>&1 || true
  rm -rf "$RUNTIME_DIR"
  return "$STATUS"
}
trap cleanup EXIT INT TERM

require_checkout() {
  CHECKOUT_PATH=$1
  OVERRIDE_NAME=$2

  test -f "$CHECKOUT_PATH/go.mod" || {
    echo "required checkout is unavailable: $CHECKOUT_PATH" >&2
    echo "place it next to the DKIM2 checkout or set $OVERRIDE_NAME explicitly" >&2
    exit 1
  }
}

require_checkout "$NAUTHILUS_REPO" NAUTHILUS_REPO
require_checkout "$MILTERTEST_REPO" MILTERTEST_REPO

if test "${POLICY_E2E_PREFLIGHT_ONLY:-0}" = 1; then
  echo "DKIM2 Policy E2E checkout preflight: PASS"
  exit 0
fi

command -v docker >/dev/null
command -v openssl >/dev/null
command -v jq >/dev/null
command -v go >/dev/null

"$SCRIPT_DIR/policy-e2e/verify-two-hop-projection.sh"

umask 077
mkdir -p "$RUNTIME_DIR/certs" "$RUNTIME_DIR/protected" "$RUNTIME_DIR/state"
printf '%s\n' '{"mode":"default"}' >"$RUNTIME_DIR/state/dkim2-stub-control.json"
printf '%s\n' '{"mode":"forward"}' >"$RUNTIME_DIR/state/policy-observer-control.json"
openssl rand 32 >"$RUNTIME_DIR/protected/process-capability"
openssl rand 32 >"$RUNTIME_DIR/protected/rspamd-retry-hmac"
POLICY_PASSWORD=$(openssl rand -hex 24)
REDIS_ENCRYPTION_SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD_NONCE=$(openssl rand -hex 32)
printf '%s' "$POLICY_PASSWORD" >"$RUNTIME_DIR/protected/nauthilus-policy-password"

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj "/CN=DKIM2 Policy E2E CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$RUNTIME_DIR/certs/policy-e2e-ca.key" \
  -out "$RUNTIME_DIR/certs/policy-e2e-ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=nauthilus-policy" \
  -addext "subjectAltName=DNS:nauthilus-policy,DNS:policy-observer" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$RUNTIME_DIR/certs/nauthilus-policy.key" \
  -out "$RUNTIME_DIR/certs/nauthilus-policy.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 \
  -in "$RUNTIME_DIR/certs/nauthilus-policy.csr" \
  -CA "$RUNTIME_DIR/certs/policy-e2e-ca.crt" \
  -CAkey "$RUNTIME_DIR/certs/policy-e2e-ca.key" \
  -CAcreateserial -copy_extensions copy \
  -out "$RUNTIME_DIR/certs/nauthilus-policy.crt" >/dev/null 2>&1
chmod 0555 "$RUNTIME_DIR/certs" "$RUNTIME_DIR/protected"
chmod 0444 \
  "$RUNTIME_DIR/certs/policy-e2e-ca.crt" \
  "$RUNTIME_DIR/certs/nauthilus-policy.crt" \
  "$RUNTIME_DIR/certs/nauthilus-policy.key" \
  "$RUNTIME_DIR/protected/process-capability" \
  "$RUNTIME_DIR/protected/rspamd-retry-hmac" \
  "$RUNTIME_DIR/protected/nauthilus-policy-password"

write_env() {
  {
    printf 'POLICY_E2E_RUNTIME=%s\n' "$RUNTIME_DIR"
    printf 'POLICY_E2E_PASSWORD=%s\n' "$POLICY_PASSWORD"
    printf 'POLICY_E2E_REDIS_ENCRYPTION_SECRET=%s\n' "$REDIS_ENCRYPTION_SECRET"
    printf 'POLICY_E2E_REDIS_PASSWORD_NONCE=%s\n' "$REDIS_PASSWORD_NONCE"
    printf 'POLICY_E2E_NAUTHILUS_IMAGE=%s\n' "$NAUTHILUS_IMAGE"
    printf 'POLICY_E2E_MILTERTEST_IMAGE=%s\n' "$MILTERTEST_IMAGE"
    printf 'NAUTHILUS_REPO=%s\n' "$NAUTHILUS_REPO"
    printf 'MILTERTEST_REPO=%s\n' "$MILTERTEST_REPO"
    printf 'PLUGIN_SHA256=%s\n' "${1:-missing}"
  } >"$ENV_FILE"
}

write_env
if test -n "$REUSED_NAUTHILUS_IMAGE"; then
  docker image inspect "$REUSED_NAUTHILUS_IMAGE" >/dev/null
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" build miltertest
else
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" build nauthilus-policy miltertest
fi
PLUGIN_SHA256=$(docker run --rm --entrypoint sha256sum "$NAUTHILUS_IMAGE" \
  /usr/local/lib/nauthilus/plugins/dkim2-reputation.so | awk '{print $1}')
test "${#PLUGIN_SHA256}" -eq 64
write_env "$PLUGIN_SHA256"

docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" up -d --wait --wait-timeout 90 \
  redis dkim2-stub nauthilus-policy policy-observer rspamd
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" exec -T rspamd \
  getent hosts nauthilus-policy policy-observer >/dev/null
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" exec -T rspamd \
  openssl s_client -connect policy-observer:9444 \
  -servername policy-observer \
  -CAfile /etc/ssl/certs/policy-e2e-ca.crt \
  -verify_return_error </dev/null >/dev/null 2>&1
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" exec -T rspamd \
  openssl s_client -connect nauthilus-policy:9443 \
  -servername nauthilus-policy \
  -CAfile /etc/ssl/certs/policy-e2e-ca.crt \
  -verify_return_error </dev/null >/dev/null 2>&1

run_scan() {
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" run --rm miltertest \
    -c /fixture/miltertest.yml -s "/fixture/$1"
}

stub_calls() {
  jq -er '.calls' "$RUNTIME_DIR/state/dkim2-stub-state.json"
}

observer_value() {
  jq -er ".$1" "$RUNTIME_DIR/state/policy-observer-state.json"
}

set_dkim_mode() {
  printf '{"mode":"%s"}\n' "$1" >"$RUNTIME_DIR/state/dkim2-stub-control.json"
}

set_policy_mode() {
  printf '{"mode":"%s"}\n' "$1" >"$RUNTIME_DIR/state/policy-observer-control.json"
}

redis_command() {
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" exec -T redis valkey-cli -n 0 "$@"
}

flush_retry_cache() {
  test "$(redis_command FLUSHDB)" = "OK"
}

retry_cache_size() {
  redis_command --scan --pattern 'dkim2:retry:v1:*' |
    awk 'NF { count++ } END { print count + 0 }'
}

assert_policy_request() {
  RESPONSE=${3:-"$SCRIPT_DIR/policy-e2e/dkim2-response.json"}
  python3 "$SCRIPT_DIR/policy-e2e/assert_policy_request.py" \
    --state "$RUNTIME_DIR/state/policy-observer-state.json" \
    --response "$RESPONSE" \
    --peer-ip "$1" --expected-action "$2"
}

# A non-applicable unsigned message must call neither upstream service.
run_scan scan-unsigned.lua
test "$(stub_calls)" -eq 0
test "$(observer_value calls)" -eq 0

# The first retry flow captures the complete request, arms once, then consumes.
run_scan scan-tempfail.lua
test "$(stub_calls)" -eq 1
test "$(observer_value calls)" -eq 1
test "$(observer_value forwarded_calls)" -eq 1
assert_policy_request 203.0.113.25 greylist

sleep 2
run_scan scan-accept.lua
test "$(stub_calls)" -eq 1
test "$(observer_value calls)" -eq 2
test "$(observer_value forwarded_calls)" -eq 2

# A later duplicate returns to dkim2d after consume and replay rejection bypasses Policy.
set_dkim_mode replayed
run_scan scan-replayed-reject.lua
test "$(stub_calls)" -eq 2
test "$(observer_value calls)" -eq 2
set_dkim_mode default
flush_retry_cache

# Malformed upstream verifier JSON is a temporary failure and never reaches Policy.
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
set_dkim_mode malformed
run_scan scan-dkim-malformed.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$POLICY_BEFORE"
set_dkim_mode default
flush_retry_cache

# Malformed Policy JSON, Policy timeout, and provider-invalid input all fail closed.
for MODE in malformed_response timeout invalid_provider; do
  STUB_BEFORE=$(stub_calls)
  POLICY_BEFORE=$(observer_value calls)
  FORWARDED_BEFORE=$(observer_value forwarded_calls)
  set_policy_mode "$MODE"
  run_scan scan-policy-failure.lua
  test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
  test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 1))"
  if test "$MODE" = invalid_provider; then
    test "$(observer_value forwarded_calls)" -eq "$((FORWARDED_BEFORE + 1))"
  else
    test "$(observer_value forwarded_calls)" -eq "$FORWARDED_BEFORE"
  fi
  flush_retry_cache
done
set_policy_mode forward

# A producer-bound two-hop chain is denied solely because its historical signer is unknown.
flush_retry_cache
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
set_dkim_mode two_hop
run_scan scan-two-hop-reject.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 1))"
assert_policy_request 203.0.113.25 greylist \
  "$SCRIPT_DIR/policy-e2e/dkim2-two-hop-response.json"
test "$(retry_cache_size)" -eq 0
set_dkim_mode default

# An oversized but syntactically valid cached JSON document is never reused.
flush_retry_cache
run_scan scan-cache-oversized.lua
OVERSIZED_KEY=$(redis_command --scan --pattern 'dkim2:retry:v1:*')
test -n "$OVERSIZED_KEY"
UPDATED=$(python3 -c \
  'import json, sys; json.dump({"padding": "x" * 262144}, sys.stdout, separators=(",", ":"))' |
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" exec -T redis valkey-cli -n 0 -x HSET "$OVERSIZED_KEY" payload)
test "$UPDATED" -eq 0
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
run_scan scan-cache-oversized.lua
test "$(stub_calls)" -eq "$STUB_BEFORE"
test "$(observer_value calls)" -eq "$POLICY_BEFORE"
test "$(redis_command HGET "$OVERSIZED_KEY" state)" = claimed

# An armed result for the same message but another envelope identity is not reused.
flush_retry_cache
run_scan scan-cache-identity-source.lua
IDENTITY_KEY=$(redis_command --scan --pattern 'dkim2:retry:v1:*')
test -n "$IDENTITY_KEY"
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
set_dkim_mode replayed
run_scan scan-cache-identity-mismatch.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$POLICY_BEFORE"
test "$(redis_command EXISTS "$IDENTITY_KEY")" -eq 1
test "$(retry_cache_size)" -eq 1
set_dkim_mode default

# While one worker owns an armed retry claim, a competitor fails closed on BUSY.
flush_retry_cache
run_scan scan-concurrent-retry.lua
CONCURRENT_KEY=$(redis_command --scan --pattern 'dkim2:retry:v1:*')
test -n "$CONCURRENT_KEY"
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
FORWARDED_BEFORE=$(observer_value forwarded_calls)
set_policy_mode timeout
WINNER_LOG="$RUNTIME_DIR/state/concurrent-winner.log"
run_scan scan-concurrent-retry.lua >"$WINNER_LOG" 2>&1 &
WINNER_PID=$!
WAIT_COUNT=0
while test "$(observer_value calls)" -eq "$POLICY_BEFORE"; do
  if ! kill -0 "$WINNER_PID" 2>/dev/null; then
    wait "$WINNER_PID" || true
    cat "$WINNER_LOG" >&2
    exit 1
  fi
  WAIT_COUNT=$((WAIT_COUNT + 1))
  test "$WAIT_COUNT" -lt 50 || {
    cat "$WINNER_LOG" >&2
    exit 1
  }
  sleep 0.1
done
run_scan scan-concurrent-retry.lua
if ! wait "$WINNER_PID"; then
  cat "$WINNER_LOG" >&2
  exit 1
fi
test "$(stub_calls)" -eq "$STUB_BEFORE"
test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 1))"
test "$(observer_value forwarded_calls)" -eq "$FORWARDED_BEFORE"
test "$(redis_command HGET "$CONCURRENT_KEY" state)" = armed
set_policy_mode forward
flush_retry_cache

# Redis unavailability fails before dkim2d or Policy and recovers without state reuse.
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" stop redis >/dev/null
run_scan scan-redis-failure.lua
test "$(stub_calls)" -eq "$STUB_BEFORE"
test "$(observer_value calls)" -eq "$POLICY_BEFORE"
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" up -d --wait --wait-timeout 30 redis >/dev/null
flush_retry_cache

# A corrupt armed entry is deleted and fails closed without either upstream call.
run_scan scan-corrupt-cache.lua
CACHE_KEY=$(redis_command --scan --pattern 'dkim2:retry:v1:*')
test -n "$CACHE_KEY"
test "$(printf '%s\n' "$CACHE_KEY" | wc -l | tr -d ' ')" -eq 1
redis_command HSET "$CACHE_KEY" state corrupt >/dev/null
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
run_scan scan-corrupt-cache.lua
test "$(stub_calls)" -eq "$STUB_BEFORE"
test "$(observer_value calls)" -eq "$POLICY_BEFORE"
test "$(redis_command EXISTS "$CACHE_KEY")" -eq 0
flush_retry_cache

# A real Policy deny is terminal: each identical delivery returns to dkim2d.
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
run_scan scan-policy-reject.lua
test "$(retry_cache_size)" -eq 0
assert_policy_request 198.51.100.25 greylist
run_scan scan-policy-reject.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 2))"
test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 2))"
test "$(retry_cache_size)" -eq 0

# An unrelated Rspamd rejection survives a Policy permit and consumes its cache entry.
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
run_scan scan-unrelated-reject.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 1))"
assert_policy_request 203.0.113.25 reject
test "$(retry_cache_size)" -eq 0

FINAL_STUB_CALLS=$(stub_calls)
FINAL_POLICY_CALLS=$(observer_value calls)
FINAL_FORWARDED_CALLS=$(observer_value forwarded_calls)

printf '%s\n' \
  "DKIM2/Rspamd/Nauthilus Policy E2E: PASS" \
  "stub_calls=$FINAL_STUB_CALLS policy_calls=$FINAL_POLICY_CALLS forwarded_policy_calls=$FINAL_FORWARDED_CALLS" \
  "request_projection=exact smtp_peers=203.0.113.25,198.51.100.25"
