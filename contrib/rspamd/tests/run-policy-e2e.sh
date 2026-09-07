#!/bin/sh
export GOEXPERIMENT=runtimesecret
export GOTOOLCHAIN=go1.27.0
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
RSPAMD_IMAGE=${POLICY_E2E_RSPAMD_IMAGE:-rspamd/rspamd:4.1.5}
# RECEIVED_DSN_ATTRIBUTE selects whether the Rspamd option
# nauthilus.received_dsn_attribute is enabled for this run. The fixture enables
# it; "false" rewrites the runtime copy of local.d and asserts the attribute
# absent, which is the variant that passes against a Policy allowlist that has
# not admitted dkim2.received_dsn_propagation.
RECEIVED_DSN_ATTRIBUTE=${POLICY_E2E_RECEIVED_DSN_ATTRIBUTE:-true}
case $RECEIVED_DSN_ATTRIBUTE in
  true|false) ;;
  *)
    echo "POLICY_E2E_RECEIVED_DSN_ATTRIBUTE must be true or false" >&2
    exit 2
    ;;
esac
RSPAMD_LOCAL_D="$RUNTIME_DIR/rspamd-local.d"

cleanup() {
  STATUS=$?
  if test "$STATUS" -ne 0 && test -f "$ENV_FILE"; then
    if test -f "$RUNTIME_DIR/state/policy-observer-state.json"; then
      jq '{calls, forwarded_calls, last_mode, last_upstream_status, last_upstream_error, last_request_id_matches}' \
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

"$SCRIPT_DIR/observation_outbox_native_test.sh" "$RSPAMD_IMAGE"
python3 "$SCRIPT_DIR/policy-e2e/policy_observer_test.py"
python3 "$SCRIPT_DIR/policy-e2e/reputation_probe_test.py"
mkdir -p "$RUNTIME_DIR/projections"
POLICY_E2E_PROJECTION_OUTPUT="$RUNTIME_DIR/projections" "$SCRIPT_DIR/policy-e2e/verify-two-hop-projection.sh"

umask 077
mkdir -p "$RUNTIME_DIR/certs" "$RUNTIME_DIR/protected" "$RUNTIME_DIR/state"
# The runtime local.d copy carries the selected received-DSN attribute setting
# and is the only Rspamd configuration the stack mounts.
mkdir -p "$RSPAMD_LOCAL_D"
cp "$SCRIPT_DIR"/policy-e2e/rspamd/local.d/* "$RSPAMD_LOCAL_D/"
grep -q '^  received_dsn_attribute = true;$' "$RSPAMD_LOCAL_D/dkim2.conf"
if test "$RECEIVED_DSN_ATTRIBUTE" = false; then
  sed -i.orig 's/^  received_dsn_attribute = true;$/  received_dsn_attribute = false;/' \
    "$RSPAMD_LOCAL_D/dkim2.conf"
  rm -f "$RSPAMD_LOCAL_D/dkim2.conf.orig"
  grep -q '^  received_dsn_attribute = false;$' "$RSPAMD_LOCAL_D/dkim2.conf"
fi
chmod 0555 "$RSPAMD_LOCAL_D"
chmod 0444 "$RSPAMD_LOCAL_D"/*
printf '%s\n' '{"mode":"default"}' >"$RUNTIME_DIR/state/dkim2-stub-control.json"
printf '%s\n' '{"mode":"forward"}' >"$RUNTIME_DIR/state/policy-observer-control.json"
openssl rand 32 >"$RUNTIME_DIR/protected/process-capability"
openssl rand 32 >"$RUNTIME_DIR/protected/rspamd-retry-hmac"
POLICY_PASSWORD=$(openssl rand -hex 24)
OBSERVATION_PASSWORD=$(openssl rand -hex 24)
SEED_PASSWORD=$(openssl rand -hex 24)
OUTBOX_PASSWORD=$(openssl rand -hex 24)
for KEY_NAME in reputation-subject-key reputation-manifest-key outbox-allocation outbox-encryption-active outbox-encryption-previous; do
  openssl rand 32 >"$RUNTIME_DIR/protected/$KEY_NAME"
done
printf '%s' "$OBSERVATION_PASSWORD" >"$RUNTIME_DIR/protected/observation-password"
printf '%s' "$SEED_PASSWORD" >"$RUNTIME_DIR/protected/fixture-seed-password"
printf '%s' "$OUTBOX_PASSWORD" >"$RUNTIME_DIR/protected/outbox-password"
python3 - "$RUNTIME_DIR" <<'PY_FIXTURE'
import hashlib
import json
from pathlib import Path
import sys
root=Path(sys.argv[1])
password=(root/'protected/outbox-password').read_bytes()
inspection=__import__('secrets').token_hex(32)
(root/'protected/outbox-inspection-password').write_text(inspection)
commands='+ping +auth +hello +evalsha +eval +script|load +script|exists +time +type +hgetall +hget +hmget +hlen +hset +hdel +exists +zadd +zrange +zrangebyscore +zscore +zrem +zcard +pttl +del'
(root/'protected/outbox.acl').write_text('user default off\nuser health on nopass +ping\nuser outbox on #'+hashlib.sha256(password).hexdigest()+' ~dkim2:observation:v1:* '+commands+'\nuser inspector on #'+hashlib.sha256(inspection.encode()).hexdigest()+
    ' ~dkim2:observation:v1:*:capacity ~dkim2:observation:v1:*:due +hgetall +zcard\n')
(root/'geoip.json').write_text(json.dumps({'records':[
  {'cidr':'203.0.113.0/24','country_iso':'DE','country_name':'Fixture','city_name':'Fixture','asn':64500,'asn_org':'Fixture trusted route'},
  {'cidr':'198.51.100.0/24','country_iso':'DE','country_name':'Fixture','city_name':'Fixture','asn':64501,'asn_org':'Fixture other route'}]}))
PY_FIXTURE
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
openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=outbox-redis" -addext "subjectAltName=DNS:outbox-redis" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$RUNTIME_DIR/certs/outbox-redis.key" -out "$RUNTIME_DIR/certs/outbox-redis.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 -in "$RUNTIME_DIR/certs/outbox-redis.csr" \
  -CA "$RUNTIME_DIR/certs/policy-e2e-ca.crt" -CAkey "$RUNTIME_DIR/certs/policy-e2e-ca.key" \
  -CAcreateserial -copy_extensions copy -out "$RUNTIME_DIR/certs/outbox-redis.crt" >/dev/null 2>&1
(
  cd "$NAUTHILUS_REPO"
  GOEXPERIMENT=runtimesecret go test -mod=vendor "$SCRIPT_DIR/policy-e2e/compose_config.go" "$SCRIPT_DIR/policy-e2e/compose_config_test.go"
  go run -mod=vendor "$SCRIPT_DIR/policy-e2e/compose_config.go" "$RUNTIME_DIR/nauthilus.yml" \
    server/docs/examples/go_plugin_reputation.yml \
    server/docs/examples/reputation_geoip_observation.yml \
    server/docs/examples/go_plugin_dkim2_intelligence.yml \
    server/docs/examples/policy_dkim2_rspamd_verifier.yml \
    "$SCRIPT_DIR/policy-e2e/reputation-fixture.yml" "$SCRIPT_DIR/policy-e2e/nauthilus.yml"
)
chmod 0444 "$RUNTIME_DIR/nauthilus.yml" "$RUNTIME_DIR/geoip.json"
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
    printf 'POLICY_E2E_RSPAMD_LOCAL_D=%s\n' "$RSPAMD_LOCAL_D"
    printf 'POLICY_E2E_PASSWORD=%s\n' "$POLICY_PASSWORD"
    printf 'POLICY_E2E_OBSERVATION_PASSWORD=%s\n' "$OBSERVATION_PASSWORD"
    printf 'POLICY_E2E_SEED_PASSWORD=%s\n' "$SEED_PASSWORD"
    printf 'POLICY_E2E_RSPAMD_IMAGE=%s\n' "$RSPAMD_IMAGE"
    printf 'POLICY_E2E_REDIS_ENCRYPTION_SECRET=%s\n' "$REDIS_ENCRYPTION_SECRET"
    printf 'POLICY_E2E_REDIS_PASSWORD_NONCE=%s\n' "$REDIS_PASSWORD_NONCE"
    printf 'POLICY_E2E_NAUTHILUS_IMAGE=%s\n' "$NAUTHILUS_IMAGE"
    printf 'POLICY_E2E_MILTERTEST_IMAGE=%s\n' "$MILTERTEST_IMAGE"
    printf 'NAUTHILUS_REPO=%s\n' "$NAUTHILUS_REPO"
    printf 'MILTERTEST_REPO=%s\n' "$MILTERTEST_REPO"
    printf 'REPUTATION_PLUGIN_SHA256=%s\n' "${REPUTATION_PLUGIN_SHA256:-missing}"
    printf 'GEOIP_PLUGIN_SHA256=%s\n' "${GEOIP_PLUGIN_SHA256:-missing}"
    printf 'INTELLIGENCE_PLUGIN_SHA256=%s\n' "${INTELLIGENCE_PLUGIN_SHA256:-missing}"
  } >"$ENV_FILE"
}

write_env
if test -n "$REUSED_NAUTHILUS_IMAGE"; then
  test -z "$(git -C "$NAUTHILUS_REPO" status --porcelain --untracked-files=normal)" || {
    echo "reused Nauthilus images require a clean matching checkout" >&2
    exit 1
  }
  docker image inspect "$REUSED_NAUTHILUS_IMAGE" >/dev/null
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" build miltertest
else
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" build nauthilus-policy miltertest
fi
# plugin_checksum reads only public artifact digests from the exact coherent bundle.
plugin_checksum() {
  docker run --rm --network none --entrypoint sha256sum "$NAUTHILUS_IMAGE" \
    "/usr/local/lib/nauthilus/plugins/$1.so" | awk '{print $1}'
}
REPUTATION_PLUGIN_SHA256=$(plugin_checksum reputation)
GEOIP_PLUGIN_SHA256=$(plugin_checksum geoip)
INTELLIGENCE_PLUGIN_SHA256=$(plugin_checksum dkim2-intelligence)
for CHECKSUM in "$REPUTATION_PLUGIN_SHA256" "$GEOIP_PLUGIN_SHA256" "$INTELLIGENCE_PLUGIN_SHA256"; do
  test "${#CHECKSUM}" -eq 64
  printf '%s' "$CHECKSUM" | grep -Eq '^[0-9a-f]{64}$'
done
EXPECTED_VERSION=$(git -C "$NAUTHILUS_REPO" describe --tags --abbrev=0)-$(git -C "$NAUTHILUS_REPO" rev-parse --short HEAD)
IMAGE_VERSION=$(docker run --rm --network none --read-only --entrypoint /usr/app/nauthilus "$NAUTHILUS_IMAGE" -version)
case "$IMAGE_VERSION" in
  *"$EXPECTED_VERSION"*) ;;
  *) echo "Nauthilus image does not match the current checkout" >&2; exit 1 ;;
esac
write_env
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" config -q
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" run --rm fixture-setup

docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" up -d --wait --wait-timeout 90 \
  redis outbox-redis dkim2-stub nauthilus-policy policy-observer rspamd
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

# clear_retry_scenario resets exact retry and fixture-greylist keys while retaining learned reputation.
clear_retry_scenario() {
  redis_command --scan --pattern 'dkim2:retry:v1:*' | while IFS= read -r KEY; do
    test -n "$KEY" || continue
    printf '%s' "$KEY" | grep -Eq '^dkim2:retry:v1:[0-9a-f]{64}$'
    redis_command DEL "$KEY" </dev/null >/dev/null
  done
  redis_command --scan --pattern 'policy_e2e_rg*' | while IFS= read -r KEY; do
    test -n "$KEY" || continue
    printf '%s' "$KEY" | grep -Eq '^policy_e2e_rg[bm][a-z0-9]{20}$'
    redis_command DEL "$KEY" </dev/null >/dev/null
  done
  REMAINING_GREYLIST=$(redis_command --scan --pattern 'policy_e2e_rg*' | awk 'NF { count++ } END { print count + 0 }')
  test "$REMAINING_GREYLIST" -eq 0
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

assert_policy_request_received_dsn() {
  if test "$RECEIVED_DSN_ATTRIBUTE" = true; then
    ATTRIBUTE_STATE=enabled
  else
    ATTRIBUTE_STATE=disabled
  fi
  python3 "$SCRIPT_DIR/policy-e2e/assert_policy_request.py" \
    --state "$RUNTIME_DIR/state/policy-observer-state.json" \
    --response "$SCRIPT_DIR/policy-e2e/dkim2-received-dsn-response.json" \
    --peer-ip "$1" --expected-action "$2" \
    --expect-received-dsn "$3" \
    --received-dsn-attribute "$ATTRIBUTE_STATE"
}

# Seed through the real observation Policy; network and ASN are derived by the native GeoIP provider.
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" exec -T policy-observer python3 /fixture/reputation_probe.py \
  seed --password-file /probe/seed-password
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" exec -T policy-observer python3 /fixture/reputation_probe.py \
  forbidden --password-file /probe/observation-password

# Prove actual durable observation admission before the existing verifier/retry scenarios.
. "$SCRIPT_DIR/policy-e2e/observation-recovery.sh"
prove_observation_recovery
test "$(stub_calls)" -eq 0
test "$(observer_value calls)" -eq 0

# The first retry flow captures the complete request, arms once, then consumes.
run_scan scan-tempfail.lua
test "$(stub_calls)" -eq 1
test "$(observer_value calls)" -eq 1
test "$(observer_value forwarded_calls)" -eq 1
test "$(observer_value last_request_id_matches)" = true
assert_policy_request 203.0.113.25 greylist

sleep 2
run_scan scan-accept.lua
test "$(stub_calls)" -eq 1
test "$(observer_value calls)" -eq 2
test "$(observer_value forwarded_calls)" -eq 2
test "$(observer_value last_request_id_matches)" = true

# A later duplicate returns to dkim2d after consume and replay rejection bypasses Policy.
set_dkim_mode replayed
run_scan scan-replayed-reject.lua
test "$(stub_calls)" -eq 2
test "$(observer_value calls)" -eq 2
set_dkim_mode default
clear_retry_scenario

# Malformed upstream verifier JSON is a temporary failure and never reaches Policy.
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
set_dkim_mode malformed
run_scan scan-dkim-malformed.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$POLICY_BEFORE"
set_dkim_mode default
clear_retry_scenario

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
  clear_retry_scenario
done
set_policy_mode forward

# A producer-bound two-hop chain is denied solely because its historical signer is unknown.
clear_retry_scenario
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

# An optional received delivery-status projection reaches Policy and the message.
clear_retry_scenario
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
set_dkim_mode received_dsn
run_scan scan-received-dsn-tempfail.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 1))"
assert_policy_request_received_dsn 203.0.113.25 greylist not_failure
sleep 2
run_scan scan-received-dsn.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 2))"
test "$(retry_cache_size)" -eq 0
set_dkim_mode default
clear_retry_scenario

# An oversized but syntactically valid cached JSON document is never reused.
clear_retry_scenario
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
clear_retry_scenario
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
clear_retry_scenario
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
clear_retry_scenario

# Redis unavailability fails before dkim2d or Policy and recovers without state reuse.
# Drain and pause independent learning so this retry-store fault cannot invalidate caller authentication.
wait_learning_drain
observation_control unavailable
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" stop redis >/dev/null
run_scan scan-redis-failure.lua
test "$(stub_calls)" -eq "$STUB_BEFORE"
test "$(observer_value calls)" -eq "$POLICY_BEFORE"
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" up -d --wait --wait-timeout 30 redis >/dev/null
# A throttle-store failure closes the authentication generation until explicit recovery.
restart_policy
observation_control forward
clear_retry_scenario

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
clear_retry_scenario

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

prove_hop_reputation
prove_provider_outages

# Policy-caused rejections have not been relabeled as independent high-weight rejection evidence.
wait_learning_drain
learned_snapshot | jq -e '.mail_risk_mass < 1' >/dev/null
OBSERVATIONS_BEFORE_REJECT=$(observer_value observation_calls)
# An unrelated Rspamd rejection survives a Policy permit and consumes its cache entry.
STUB_BEFORE=$(stub_calls)
POLICY_BEFORE=$(observer_value calls)
run_scan scan-unrelated-reject.lua
test "$(stub_calls)" -eq "$((STUB_BEFORE + 1))"
test "$(observer_value calls)" -eq "$((POLICY_BEFORE + 1))"
assert_policy_request 203.0.113.25 reject
test "$(retry_cache_size)" -eq 0

prove_later_reputation
prove_consumer_calibration

FINAL_STUB_CALLS=$(stub_calls)
FINAL_POLICY_CALLS=$(observer_value calls)
FINAL_FORWARDED_CALLS=$(observer_value forwarded_calls)

printf '%s\n' \
  "DKIM2/Rspamd/Nauthilus Policy E2E: PASS" \
  "stub_calls=$FINAL_STUB_CALLS policy_calls=$FINAL_POLICY_CALLS forwarded_policy_calls=$FINAL_FORWARDED_CALLS" \
  "received_dsn_attribute=$RECEIVED_DSN_ATTRIBUTE" \
  "request_projection=exact response_request_id=correlated smtp_peers=203.0.113.25,198.51.100.25"
