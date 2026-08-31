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

umask 077
mkdir -p "$RUNTIME_DIR/certs" "$RUNTIME_DIR/protected" "$RUNTIME_DIR/state"
openssl rand 32 >"$RUNTIME_DIR/protected/process-capability"
openssl rand 32 >"$RUNTIME_DIR/protected/rspamd-retry-hmac"
POLICY_PASSWORD=$(openssl rand -hex 24)
REDIS_ENCRYPTION_SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD_NONCE=$(openssl rand -hex 32)
printf '%s' "$POLICY_PASSWORD" >"$RUNTIME_DIR/protected/nauthilus-policy-password"

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj "/CN=DKIM2 Policy E2E CA" \
  -keyout "$RUNTIME_DIR/certs/policy-e2e-ca.key" \
  -out "$RUNTIME_DIR/certs/policy-e2e-ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=nauthilus-policy" \
  -addext "subjectAltName=DNS:nauthilus-policy" \
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
  redis dkim2-stub nauthilus-policy rspamd
docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" exec -T rspamd \
  getent hosts nauthilus-policy >/dev/null
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

policy_calls() {
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" exec -T nauthilus-policy \
    wget -q -O - https://nauthilus-policy:9443/metrics |
    awk '/^http_requests_total\{path="\/api\/v1\/policy\/decisions"\}/ {print int($2)}'
}

run_scan scan-tempfail.lua
test "$(stub_calls)" -eq 1
FIRST_POLICY_CALLS=$(policy_calls)
test "${FIRST_POLICY_CALLS:-0}" -ge 1

sleep 2
run_scan scan-accept.lua
test "$(stub_calls)" -eq 1
SECOND_POLICY_CALLS=$(policy_calls)
test "$SECOND_POLICY_CALLS" -gt "$FIRST_POLICY_CALLS"

run_scan scan-accept.lua
test "$(stub_calls)" -eq 2
THIRD_POLICY_CALLS=$(policy_calls)
test "$THIRD_POLICY_CALLS" -gt "$SECOND_POLICY_CALLS"

printf '%s\n' \
  "DKIM2/Rspamd/Nauthilus Policy E2E: PASS" \
  "stub_calls=2 policy_calls=$THIRD_POLICY_CALLS smtp_peer=203.0.113.25"
