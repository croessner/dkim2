#!/bin/sh

set -eu

readonly expected_version="9.1.0"
readonly application_user="dkim2-integration-application"
readonly application_password="synthetic-application-password-91"
readonly auditor_user="dkim2-integration-auditor"
readonly auditor_password="synthetic-auditor-password-91"

TMPDIR=/tmp
export TMPDIR

if ! command -v valkey-server >/dev/null 2>&1; then
	echo "test-valkey: valkey-server 9.1.0 is required" >&2
	exit 1
fi

version_output="$(valkey-server --version 2>&1)" || {
	echo "test-valkey: failed to query valkey-server version" >&2
	exit 1
}
version_lines="$(printf '%s\n' "$version_output" | wc -l | tr -d '[:space:]')"
if [ "$version_lines" != "1" ] ||
	! printf '%s\n' "$version_output" |
		grep -Eq "^Valkey server v=$expected_version sha=[0-9a-f]{8,64}:[01] malloc=[A-Za-z0-9._+-]+ bits=(32|64) build=[0-9a-f]{8,64}$"; then
	echo "test-valkey: exact official Valkey server 9.1.0 binary is required" >&2
	exit 1
fi

workdir="$(mktemp -d /tmp/dkim2-valkey-integration.XXXXXX)"
chmod 700 "$workdir"
socket="$workdir/valkey.sock"
config="$workdir/valkey.conf"
log="$workdir/valkey.log"
server_pid=""
test_pid=""

stop_and_reap() {
	cleanup_target_pid=$1
	if kill -0 "$cleanup_target_pid" 2>/dev/null; then
		kill "$cleanup_target_pid" 2>/dev/null || true
		cleanup_attempt=0
		while kill -0 "$cleanup_target_pid" 2>/dev/null &&
			[ "$cleanup_attempt" -lt 100 ]; do
			cleanup_attempt=$((cleanup_attempt + 1))
			sleep 0.05
		done
		if kill -0 "$cleanup_target_pid" 2>/dev/null; then
			kill -9 "$cleanup_target_pid" 2>/dev/null || true
		fi
	fi
	wait "$cleanup_target_pid" 2>/dev/null || true
}

cleanup() {
	saved_status=$?
	trap - EXIT HUP INT TERM
	if [ -n "$test_pid" ]; then
		stop_and_reap "$test_pid"
	fi
	if [ -n "$server_pid" ]; then
		stop_and_reap "$server_pid"
	fi
	rm -rf "$workdir"
	exit "$saved_status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

umask 077
{
	printf '%s\n' \
		'bind 127.0.0.1' \
		'port 0' \
		"unixsocket \"$socket\"" \
		'unixsocketperm 600' \
		'protected-mode yes' \
		'daemonize no' \
		"dir \"$workdir\"" \
		'dbfilename synthetic-replay.rdb' \
		'save 3600 1' \
		'appendonly no' \
		'maxmemory 67108864' \
		'maxmemory-policy noeviction' \
		'min-replicas-to-write 0' \
		'min-replicas-max-lag 10' \
		'databases 1' \
		"logfile \"$log\"" \
		'user default reset off sanitize-payload resetkeys resetchannels resetdbs' \
		"user $application_user reset on sanitize-payload >$application_password -@all resetkeys resetchannels resetdbs +ping +set ~dkim2:replay:v1:* db=0" \
		"user $auditor_user reset on sanitize-payload >$auditor_password -@all resetkeys resetchannels resetdbs +role +config|get +info +acl|getuser +acl|dryrun db=0"
} >"$config"

valkey-server "$config" &
server_pid=$!

attempt=0
while [ ! -S "$socket" ]; do
	if ! kill -0 "$server_pid" 2>/dev/null; then
		echo "test-valkey: hermetic server exited before creating its socket" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 100 ]; then
		echo "test-valkey: timed out waiting for hermetic server socket" >&2
		exit 1
	fi
	sleep 0.05
done

DKIM2_VALKEY_SOCKET="$socket" \
	GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
	GOFLAGS="-mod=vendor" \
	go test -tags=valkeyintegration \
		./cmd/dkim2d/internal/replay/valkey \
		-run '^TestRealValkeyHarness$' \
		-count=1 \
		-timeout=45s &
test_pid=$!
test_status=0
wait "$test_pid" || test_status=$?
test_pid=""
exit "$test_status"
