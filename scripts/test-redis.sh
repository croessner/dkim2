#!/bin/sh
export GOEXPERIMENT=runtimesecret
export GOTOOLCHAIN=go1.27.3

set -eu

manifest=build/ci/toolchain.json
expected_version=$(jq -er '
  if .schema == "dkim2-ci-toolchain-v1" and
    (.fixtures.valkey.version | test("^[0-9]+[.][0-9]+[.][0-9]+$"))
  then .fixtures.valkey.version else halt_error(1) end
' "$manifest")
readonly manifest expected_version

TMPDIR=/tmp
export TMPDIR

build_test_binary=false
case $# in
0)
	if ! command -v valkey-server >/dev/null 2>&1; then
		printf 'test-redis: valkey-server %s is required\n' \
			"$expected_version" >&2
		exit 1
	fi
	server_binary="$(realpath "$(command -v valkey-server)")"
	test_binary=""
	build_test_binary=true
	;;
2)
	server_binary=$1
	test_binary=$2
	;;
*)
	echo "test-redis: expected no arguments or exact server and test binaries" >&2
	exit 1
	;;
esac

case "$server_binary" in
/*) ;;
*)
	echo "test-redis: exact server path must be absolute" >&2
	exit 1
	;;
esac
if [ ! -f "$server_binary" ] || [ ! -x "$server_binary" ] || [ -L "$server_binary" ]; then
	echo "test-redis: exact regular server binary is required" >&2
	exit 1
fi

version_output="$("$server_binary" --version 2>&1)" || {
	echo "test-redis: failed to query valkey-server version" >&2
	exit 1
}
version_lines="$(printf '%s\n' "$version_output" | wc -l | tr -d '[:space:]')"
if [ "$version_lines" != "1" ] ||
	! printf '%s\n' "$version_output" |
		grep -Eq "^Valkey server v=$expected_version sha=[0-9a-f]{8,64}:[01] malloc=[A-Za-z0-9._+-]+ bits=(32|64) build=[0-9a-f]{8,64}$"; then
	printf 'test-redis: exact official Valkey server %s binary is required\n' \
		"$expected_version" >&2
	exit 1
fi

workdir="$(mktemp -d /tmp/dkim2-redis-integration.XXXXXX)"
chmod 700 "$workdir"
test_pid=""

# shellcheck disable=SC2329
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

# shellcheck disable=SC2329
cleanup() {
	saved_status=$?
	trap - EXIT HUP INT TERM
	if [ -n "$test_pid" ]; then
		stop_and_reap "$test_pid"
	fi
	# Reap any server the harness could not stop itself; every server runs
	# from a configuration file inside the private work directory.
	pkill -TERM -f "$workdir/" 2>/dev/null || true
	cleanup_attempt=0
	while pgrep -f "$workdir/" >/dev/null 2>&1 && [ "$cleanup_attempt" -lt 100 ]; do
		cleanup_attempt=$((cleanup_attempt + 1))
		sleep 0.05
	done
	pkill -KILL -f "$workdir/" 2>/dev/null || true
	rm -rf "$workdir"
	exit "$saved_status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$build_test_binary" = true ]; then
	test_binary="$workdir/redis-integration.test"
	GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		GOFLAGS="-mod=vendor" \
		go test -tags=redisintegration -c \
			-o "$test_binary" \
			./cmd/dkim2d/internal/replay/redisstore
fi
case "$test_binary" in
/*) ;;
*)
	echo "test-redis: exact test path must be absolute" >&2
	exit 1
	;;
esac
if [ ! -f "$test_binary" ] || [ ! -x "$test_binary" ] || [ -L "$test_binary" ]; then
	echo "test-redis: exact regular test binary is required" >&2
	exit 1
fi

umask 077
(
	cd cmd/dkim2d/internal/replay/redisstore
	DKIM2_REDIS_SERVER="$server_binary" \
		DKIM2_REDIS_WORKDIR="$workdir" \
		exec "$test_binary" \
			-test.run '^TestRealRedisHarness$' \
			-test.count=1 \
			-test.v \
			-test.timeout=180s
) &
test_pid=$!
test_status=0
wait "$test_pid" || test_status=$?
test_pid=""
exit "$test_status"
