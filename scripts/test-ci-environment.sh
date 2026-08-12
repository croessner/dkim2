#!/bin/sh
set -eu
umask 077

temporary=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-ci-environment.XXXXXX")
test_root=$(CDPATH='' cd -- "$temporary" && pwd -P)

# cleanup removes only the invocation-owned test workspace.
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

github_environment="$test_root/github-environment"
: >"$github_environment"
HOME="$test_root" GITHUB_ENV="$github_environment" \
  scripts/prepare-ci-environment.sh prepare
expected="$test_root/.dkim2-ci-tmp"
test -d "$expected"
test ! -L "$expected"
grep -Fxq "DKIM2_CI_TMPDIR=$expected" "$github_environment"
grep -Fxq "TMPDIR=$expected" "$github_environment"

HOME="$test_root" DKIM2_CI_TMPDIR="$expected" TMPDIR="$expected" \
  scripts/prepare-ci-environment.sh cleanup
test ! -e "$expected"

if HOME="$test_root" GITHUB_ENV="$github_environment" \
  scripts/prepare-ci-environment.sh unsupported >/dev/null 2>&1; then
  exit 1
fi
