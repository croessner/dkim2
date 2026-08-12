#!/bin/sh
set -eu
umask 077

temporary=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-ci-environment.XXXXXX")
test_root=$(CDPATH='' cd -- "$temporary" && pwd -P)
repository=$(pwd -P)
preparer="$repository/scripts/prepare-ci-environment.sh"

# cleanup removes only the invocation-owned test workspace.
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

github_environment="$test_root/github-environment"
: >"$github_environment"
(CDPATH='' cd -- "$test_root" &&
  GITHUB_ENV="$github_environment" "$preparer" prepare)
expected="$test_root/.artifacts/.ci-tmp"
test -d "$expected"
test ! -L "$expected"
test -d "$test_root/.artifacts"
test ! -L "$test_root/.artifacts"
grep -Fxq "DKIM2_CI_TMPDIR=$expected" "$github_environment"
grep -Fxq "TMPDIR=$expected" "$github_environment"

(CDPATH='' cd -- "$test_root" &&
  DKIM2_CI_TMPDIR="$expected" TMPDIR="$expected" \
    DKIM2_CI_RETAIN_FOR_POST_ACTIONS=1 "$preparer" cleanup)
test -d "$expected"
test ! -L "$expected"

(CDPATH='' cd -- "$test_root" &&
  DKIM2_CI_TMPDIR="$expected" TMPDIR="$expected" "$preparer" cleanup)
test ! -e "$expected"

if (CDPATH='' cd -- "$test_root" &&
  DKIM2_CI_RETAIN_FOR_POST_ACTIONS=invalid \
    "$preparer" cleanup >/dev/null 2>&1); then
  exit 1
fi

if (CDPATH='' cd -- "$test_root" &&
  GITHUB_ENV="$github_environment" \
    "$preparer" unsupported >/dev/null 2>&1); then
  exit 1
fi
