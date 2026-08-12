#!/bin/sh
set -eu
umask 077

test "$#" -eq 1
repository=$(pwd -P)
case "$repository" in
  /*) ;;
  *)
    printf '%s\n' 'CI repository root must be absolute' >&2
    exit 1
    ;;
esac
artifacts="$repository/.artifacts"
if test ! -e "$artifacts"; then
  mkdir -m 0700 "$artifacts"
fi
test -d "$artifacts"
test ! -L "$artifacts"
directory="$artifacts/.ci-tmp"
retain_for_post_actions=${DKIM2_CI_RETAIN_FOR_POST_ACTIONS:-0}
case "$retain_for_post_actions" in
  0 | 1) ;;
  *)
    printf '%s\n' 'DKIM2_CI_RETAIN_FOR_POST_ACTIONS must be 0 or 1' >&2
    exit 1
    ;;
esac

case "$1" in
  prepare)
    test -n "${GITHUB_ENV:-}"
    test ! -e "$directory"
    test ! -L "$directory"
    mkdir -m 0700 "$directory"
    printf 'DKIM2_CI_TMPDIR=%s\nTMPDIR=%s\n' \
      "$directory" "$directory" >>"$GITHUB_ENV"
    ;;
  cleanup)
    if test -z "${DKIM2_CI_TMPDIR:-}"; then
      exit 0
    fi
    test "$DKIM2_CI_TMPDIR" = "$directory"
    test "${TMPDIR:-}" = "$directory"
    test -d "$directory"
    test ! -L "$directory"
    if test "$retain_for_post_actions" = 1; then
      exit 0
    fi
    rm -rf -- "$directory"
    ;;
  *)
    printf '%s\n' 'expected prepare or cleanup' >&2
    exit 1
    ;;
esac
