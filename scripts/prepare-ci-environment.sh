#!/bin/sh
set -eu
umask 077

test "$#" -eq 1
case "$HOME" in
  /*) ;;
  *)
    printf '%s\n' 'GitHub runner HOME must be absolute' >&2
    exit 1
    ;;
esac
test -d "$HOME"
test ! -L "$HOME"
resolved_home=$(CDPATH='' cd -- "$HOME" && pwd -P)
test "$resolved_home" = "$HOME"
directory="$HOME/.dkim2-ci-tmp"

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
    rm -rf -- "$directory"
    ;;
  *)
    printf '%s\n' 'expected prepare or cleanup' >&2
    exit 1
    ;;
esac
