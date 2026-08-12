#!/bin/sh
set -eu
umask 077

manifest=build/ci/toolchain.json
test -f "$manifest"
test "$#" -gt 0

binary_directory=${GOBIN:-$(go env GOPATH)/bin}
case "$binary_directory" in
  /*) ;;
  *)
    printf '%s\n' 'CI tool binary directory must be absolute' >&2
    exit 1
    ;;
esac
if test ! -e "$binary_directory"; then
  mkdir -m 0700 "$binary_directory"
fi
test -d "$binary_directory"
test ! -L "$binary_directory"

for requested_tool in "$@"; do
  case "$requested_tool" in
    actionlint)
      manifest_key=actionlint
      binary_name=actionlint
      ;;
    golangci-lint)
      manifest_key=golangci_lint
      binary_name=golangci-lint
      ;;
    govulncheck)
      manifest_key=govulncheck
      binary_name=govulncheck
      ;;
    *)
      printf 'unsupported CI tool: %s\n' "$requested_tool" >&2
      exit 1
      ;;
  esac

  module=$(jq -er --arg key "$manifest_key" '.go_tools[$key].module' "$manifest")
  version=$(jq -er --arg key "$manifest_key" '.go_tools[$key].version' "$manifest")
  GOFLAGS=-mod=mod GOBIN="$binary_directory" go install "$module@$version"
  binary="$binary_directory/$binary_name"
  test -x "$binary"

  case "$requested_tool" in
    actionlint)
      actual_version=$("$binary" -version 2>&1 | sed -n '1p')
      case "$actual_version" in
        "$version" | "${version#v}") ;;
        *) exit 1 ;;
      esac
      ;;
    golangci-lint)
      "$binary" version 2>&1 | grep -Fq "has version ${version#v} "
      ;;
    govulncheck)
      "$binary" -version 2>&1 | grep -Fq "Scanner: govulncheck@$version"
      ;;
  esac
done

if test -n "${GITHUB_PATH:-}"; then
  printf '%s\n' "$binary_directory" >>"$GITHUB_PATH"
fi
