#!/bin/sh
set -eu

skip_sanitizers=${DKIM2_EXIM_SKIP_SANITIZERS:-0}
case "$skip_sanitizers" in
  0 | 1) ;;
  *)
    printf '%s\n' 'DKIM2_EXIM_SKIP_SANITIZERS must be 0 or 1' >&2
    exit 1
    ;;
esac

root=$(CDPATH='' cd -- "$(dirname "$0")/../../../.." && pwd)
exim="$root/cmd/dkim2-exim/exim"
work=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-exim-c-harness.XXXXXX")
trap 'rm -rf "$work"' 0 1 2 15

cc_bin=${CC:-cc}
common_flags="-std=c11 -D_GNU_SOURCE -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L"
warning_flags="-Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow -Wstrict-prototypes"
include_common="-I$exim/fixtures/include -I$exim/generated"

# digest prints the portable lowercase SHA-256 spelling of one fixture.
digest()
{
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

transport_filter_patch_sha=$(digest \
  "$root/cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch")

upstream_header="$exim/fixtures/upstream-4.99.5/local_scan.h"
test "$(digest "$upstream_header")" = \
  ea0cde6e279bd5abeecbf67f7e54d8d0964fefedacae526818d6c035a7bfbb29

mkdir "$work/upstream"
cp "$upstream_header" "$work/upstream/local_scan.h"
(cd "$work/upstream" &&
  git apply --include=local_scan.h \
    "$exim/fixtures/upstream-4.99.5/local_scan-expand-string.patch")
test "$(digest "$work/upstream/local_scan.h")" = \
  46153aa898cd90252fcc96041f4d51a5b104d39bb6507f12d1917828c6d4b277

mkdir "$work/debian"
cp "$upstream_header" "$work/debian/local_scan.h"
(cd "$work/debian" &&
  git apply "$exim/fixtures/debian-4.98.2-1+deb13u3/local_scan.patch")
test "$(digest "$work/debian/local_scan.h")" = \
  0d33e5e807eff58ff1b535431591c3290887e250f05252c1177864052176a0a6

# run_fixture compiles the ABI probe and actual local_scan harness independently.
run_fixture()
{
  name=$1
  version=$2
  source_sha=$3
  header_sha=$4
  header_dir=$5
  expected=$6
  api_family=${7:-legacy}
  build_header=${8:-$exim/generated/build-id-v1.h}
  local_dir="$work/Local-$name"
  mkdir "$local_dir"
  cp "$exim/dkim2_local_scan.c" "$local_dir/dkim2_local_scan.c"
  cp "$build_header" "$local_dir/build-id-v1.h"

  api_flags=
  if [ "$api_family" = expand_string_2 ]; then
    api_flags=-DDKIM2_EXIM_EXPAND_STRING_2=1
  fi

  "$cc_bin" $common_flags $warning_flags $include_common $api_flags \
    "-I$header_dir" \
    "-DDKIM2_EXIM_VERSION=\"$version\"" \
    "-DDKIM2_EXIM_SOURCE_SHA256=\"$source_sha\"" \
    "-DDKIM2_EXIM_HEADER_SHA256=\"$header_sha\"" \
    "-DDKIM2_EXIM_TRANSPORT_FILTER_PATCH_SHA256=\"$transport_filter_patch_sha\"" \
    -DDKIM2_EXIM_I18N=1 \
    "$exim/abi_probe.c" -o "$work/probe-$name"
  "$work/probe-$name" > "$work/probe-$name.txt"
  cmp "$expected" "$work/probe-$name.txt"

  "$cc_bin" $common_flags $warning_flags "-I$local_dir" $include_common $api_flags \
    "-I$header_dir" \
    "$local_dir/dkim2_local_scan.c" "$exim/tests/local_scan_harness.c" \
    -pthread -o "$work/harness-$name"
  "$work/harness-$name"
}

run_fixture \
  upstream-4.99.5 \
  4.99.5 \
  c2d2f80adc7c71d424fd82a46655eaa2d7d9b4ca2e77883eba9076947b7ee627 \
  46153aa898cd90252fcc96041f4d51a5b104d39bb6507f12d1917828c6d4b277 \
  "$work/upstream" \
  "$exim/fixtures/upstream-4.99.5/probe-contract-v1.txt" \
  expand_string_2
run_fixture \
  debian-4.98.2 \
  4.98.2-1+deb13u3 \
  88b8e8a67c1db6cc0b1d148161aa36e662f4ca2fef25d5b6f3694d490e42dcae \
  0d33e5e807eff58ff1b535431591c3290887e250f05252c1177864052176a0a6 \
  "$work/debian" \
  "$exim/fixtures/debian-4.98.2-1+deb13u3/probe-contract-v1.txt" \
  legacy \
  "$exim/fixtures/debian-4.98.2-1+deb13u3/build-id-v1.h"
run_fixture \
  debian-4.98.2-u4 \
  4.98.2-1+deb13u4 \
  88b8e8a67c1db6cc0b1d148161aa36e662f4ca2fef25d5b6f3694d490e42dcae \
  0d33e5e807eff58ff1b535431591c3290887e250f05252c1177864052176a0a6 \
  "$work/debian" \
  "$exim/fixtures/debian-4.98.2-1+deb13u4/probe-contract-v1.txt" \
  legacy \
  "$exim/fixtures/debian-4.98.2-1+deb13u4/build-id-v1.h"
run_fixture \
  ubuntu-4.99.1-u13 \
  4.99.1-1ubuntu1.3 \
  eae967bd49a5f879933b8c6ec88c30475a1c6646232135f37f05b55dbc4e3447 \
  75c8ebbdf9cedf4743654217f403492d2a9e3909dc395ff90f537073b7097e2e \
  "$exim/fixtures/ubuntu-4.99.1-1ubuntu1.3/include" \
  "$exim/fixtures/ubuntu-4.99.1-1ubuntu1.3/probe-contract-v1.txt" \
  expand_string_2 \
  "$exim/fixtures/ubuntu-4.99.1-1ubuntu1.3/build-id-v1.h"
run_fixture \
  ubuntu-4.99.1-u14 \
  4.99.1-1ubuntu1.4 \
  eae967bd49a5f879933b8c6ec88c30475a1c6646232135f37f05b55dbc4e3447 \
  75c8ebbdf9cedf4743654217f403492d2a9e3909dc395ff90f537073b7097e2e \
  "$exim/fixtures/ubuntu-4.99.1-1ubuntu1.4/include" \
  "$exim/fixtures/ubuntu-4.99.1-1ubuntu1.4/probe-contract-v1.txt" \
  expand_string_2 \
  "$exim/fixtures/ubuntu-4.99.1-1ubuntu1.4/build-id-v1.h"

"$cc_bin" $common_flags $warning_flags -DLOCAL_SCAN $include_common \
  -DDKIM2_EXIM_EXPAND_STRING_2=1 \
  "-I$work/upstream" \
  "$work/Local-upstream-4.99.5/dkim2_local_scan.c" "$exim/tests/local_scan_harness.c" \
  -pthread -o "$work/harness-local-scan-predefined"
"$work/harness-local-scan-predefined"

if test "$skip_sanitizers" = 1; then
  printf '%s\n' \
    'local_scan harness: sanitizer sub-run skipped under CodeQL instrumentation'
elif "$cc_bin" $common_flags $warning_flags $include_common \
  -DDKIM2_EXIM_EXPAND_STRING_2=1 \
  "-I$work/upstream" \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  "$work/Local-upstream-4.99.5/dkim2_local_scan.c" "$exim/tests/local_scan_harness.c" \
  -pthread -o "$work/harness-sanitized" 2>/dev/null; then
  ASAN_OPTIONS=detect_leaks=0 "$work/harness-sanitized"
else
  printf '%s\n' "local_scan harness: address/undefined sanitizers unavailable"
fi

if grep -q 'smtp_fflush[[:space:]]*(' "$exim/dkim2_local_scan.c"; then
  printf '%s\n' "local_scan harness: forbidden smtp_fflush use" >&2
  exit 1
fi
