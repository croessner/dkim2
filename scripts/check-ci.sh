#!/bin/sh
set -eu

workflows=.github/workflows
expected='conformance.yml
guardrails.yml
release.yml'

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

command -v actionlint >/dev/null 2>&1 || fail 'actionlint is required'

actual=$(find "$workflows" -maxdepth 1 -type f -name '*.yml' -exec basename {} \; |
  LC_ALL=C sort)
test "$actual" = "$expected" || fail 'unexpected GitHub workflow set'

actionlint -no-color

if grep -RE 'uses: [^@[:space:]]+@(main|master|v[0-9]+([.]|$))' "$workflows"; then
  fail 'GitHub Actions must use immutable commit pins'
fi
if grep -RE 'github[.]ref_protected|prepare-ci-environment|DKIM2_CI_TMPDIR|[.]ci-tmp' "$workflows"; then
  fail 'obsolete branch-protection or CI temporary-directory coupling remains'
fi
if grep -RE 'DKIM2_TEST_TRUSTED_ROOT|/dkim2-test|mkfs[.]ext4|mount -o loop' "$workflows"; then
  fail 'special or privileged test filesystem coupling remains'
fi
test ! -e "$workflows/postfix-integration.yml" || fail 'Postfix E2E must remain opt-in'
test ! -e "$workflows/exim-integration.yml" || fail 'Exim E2E must remain opt-in'
for workflow in conformance.yml release.yml; do
  grep -A4 'actions/setup-go@' "$workflows/$workflow" | grep -q 'cache: false' ||
    fail "$workflow must not use setup-go's implicit root-module cache"
done
if grep -Eq '^check-openapi:.*check-workspace' Makefile; then
  fail 'normal generated-source checks must not depend on private module-proof reconstruction'
fi
grep -A5 '^check-vendor:' Makefile | grep -q -- '-mod=vendor' ||
  fail 'vendor validation must use Go vendor resolution directly'
if grep -RE '(packages|id-token|attestations):[[:space:]]*write' \
  "$workflows" --exclude=release.yml; then
  fail 'only the release workflow may publish or attest artifacts'
fi

grep -Fq 'release:' "$workflows/release.yml" || fail 'release event is missing'
grep -Fq 'types: [published]' "$workflows/release.yml" || fail 'published release gate is missing'
grep -Fq 'packages: write' "$workflows/release.yml" || fail 'release package authority is missing'
grep -Fq 'attestations: write' "$workflows/release.yml" || fail 'release attestation authority is missing'
grep -Fq 'id-token: write' "$workflows/release.yml" || fail 'release identity authority is missing'

if grep -Fq 'latest' "$workflows/release.yml"; then
  fail 'stable publication must not create an implicit latest tag'
fi
