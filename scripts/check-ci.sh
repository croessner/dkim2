#!/bin/sh
set -eu

workflows=.github/workflows
expected='conformance.yml
guardrails.yml
mirror.yml
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
if grep -Eq '(^|[[:space:]])rg([[:space:]]|$$)' Makefile; then
  fail 'normal Make gates must not require undeclared ripgrep tooling'
fi
if grep -RE '(packages|id-token|attestations):[[:space:]]*write' \
  "$workflows" --exclude=release.yml; then
  fail 'only the release workflow may publish or attest artifacts'
fi

mirror_workflow="$workflows/mirror.yml"
grep -Fq "github.repository == 'go-dkim2/dkim2'" "$mirror_workflow" ||
  fail 'mirror workflow must run only in the organization mirror'
grep -Fq 'repository: croessner/dkim2' "$mirror_workflow" ||
  fail 'mirror workflow must fetch only the canonical repository'
grep -Fq 'contents: write' "$mirror_workflow" ||
  fail 'mirror workflow requires target-scoped contents write authority'
if grep -Eq 'secrets[.]|packages:[[:space:]]*write|id-token:[[:space:]]*write' "$mirror_workflow"; then
  fail 'mirror workflow must use only the target-scoped GitHub token'
fi

grep -Fq 'release:' "$workflows/release.yml" || fail 'release event is missing'
grep -Fq 'types: [published]' "$workflows/release.yml" || fail 'published release gate is missing'
grep -Fq 'packages: write' "$workflows/release.yml" || fail 'release package authority is missing'
grep -Fq 'sbom: true' "$workflows/release.yml" || fail 'release BuildKit SBOM is missing'
grep -Fq 'provenance: mode=max' "$workflows/release.yml" || fail 'release BuildKit provenance is missing'
if grep -Eq '(attestations|id-token):[[:space:]]*write' "$workflows/release.yml"; then
  fail 'release policy must use one registry-bound BuildKit attestation authority'
fi
if grep -Fq 'actions/attest-build-provenance' "$workflows/release.yml"; then
  fail 'release policy must use registry-bound BuildKit provenance'
fi

if grep -Fq 'latest' "$workflows/release.yml"; then
  fail 'stable publication must not create an implicit latest tag'
fi
