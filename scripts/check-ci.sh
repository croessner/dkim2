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
grep -Fq 'OPENAPI_GO_TOOLCHAIN := go1.26.0' Makefile ||
  fail 'OpenAPI generation must use the reproducible Go 1.26 toolchain'
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
grep -Fq 'https://github.com/croessner/dkim2.git' "$mirror_workflow" ||
  fail 'mirror workflow must fetch only the canonical repository'
grep -Eq '^permissions:[[:space:]]*\{\}$' "$mirror_workflow" ||
  fail 'mirror workflow must disable built-in GitHub token permissions'
permission_declarations=$(grep -Ec '^[[:space:]]*permissions:' "$mirror_workflow")
test "$permission_declarations" -eq 1 ||
  fail 'mirror workflow must declare built-in token permissions exactly once'

mirror_action='actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0'
mirror_actions=$(sed -n 's/^[[:space:]]*uses:[[:space:]]*//p' "$mirror_workflow")
test "$mirror_actions" = "$mirror_action" ||
  fail 'mirror workflow must use only the pinned GitHub App token action'
if grep -RE 'DKIM2_MIRROR_APP_(CLIENT_ID|PRIVATE_KEY)|actions/create-github-app-token@' \
  "$workflows" --exclude=mirror.yml; then
  fail 'mirror credentials and token action must not appear in other workflows'
fi

canonical_clone='git clone --bare "https://github.com/croessner/dkim2.git" "$RUNNER_TEMP/repository.git"'
clone_lines=$(grep -nF "$canonical_clone" "$mirror_workflow")
test "$(printf '%s\n' "$clone_lines" | wc -l | tr -d ' ')" -eq 1 ||
  fail 'mirror workflow must clone the canonical repository exactly once'
clone_line=${clone_lines%%:*}
token_action_line=$(grep -nF "$mirror_action" "$mirror_workflow")
token_action_line=${token_action_line%%:*}
test "$clone_line" -lt "$token_action_line" ||
  fail 'mirror workflow must clone the public canonical repository before token creation'

if grep -Eq '(secrets|vars|steps)[[:space:]]*\[' "$mirror_workflow"; then
  fail 'mirror workflow must not bypass credential allowlists with bracket syntax'
fi
mirror_secrets=$(grep -Eo 'secrets[.][A-Za-z0-9_]+' "$mirror_workflow" | LC_ALL=C sort)
test "$mirror_secrets" = 'secrets.DKIM2_MIRROR_APP_PRIVATE_KEY' ||
  fail 'mirror workflow must use the target-scoped App private key secret exactly once'
mirror_secret_contexts=$(grep -Fo 'secrets' "$mirror_workflow" | wc -l | tr -d ' ')
test "$mirror_secret_contexts" -eq 1 ||
  fail 'mirror workflow must not access any other secret context'
mirror_variables=$(grep -Eo 'vars[.][A-Za-z0-9_]+' "$mirror_workflow" | LC_ALL=C sort)
test "$mirror_variables" = 'vars.DKIM2_MIRROR_APP_CLIENT_ID' ||
  fail 'mirror workflow must use the target-scoped App client ID variable exactly once'
mirror_variable_contexts=$(grep -Fo 'vars' "$mirror_workflow" | wc -l | tr -d ' ')
test "$mirror_variable_contexts" -eq 1 ||
  fail 'mirror workflow must not access any other variable context'

mirror_token_step_ids=$(grep -Fc 'id: mirror-token' "$mirror_workflow")
test "$mirror_token_step_ids" -eq 1 ||
  fail 'mirror workflow must own exactly one explicit App token step'
grep -Fq 'client-id: ${{ vars.DKIM2_MIRROR_APP_CLIENT_ID }}' "$mirror_workflow" ||
  fail 'mirror workflow must load the target App client ID'
grep -Fq 'private-key: ${{ secrets.DKIM2_MIRROR_APP_PRIVATE_KEY }}' "$mirror_workflow" ||
  fail 'mirror workflow must load the target App private key'
grep -Fq 'owner: go-dkim2' "$mirror_workflow" ||
  fail 'mirror App token must be scoped to the mirror organization'
grep -Fq 'repositories: dkim2' "$mirror_workflow" ||
  fail 'mirror App token must be scoped to the mirror repository'
mirror_app_permissions=$(sed -n 's/^[[:space:]]*\(permission-[A-Za-z0-9-]*\):[[:space:]]*\(.*\)$/\1: \2/p' "$mirror_workflow" | LC_ALL=C sort)
expected_mirror_app_permissions='permission-contents: write
permission-workflows: write'
test "$mirror_app_permissions" = "$expected_mirror_app_permissions" ||
  fail 'mirror App token may request only contents and workflows write authority'
grep -Fq 'skip-token-revoke: false' "$mirror_workflow" ||
  fail 'mirror App token must be revoked after the job'
mirror_tokens=$(sed -n 's/^[[:space:]]*GH_TOKEN:[[:space:]]*//p' "$mirror_workflow")
test "$mirror_tokens" = '${{ steps.mirror-token.outputs.token }}' ||
  fail 'mirror pushes must use the short-lived App installation token'
mirror_token_uses=$(grep -Fc '${{ steps.mirror-token.outputs.token }}' "$mirror_workflow")
test "$mirror_token_uses" -eq 1 ||
  fail 'mirror workflow must expose the App installation token exactly once'
mirror_step_contexts=$(grep -Fo 'steps' "$mirror_workflow" | wc -l | tr -d ' ')
test "$mirror_step_contexts" -eq 2 ||
  fail 'mirror workflow must not access any other step context'
mirror_heads_push='git -C "$RUNNER_TEMP/repository.git" push --prune mirror '\''+refs/heads/*:refs/heads/*'\'''
grep -Fq "$mirror_heads_push" "$mirror_workflow" ||
  fail 'mirror workflow must synchronize force-updated canonical branches exactly'
mirror_tags_push='git -C "$RUNNER_TEMP/repository.git" push --prune mirror '\''refs/tags/*:refs/tags/*'\'''
grep -Fq "$mirror_tags_push" "$mirror_workflow" ||
  fail 'mirror workflow must synchronize canonical tags without rewriting them'
if grep -Eq 'github[.]token|GITHUB_TOKEN|packages:[[:space:]]*write|id-token:[[:space:]]*write|attestations:[[:space:]]*write' "$mirror_workflow"; then
  fail 'mirror workflow contains authority outside the target-scoped App token'
fi

grep -Fq 'tags: ["v*"]' "$workflows/release.yml" || fail 'release tag-push gate is missing'
grep -Fq 'scripts/generate-release-notes.sh "$RELEASE_TAG" "$previous_tag"' "$workflows/release.yml" ||
  fail 'release notes generator is missing'
grep -Fq 'gh release create "$RELEASE_TAG"' "$workflows/release.yml" ||
  fail 'release creation is missing'
grep -Fq -- '--generate-notes' "$workflows/release.yml" ||
  fail 'GitHub generated release notes are missing'
grep -Fq 'packages: write' "$workflows/release.yml" || fail 'release package authority is missing'
grep -Fq 'sbom: true' "$workflows/release.yml" || fail 'release BuildKit SBOM is missing'
grep -Fq 'provenance: mode=max' "$workflows/release.yml" || fail 'release BuildKit provenance is missing'
if grep -Eq '(attestations|id-token):[[:space:]]*write' "$workflows/release.yml"; then
  fail 'release policy must use one registry-bound BuildKit attestation authority'
fi
if grep -Fq 'actions/attest-build-provenance' "$workflows/release.yml"; then
  fail 'release policy must use registry-bound BuildKit provenance'
fi

if grep -Eq '(^|[[:space:]])[^#[:space:]]+:latest([[:space:]]|$$)' "$workflows/release.yml"; then
  fail 'stable image publication must not create an implicit latest tag'
fi
