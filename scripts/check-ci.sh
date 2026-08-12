#!/bin/sh
set -eu

manifest=build/ci/toolchain.json
workflows=.github/workflows
ordinary_workflows="
$workflows/codeql.yml
$workflows/conformance.yml
$workflows/container-release.yml
$workflows/guardrails.yml
$workflows/unit-tests.yml
"
all_workflows="$ordinary_workflows
$workflows/container-publish.yml
"

# fail reports one stable CI contract violation.
fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail 'jq is required for make check-ci'
command -v actionlint >/dev/null 2>&1 || \
  fail 'actionlint is required for make check-ci'

jq -e '
  (keys == [
    "actions", "evidence_tool_manifests", "fixtures", "go", "go_tools",
    "runner", "schema"
  ]) and
  .schema == "dkim2-ci-toolchain-v1" and
  (.runner == {image:.runner.image}) and
  (.runner.image | test("^ubuntu-[0-9]+[.][0-9]+$")) and
  (.go == {version:.go.version}) and
  (.go.version | test("^1[.]26[.][0-9]+$")) and
  (.actions | keys == ["attest","checkout","codeql","setup_go","upload_artifact"]) and
  (.actions.checkout.repository == "actions/checkout") and
  (.actions.setup_go.repository == "actions/setup-go") and
  (.actions.upload_artifact.repository == "actions/upload-artifact") and
  (.actions.codeql.repository == "github/codeql-action") and
  (.actions.attest.repository == "actions/attest") and
  all(.actions[];
    (keys == ["commit","repository","version"]) and
    (.version | test("^v[0-9]+[.][0-9]+[.][0-9]+$")) and
    (.commit | test("^[0-9a-f]{40}$"))) and
  (.go_tools | keys == ["actionlint","golangci_lint","govulncheck"]) and
  (.go_tools.actionlint.module ==
    "github.com/rhysd/actionlint/cmd/actionlint") and
  (.go_tools.golangci_lint.module ==
    "github.com/golangci/golangci-lint/v2/cmd/golangci-lint") and
  (.go_tools.govulncheck.module ==
    "golang.org/x/vuln/cmd/govulncheck") and
  all(.go_tools[];
    (keys == ["module","version"]) and
    (.version | test("^v[0-9]+[.][0-9]+[.][0-9]+$"))) and
  (.fixtures | keys == ["valkey"]) and
  (.fixtures.valkey.repository == "valkey-io/valkey") and
  (.fixtures.valkey.version | test("^[0-9]+[.][0-9]+[.][0-9]+$")) and
  (.fixtures.valkey.commit | test("^[0-9a-f]{40}$")) and
  .evidence_tool_manifests == [
    "build/container/image-tools.json",
    "build/container/publication-tools.json"
  ]
' "$manifest" >/dev/null || fail 'invalid central CI toolchain manifest'

actionlint_version=$(jq -er '.go_tools.actionlint.version' "$manifest")
actual_actionlint_version=$(actionlint -version 2>&1 | sed -n '1p')
case "$actual_actionlint_version" in
  "$actionlint_version" | "${actionlint_version#v}") ;;
  *) fail 'actionlint does not match the CI manifest' ;;
esac
actionlint -no-color

for workflow in $ordinary_workflows; do
  grep -Fq 'workflow_dispatch:' "$workflow"
  grep -Fq '      - main' "$workflow"
  grep -Fq '      - features' "$workflow"
  grep -Fq '      - release/**' "$workflow"
  grep -Fq '  contents: read' "$workflow"
  grep -Fq 'concurrency:' "$workflow"
  grep -Fq '  cancel-in-progress: true' "$workflow"
  grep -Fq 'persist-credentials: false' "$workflow"
  if grep -Eq \
    '(packages|id-token|attestations|security-events):[[:space:]]*write' \
    "$workflow"; then
    fail "ordinary workflow has elevated authority: $workflow"
  fi
done

if grep -RE 'uses: [^@[:space:]]+@(main|master|v[0-9]+([.]|$))' \
  "$workflows"; then
  fail 'workflow actions must use full commit pins'
fi
if grep -RE '^[[:space:]]*uses:' "$workflows" |
  grep -Ev 'uses: [^@[:space:]]+@[0-9a-f]{40}[[:space:]]+# v[0-9]+[.][0-9]+[.][0-9]+$'; then
  fail 'workflow action pin must have a full SHA and manifest version comment'
fi

used_repositories=$(sed -En \
  's|.*uses: ([^/@[:space:]]+/[^/@[:space:]]+)(/[^@[:space:]]*)?@.*|\1|p' \
  "$workflows"/* | LC_ALL=C sort -u)
manifest_repositories=$(jq -r '.actions[].repository' "$manifest" |
  LC_ALL=C sort -u)
test "$used_repositories" = "$manifest_repositories" || \
  fail 'workflow action repository is missing from the central manifest'

# validate_action_pin proves every use of one action mirrors its manifest pin.
validate_action_pin() {
  action_key=$1
  repository=$(jq -er --arg key "$action_key" \
    '.actions[$key].repository' "$manifest")
  commit=$(jq -er --arg key "$action_key" \
    '.actions[$key].commit' "$manifest")
  version=$(jq -er --arg key "$action_key" \
    '.actions[$key].version' "$manifest")
  lines=$(grep -Rh "uses: $repository" "$workflows")
  test -n "$lines" || fail "manifest action is unused: $repository"
  pins=$(printf '%s\n' "$lines" |
    sed -E "s|.*uses: ${repository}(/[^@[:space:]]*)?@([0-9a-f]+).*|\\2|" |
    LC_ALL=C sort -u)
  test "$pins" = "$commit" || fail "action pin drift: $repository"
  if printf '%s\n' "$lines" | grep -Fv "# $version" >/dev/null; then
    fail "action version comment drift: $repository"
  fi
}
for action_key in $(jq -r '.actions | keys[]' "$manifest"); do
  validate_action_pin "$action_key"
done

runner_image=$(jq -er '.runner.image' "$manifest")
actual_runner_images=$(sed -n 's/^[[:space:]]*runs-on: //p' "$workflows"/* |
  LC_ALL=C sort -u)
test "$actual_runner_images" = "$runner_image" || \
  fail 'workflow runner image drifted from the central manifest'

go_version=$(jq -er '.go.version' "$manifest")
actual_go_versions=$(sed -n 's/.*go-version: "\([^"]*\)".*/\1/p' \
  "$workflows"/* | LC_ALL=C sort -u)
test "$actual_go_versions" = "$go_version" || \
  fail 'workflow Go patch level drifted from the central manifest'
test "$(grep -Rh 'go-version:' "$workflows" | wc -l | tr -d ' ')" -ge 6

if grep -RE \
  '(ACTIONLINT_VERSION|GOLANGCI_LINT_VERSION|GOVULNCHECK_VERSION|go install .+@(latest|v[0-9]))' \
  "$workflows"; then
  fail 'workflow duplicated a CI tool version outside the central manifest'
fi
grep -Fq \
  'run: scripts/install-ci-tools.sh actionlint golangci-lint govulncheck' \
  "$workflows/guardrails.yml"
grep -Fq \
  'run: scripts/install-ci-tools.sh actionlint golangci-lint govulncheck' \
  "$workflows/container-publish.yml"
grep -Fq 'run: scripts/install-ci-tools.sh govulncheck' \
  "$workflows/conformance.yml"

for workflow in $all_workflows; do
  test "$(grep -Fc 'id: ci_environment' "$workflow")" -eq 1
  test "$(grep -Fc 'run: scripts/prepare-ci-environment.sh prepare' "$workflow")" -eq 1
  test "$(grep -Fc \
    "if: \${{ always() && steps.ci_environment.outcome == 'success' }}" \
    "$workflow")" -eq 1
  test "$(grep -Fc 'run: scripts/prepare-ci-environment.sh cleanup' "$workflow")" -eq 1
done

grep -Fq 'run: make release-guardrails' "$workflows/container-publish.yml"
grep -Fq 'run: make check-container-release' "$workflows/container-release.yml"
grep -Fq 'run: make guardrails' "$workflows/guardrails.yml"
grep -Fq 'run: make test' "$workflows/unit-tests.yml"

grep -Fq '          - language: actions' "$workflows/codeql.yml"
grep -Fq '          - language: go' "$workflows/codeql.yml"
grep -Fq '          - language: c-cpp' "$workflows/codeql.yml"
grep -Fq '          upload: never' "$workflows/codeql.yml"
grep -Fq '          upload-database: false' "$workflows/codeql.yml"
grep -Fq '          output: .artifacts/codeql/${{ matrix.language }}' \
  "$workflows/codeql.yml"
grep -Fq '          DKIM2_EXIM_SKIP_SANITIZERS: "1"' "$workflows/codeql.yml"
test "$(grep -RhF 'DKIM2_EXIM_SKIP_SANITIZERS: "1"' "$workflows" |
  wc -l | tr -d ' ')" -eq 1
grep -Fq 'skip_sanitizers=${DKIM2_EXIM_SKIP_SANITIZERS:-0}' \
  cmd/dkim2-exim/exim/tests/run-local-scan-harness.sh

upload_count=$(grep -RhF 'uses: actions/upload-artifact@' "$workflows" |
  wc -l | tr -d ' ')
hidden_upload_count=$(grep -RhF 'include-hidden-files: true' "$workflows" |
  wc -l | tr -d ' ')
test "$upload_count" -eq "$hidden_upload_count" || \
  fail 'hidden .artifacts uploads must opt in explicitly'
if grep -REq '^[[:space:]]*path:[[:space:]]+[.]artifacts/$' "$workflows"; then
  fail 'artifact upload must not expose the whole working artifact root'
fi

valkey_repository=$(jq -er '.fixtures.valkey.repository' "$manifest")
valkey_version=$(jq -er '.fixtures.valkey.version' "$manifest")
valkey_commit=$(jq -er '.fixtures.valkey.commit' "$manifest")
for workflow in \
  "$workflows/conformance.yml" \
  "$workflows/guardrails.yml" \
  "$workflows/container-publish.yml"; do
  grep -Fq "repository: $valkey_repository" "$workflow"
  grep -Fq "ref: $valkey_commit" "$workflow"
  grep -Fq 'run: scripts/install-valkey-ci.sh' "$workflow"
done

for consumer in scripts/test-valkey.sh tools/cmd/conformance/main.go; do
  grep -Fq 'build/ci/toolchain.json' "$consumer" ||
    fail "Valkey consumer does not read the central manifest: $consumer"
  if grep -Fq "$valkey_version" "$consumer"; then
    fail "Valkey consumer duplicates the manifest version: $consumer"
  fi
done

grep -Fq 'groups:' .github/dependabot.yml
grep -Fq 'codeql-actions:' .github/dependabot.yml
grep -Fq '"github/codeql-action/*"' .github/dependabot.yml
scripts/test-ci-environment.sh

if grep -Eq \
  '(^|[[:space:]])(pull_request|push|workflow_dispatch|workflow_call):' \
  "$workflows/container-publish.yml"; then
  fail 'protected publication must remain release-event-only'
fi
