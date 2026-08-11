#!/bin/sh
set -eu

workflows=.github/workflows
ordinary_workflows="
$workflows/codeql.yml
$workflows/conformance.yml
$workflows/container-release.yml
$workflows/guardrails.yml
$workflows/unit-tests.yml
"

if ! command -v actionlint >/dev/null 2>&1; then
  printf '%s\n' 'actionlint is required for make check-ci' >&2
  exit 1
fi

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
  if grep -Eq '(packages|id-token|attestations):[[:space:]]*write' "$workflow"; then
    printf 'ordinary workflow has publication authority: %s\n' "$workflow" >&2
    exit 1
  fi
done

if grep -RE 'uses: [^@[:space:]]+@(main|master|v[0-9]+([.]|$))' "$workflows"; then
  printf '%s\n' 'workflow actions must use full commit pins' >&2
  exit 1
fi

if grep -RE '^[[:space:]]*uses:' "$workflows" |
  grep -Ev 'uses: [^@[:space:]]+@[0-9a-f]{40}([[:space:]]+#.*)?$'; then
  printf '%s\n' 'workflow action pin is not a full lowercase commit SHA' >&2
  exit 1
fi

checkout_pins=$(sed -n 's/.*uses: actions\/checkout@\([0-9a-f]*\).*/\1/p' \
  "$workflows"/* | sort -u)
setup_go_pins=$(sed -n 's/.*uses: actions\/setup-go@\([0-9a-f]*\).*/\1/p' \
  "$workflows"/* | sort -u)
upload_pins=$(sed -n 's/.*uses: actions\/upload-artifact@\([0-9a-f]*\).*/\1/p' \
  "$workflows"/* | sort -u)
codeql_pins=$(sed -n 's/.*uses: github\/codeql-action\/[^@]*@\([0-9a-f]*\).*/\1/p' \
  "$workflows"/* | sort -u)

test "$checkout_pins" = de0fac2e4500dabe0009e67214ff5f5447ce83dd
test "$setup_go_pins" = 4b73464bb391d4059bd26b0524d20df3927bd417
test "$upload_pins" = bbbca2ddaa5d8feaa63e36b76fdaad77386f024f
test "$codeql_pins" = 0d579ffd059c29b07949a3cce3983f0780820c98

if grep -Rq 'go-version: "1.26.0"' "$workflows"; then
  printf '%s\n' 'GitHub Actions must use the repository Go 1.26.5 patch level' >&2
  exit 1
fi

test "$(grep -Rh 'go-version: "1.26.5"' "$workflows" | wc -l | tr -d ' ')" -ge 6
grep -Fq 'run: make release-guardrails' "$workflows/container-publish.yml"
grep -Fq 'run: make check-container-release' "$workflows/container-release.yml"
grep -Fq 'run: make guardrails' "$workflows/guardrails.yml"
grep -Fq 'run: make test' "$workflows/unit-tests.yml"
grep -Fq '          - language: actions' "$workflows/codeql.yml"
grep -Fq '          - language: go' "$workflows/codeql.yml"
grep -Fq '          - language: c-cpp' "$workflows/codeql.yml"
grep -Fq 'security-events: write' "$workflows/codeql.yml"

if grep -Eq '(^|[[:space:]])(pull_request|push|workflow_dispatch|workflow_call):' \
  "$workflows/container-publish.yml"; then
  printf '%s\n' 'protected publication must remain release-event-only' >&2
  exit 1
fi
