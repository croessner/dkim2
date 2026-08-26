#!/bin/sh
set -eu

release_tag=${1:?usage: generate-release-notes.sh RELEASE_TAG [PREVIOUS_TAG]}
previous_tag=${2:-}

# require_commit resolves one release boundary without accepting ambiguous revisions.
require_commit() {
  tag=$1
  git rev-parse --verify --quiet "${tag}^{commit}" >/dev/null || {
    printf 'release boundary is not a commit: %s\n' "$tag" >&2
    exit 1
  }
}

# append_section emits commits with one approved structured subject prefix.
append_section() {
  title=$1
  pattern=$2
  entries=$(git log "$release_range" \
    --pretty=format:'- %s (%h)' \
    --no-merges \
    --extended-regexp \
    --regexp-ignore-case \
    --grep="^${pattern}" \
    -- || true)

  if test -n "$entries"; then
    printf '### %s\n%s\n\n' "$title" "$entries"
    categorized=true
  fi
}

require_commit "$release_tag"
if test -n "$previous_tag"; then
  require_commit "$previous_tag"
  git merge-base --is-ancestor "${previous_tag}^{commit}" "${release_tag}^{commit}" || {
    printf 'previous release is not an ancestor of %s: %s\n' "$release_tag" "$previous_tag" >&2
    exit 1
  }
  release_range="${previous_tag}..${release_tag}"
else
  release_range=$release_tag
fi

test -n "$(git log "$release_range" --pretty=format:%H --no-merges -n 1 --)" || {
  printf 'release contains no new non-merge commits: %s\n' "$release_tag" >&2
  exit 1
}

printf '## Commit Summary\n\n'
categorized=false
append_section Added 'Add:'
append_section Changed 'Change:'
append_section Fixed 'Fix:'
append_section Removed 'Remove:'
append_section Refactored 'Refactor:'
append_section Tests 'Test:'
append_section Documentation 'Docs:'
append_section 'Build And CI' '(Build|Ci):'
append_section Security 'Security:'
append_section Dependencies 'Vendor:'
append_section Chores 'Chore:'

if test "$categorized" = false; then
  printf '### Other Commits\n'
  git log "$release_range" --pretty=format:'- %s (%h)' --no-merges -n 20 --
  printf '\n\n'
fi
