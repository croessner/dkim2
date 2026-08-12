#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
milter="$root/cmd/dkim2-milter/internal/securefile"
exim="$root/cmd/dkim2-exim/internal/securefile"

! grep -R -q 'dkim2-milter-securefile' "$exim"
for policy in O_NOFOLLOW AT_SYMLINK_NOFOLLOW RequiredFileLinkCount \
	ExactParent ParentMode AllowRootFileOwner EventBeforeFinalOpen EventAfterRead
do
	grep -R -q "$policy" "$milter"
	grep -R -q "$policy" "$exim"
done
! grep -R -Eq 'Fstatfs|Flistxattr|acl_|posix_acl|filesystem.*allowlist' "$milter" "$exim"
test -s "$exim/securefile_unix_test.go"
test -s "$milter/securefile_unix_test.go"
