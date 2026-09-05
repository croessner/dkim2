#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
milter="$root/cmd/dkim2-milter/internal/securefile"
exim="$root/cmd/dkim2-exim/internal/securefile"
propagator="$root/cmd/dkim2-dsn-propagator/internal/securefile"

! grep -R -q 'dkim2-milter-securefile' "$exim"
! grep -R -q 'dkim2-milter-securefile' "$propagator"
for policy in O_NOFOLLOW AT_SYMLINK_NOFOLLOW RequiredFileLinkCount \
	ExactParent ParentMode AllowRootFileOwner EventBeforeFinalOpen EventAfterRead
do
	grep -R -q "$policy" "$milter"
	grep -R -q "$policy" "$exim"
	grep -R -q "$policy" "$propagator"
done
! grep -R -Eq 'Fstatfs|Flistxattr|acl_|posix_acl|filesystem.*allowlist' \
	"$milter" "$exim" "$propagator"
test -s "$exim/securefile_unix_test.go"
test -s "$milter/securefile_unix_test.go"
test -s "$propagator/securefile_unix_test.go"
