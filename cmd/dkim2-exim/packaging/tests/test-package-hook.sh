#!/bin/sh
set -eu

# Exercise the exact daemon-tree injection hunk and its required failure mode.
root=$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-exim-package-hook.XXXXXX")
trap 'rm -rf "$work"' 0 1 2 15

for variant in debian ubuntu; do
	case_dir="$work/$variant"
	mkdir -p "$case_dir"
	cp -R "$root/cmd/dkim2-exim/packaging/tests/fixtures/$variant/." "$case_dir/"
	mkdir -p "$case_dir/debian/dkim2"
	cp "$root/cmd/dkim2-exim/packaging/exim/Local.Makefile" "$case_dir/debian/dkim2/dkim2.mk"
	cp "$root/cmd/dkim2-exim/exim/dkim2_local_scan.c" "$case_dir/debian/dkim2/dkim2_local_scan.c"
	cp "$root/cmd/dkim2-exim/exim/fixtures/debian-4.98.2-1+deb13u3/build-id-v1.h" "$case_dir/debian/dkim2/build-id-v1.h"
	patch -s -p1 -d "$case_dir" < "$root/cmd/dkim2-exim/packaging/$variant/exim4-dkim2-build.patch"
	make -s -C "$case_dir" -f debian/rules override_dh_auto_configure
	make -s -C "$case_dir" -f debian/rules override_dh_auto_configure
	for daemon in exim4-daemon-light exim4-daemon-heavy; do
		local_dir="$case_dir/b-$daemon/Local"
		cmp "$case_dir/debian/dkim2/dkim2.mk" "$local_dir/dkim2.mk"
		cmp "$case_dir/debian/dkim2/dkim2_local_scan.c" "$local_dir/dkim2_local_scan.c"
		cmp "$case_dir/debian/dkim2/build-id-v1.h" "$local_dir/build-id-v1.h"
		count=$(grep -cxF 'include ../Local/dkim2.mk' "$local_dir/Makefile")
		test "$count" -eq 1
		count=$(grep -cxF 'LOCAL_SCAN_HAS_OPTIONS=yes' "$local_dir/Makefile")
		test "$count" -eq 1
	done
	rm "$case_dir/debian/dkim2/build-id-v1.h"
	rm -rf "$case_dir"/b-exim4-daemon-*
	if make -s -C "$case_dir" -f debian/rules override_dh_auto_configure >/dev/null 2>&1; then
		echo "$variant package hook accepted a missing build-id header" >&2
		exit 1
	fi
done
