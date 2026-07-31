# Debian 13 source-package integration

Use only the authenticated Debian source package named in
`../../exim/fixtures/debian-4.98.2-1+deb13u3/source-manifest-v1.txt`.

1. Verify the signed source metadata and every recorded checksum.
2. Apply `../exim/dkim2-transport-filter-return-path.patch` with `patch -p1`
   before `../../exim/fixtures/debian-4.98.2-1+deb13u3/local_scan.patch`. The
   source patch is required for outbound filters and accepts only the one
   direct-argv `$dkim2_transport_filter_return_path` token in the SMTP filter
   call path.
3. Apply `../../exim/fixtures/debian-4.98.2-1+deb13u3/local_scan.patch`.
4. Run `make check-exim-row-builds`, then stage `../exim/Local.Makefile` as
   `debian/dkim2/dkim2.mk`, together with `dkim2_local_scan.c` and only the
   matching row's checked-in `fixtures/<exact-row>/build-id-v1.h`. Apply the
   baseline build patch, which includes the fragment without replacing
   `Local/Makefile`. The patch also writes `LOCAL_SCAN_HAS_OPTIONS=yes`
   directly into each generated daemon `Local/Makefile`: Exim's `config.h`
   generation reads that file before Make resolves included fragments. Confirm
   the installed binary exposes the DKIM2 options with `exim4 -bP local_scan`.
5. Build with the normal Debian source-package toolchain; do not reuse an
   object compiled for another Exim revision.
6. Run `make check-exim-row-builds` and the deployment validator before
   activation. The installed binary's embedded ID must equal that exact row's
   compatibility manifest and must not equal another matrix row.

Rollback restores the distribution package and removes the DKIM2 local-scan
configuration only after Exim has been stopped.
