# Ubuntu 26.04 source-package integration

Use only the authenticated Ubuntu security source package named in
`../../exim/fixtures/ubuntu-4.99.1-1ubuntu1.3/source-manifest-v1.txt`.

Apply `../exim/dkim2-transport-filter-return-path.patch` with `patch -p1`
before the source-matched local-scan integration. The source patch is required
for outbound filters and accepts only the direct-argv
`$dkim2_transport_filter_return_path` token in the SMTP filter call path. Run
`make check-exim-row-builds`, and stage only the matching row's checked-in
`fixtures/<exact-row>/build-id-v1.h` with the other `debian/dkim2/` inputs.
Apply the Ubuntu-specific build patch without replacing `Local/Makefile`; it
also writes `LOCAL_SCAN_HAS_OPTIONS=yes` directly into each generated daemon
`Local/Makefile`, because Exim's `config.h` generation reads that file before
Make resolves included fragments. Rebuild with Ubuntu's source-package
toolchain and confirm the installed DKIM2 options with `exim4 -bP local_scan`.
Never load a local-scan object or build-ID header built for another Exim
revision. The installed binary's
embedded ID must equal that exact row manifest and must differ from every
other matrix row. Run `make check-exim-row-builds` and the deployment
validator before activation.

Rollback restores the signed Ubuntu package and removes the DKIM2 local-scan
configuration only while Exim is stopped.
