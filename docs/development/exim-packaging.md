# Exim Adapter Packaging

`make check-exim-matrix-prep` verifies the pinned source manifests, public-API
probe contracts, source-package build patches, C harness, generated build-ID
artifacts, and hermetic deployment-validator fixtures. It performs no network
fetch and never resolves `latest`.

For each matrix row, fetch the official signed source metadata outside this
hermetic check, verify the recorded source checksum, apply the exact checked
`packaging/exim/dkim2-transport-filter-return-path.patch` with `patch -p1`
before the row's local-scan source/header patch and distribution build hook,
and regenerate the build ID from that exact manifest. The patch is required
for outbound filters because it recognizes only the direct-argv
`$dkim2_transport_filter_return_path` token in the SMTP transport-filter call
path; it does not enable a general taint bypass. An unpatched distribution
binary is therefore not supported for outbound filtering. The checked-in public API
fixtures retain upstream GPL-2.0-or-later notices; generated OpenAPI client
fixtures retain the repository and generator dependency licenses recorded in
the module and vendor metadata.

The matrix preparation artifacts are compile/test inputs, not proof of a real
Exim run. `make check-exim-c-linux-native` compiles the prepared `Local/`
source/header layout with the runner's native Linux C compiler and is part of
the explicit `make integration-exim` gate. Release qualification additionally runs
`make check-exim-c-linux-cross`, which uses exact Zig 0.16.0 targets for Linux
amd64 and arm64. Zig is therefore a qualification dependency, not a hidden
requirement of ordinary GitHub CI. Authenticated qualification
builds remain bound to each pinned source-package toolchain.

Release qualification owns authenticated package builds and recorded
SMTP/filter execution for upstream 4.99.5, Debian 13, and Ubuntu 26.04.
