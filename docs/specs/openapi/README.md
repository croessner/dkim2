# OpenAPI Contracts

This directory contains the planned source-of-truth OpenAPI contract for
`dkim2d`.

Expected generated-code policy:

- The YAML contract is authoritative.
- Server and client generated code must be reproducible.
- Generated DTOs stay at HTTP boundaries.
- Core DKIM2 domain packages must not import generated REST types.
- `dkim2ctl` and test-client workflows use the generated client SDK.

The initial contract is intentionally small and will expand as service behavior
is implemented.

