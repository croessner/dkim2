#!/bin/sh
# Copyright 2026 Christian Roessner
# SPDX-License-Identifier: Apache-2.0

set -eu

# install_private confines each service's synthetic secrets to its own private read-only runtime volume.
install_private() {
  destination=$1
  owner=$2
  shift 2
  mkdir -p "$destination"
  for source in "$@"; do
    target="$destination/$(basename "$source")"
    cp "$source" "$target"
    chown "$owner" "$target"
    chmod 0400 "$target"
  done
  chown "$owner" "$destination"
  chmod 0700 "$destination"
}

# These IDs are verified against the canonical Rspamd and Valkey images and the Nauthilus Dockerfile.
install_private /rspamd 11333:11333 \
  /input/protected/process-capability /input/protected/rspamd-retry-hmac \
  /input/protected/nauthilus-policy-password /input/protected/observation-password \
  /input/protected/outbox-password /input/protected/outbox-allocation \
  /input/protected/outbox-encryption-active /input/protected/outbox-encryption-previous
install_private /nauthilus 65532:65532 \
  /input/protected/reputation-subject-key /input/protected/reputation-manifest-key
install_private /outbox 999:1000 \
  /input/protected/outbox.acl /input/certs/outbox-redis.crt \
  /input/certs/outbox-redis.key /input/certs/policy-e2e-ca.crt
mkdir -p /outbox-data
chown 999:1000 /outbox-data
chmod 0700 /outbox-data
