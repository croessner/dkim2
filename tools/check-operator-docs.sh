#!/bin/sh
set -eu

protected_test_tmp=
if test "$(uname -s)" = Linux; then
  artifacts=.artifacts
  if test ! -e "$artifacts"; then
    mkdir -m 0700 "$artifacts"
  fi
  test -d "$artifacts"
  test ! -L "$artifacts"
  protected_test_tmp=$(mktemp -d "$artifacts/.operator-docs-tmp.XXXXXX")
  chmod 0700 "$protected_test_tmp"
  # cleanup removes only the invocation-owned protected directory.
  cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$protected_test_tmp" || status=1
    exit "$status"
  }
  trap cleanup EXIT HUP INT TERM
fi

# refute fails the check when the fixed text is present in any named file.
refute() {
  refuted=$1
  shift
  if grep -Fq -e "$refuted" "$@"; then
    printf 'check-operator-docs: forbidden text present: %s\n' "$refuted" >&2
    exit 1
  fi
}

# refute_pattern fails the check when the extended expression matches any input.
refute_pattern() {
  expression=$1
  shift
  if grep -ERn -e "$expression" "$@"; then
    printf 'check-operator-docs: forbidden pattern matched: %s\n' "$expression" >&2
    exit 1
  fi
}

guide=docs/operator/postfix-compose.md
supply=docs/operator/container-supply-chain.md
datasources=docs/operator/datasource-backends.md
ldap_reference=docs/operator/ldap-schema-reference.md
rotation=docs/operator/datasource-key-rotation.md
onboarding=docs/operator/native-domain-onboarding.md
semantics_audit=docs/reports/draft-05-semantics-audit-2026-08-26.md
exim_operations=docs/operations/exim-adapter.md
exim_history=docs/reports/exim-compatibility-2026-07-27.md
daemon=cmd/dkim2d/README.md
milter=cmd/dkim2-milter/README.md
client=cmd/dkim2ctl/README.md
propagator=cmd/dkim2-dsn-propagator/README.md
openapi=docs/specs/openapi/dkim2d.yaml
openapi_readme=docs/specs/openapi/README.md
containerfile=build/container/Dockerfile
for document in \
  README.md \
  "$guide" \
  "$supply" \
  "$daemon" \
  "$milter" \
  "$client" \
  "$propagator" \
  "$openapi" \
  "$openapi_readme" \
  docs/datasource-ldap-sql-design.md \
  "$datasources" \
  "$ldap_reference" \
  "$rotation" \
  "$onboarding" \
  docs/operator/datasource-ldap-postgresql.md \
  docs/operator/opendkim-migration.md \
  docs/operator/examples/dkim2d-signing-ldap.yaml \
  docs/operator/examples/dkim2d-signing-postgresql.yaml \
  docs/operator/examples/dkim2d-signing-mysql.yaml \
  docs/operator/examples/dkim2d-domain-admin-ldap.yaml \
  docs/operator/examples/dkim2d-rotation-admin-ldap.yaml \
  docs/operator/examples/dkim2d-domain-intent.yaml \
  contrib/schema/mysql/002_least_privilege_grants.sql.example \
  docs/replay-store-valkey.md \
  docs/reference/README.md \
  docs/reference/compatibility.md \
  docs/reference/draft-issues.md \
  docs/reference/known-limitations.md \
  docs/reference/release-candidate.md \
  docs/conformance.md \
  docs/security-testing.md \
  docs/ci.md \
  "$semantics_audit" \
  "$exim_operations" \
  "$exim_history" \
  docs/specs/implementation/datasource-providers.md \
  "$containerfile"; do
  test -s "$document"
done

for reference in \
  'docs/operator/native-domain-onboarding.md' \
  'docs/operator/examples/dkim2d-domain-admin-ldap.yaml' \
  'docs/operator/examples/dkim2d-domain-intent.yaml'; do
  grep -Fq "$reference" README.md
done
for reference in \
  'examples/dkim2d-domain-admin-ldap.yaml' \
  'examples/dkim2d-domain-intent.yaml'; do
  grep -Fq "$reference" "$onboarding"
done

for command in \
  'datasource domain plan' \
  'datasource domain prepare' \
  'datasource domain dns export' \
  'datasource domain prove' \
  'datasource domain activate' \
  'datasource domain status' \
  'datasource domain reconcile' \
  'datasource domain abort'; do
  grep -Fq "$command" "$onboarding"
  grep -Fq "$command" cmd/dkim2d/internal/command/command.go
done

for invariant in \
  'receipt-before-Claim' \
  'not a public lifecycle state' \
  'ownerless unchanged `R` never closes `release_required`' \
  'authoritative ownerless exact' \
  'performs no `Release`' \
  'no persisted verified state' \
  'fresh recursive resolver path' \
  'not an authoritative DNS query' \
  'prepared-without-backend' \
  'key_recovery_unavailable' \
  'higher-generation rollback' \
  'runtime_smoke_required'; do
  grep -Fqi "$invariant" "$onboarding"
done

refute 'no operator CLI for that workflow is released' README.md
refute 'currently accept only `dkim2-datasource-v2`' cmd/dkim2d/README.md
refute 'unique staging current entry' cmd/dkim2d/README.md
refute 'LDAP atomically claims and later activates the unique `cn=current`' "$datasources"
refute '18/6 schema allocation' "$datasources"
refute 'stable v2 current fence' "$datasources"
refute 'not yet exposed as an operator command' "$rotation"
refute 'Until the native domain-onboarding command surface is wired and qualified' "$rotation"
grep -Fq 'native v2 or v3 generation' README.md
grep -Fq 'LDAP, PostgreSQL, MySQL, and' cmd/dkim2d/README.md
grep -Fq 'MariaDB accept an exact complete' cmd/dkim2d/README.md
grep -Fq 'atomic LDAP Add with no placeholder current' cmd/dkim2d/README.md
grep -Fq 'creates `cn=current` through one atomic Add' "$datasources"
grep -Fq '23-attribute/eight-class' "$datasources"
grep -Fq 'native-domain-onboarding.md' "$rotation"
refute 'key-manager integration remains a separate project' docs/reference/known-limitations.md
for document in \
  docs/reference/README.md \
  docs/reference/compatibility.md \
  docs/reference/known-limitations.md; do
  grep -Fq 'native-domain-onboarding.md' "$document"
done
grep -Fq 'native-domain onboarding implementation is a later local closeout' docs/reference/release-candidate.md
for evidence in \
  'dkim2.datasource-integration-report.v2' \
  'four qualification runs' \
  '54 unique allowlisted checks' \
  'exactly twelve backend-by-result-class PASS'; do
  grep -Fq "$evidence" docs/security-testing.md
done

grep -Fq 'docs/reference/README.md' README.md
for reference in draft-issues.md compatibility.md known-limitations.md; do
  grep -Fq "$reference" docs/reference/README.md
done

for required in \
  'draft-ietf-dkim-dkim2-spec-06' \
  'draft-chuang-dkim2-dns-04' \
  '127.0.0.1:2525' \
  'milter_protocol = 6' \
  'milter_default_action = tempfail' \
  'Exim' \
  'unqualified_draft06' \
  'LDAP' \
  'SQL' \
  'PostgreSQL' \
  'read-only' \
  'rollback' \
  'backup'; do
  grep -Fq "$required" "$guide"
done

grep -Fq 'draft-ietf-dkim-dkim2-spec-06' README.md
grep -Fq 'unqualified_draft06' README.md
refute 'DKIM2 based on `draft-ietf-dkim-dkim2-spec-04`' README.md
refute 'implemented with capability `qualified_linux`' README.md
refute 'Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04`' "$guide"
refute 'Exim is `qualified_linux`' "$guide"

for document in \
  docs/conformance.md \
  docs/security-testing.md \
  docs/reference/compatibility.md \
  docs/reference/known-limitations.md \
  docs/reference/release-candidate.md \
  "$exim_operations"; do
  grep -Fq 'unqualified_draft06' "$document"
done
for required in \
  'duplicate_hash_algorithm' \
  'invalid_recipe_json' \
  'duplicate_selector' \
  'too_many_signatures' \
  'positional' \
  'drain-only' \
  'retention period' \
  'draft-chuang-dkim2-dns-04' \
  'working-group DNS successor'; do
  grep -Fq "$required" "$semantics_audit"
done
grep -Fq 'Historical Draft-04 audit' docs/reports/current-semantics-audit-2026-08-21.md
grep -Fq 'Historical Draft-04 qualification evidence' "$exim_history"

for reference in \
  'cmd/dkim2d/README.md' \
  'cmd/dkim2-milter/README.md' \
  'cmd/dkim2ctl/README.md' \
  'cmd/dkim2-dsn-propagator/README.md' \
  'docs/operator/container-supply-chain.md' \
  'docs/operator/datasource-backends.md' \
  'docs/operator/ldap-schema-reference.md' \
  'docs/operator/datasource-key-rotation.md' \
  'docs/operator/opendkim-migration.md' \
  'docs/specs/openapi/dkim2d.yaml'; do
  grep -Fq "$reference" README.md
done

for required in \
  'signing.reload_interval' \
  'dkim2-datasource-v2' \
  'dkim2PrivateKeyPKCS8' \
  'dkim2KeyMaterial' \
  'PostgreSQL' \
  'MySQL' \
  'MariaDB' \
  'higher generation' \
  'rollback'; do
  grep -Fq "$required" "$datasources" "$ldap_reference" "$rotation"
done

for command in \
  'datasource bootstrap-opendkim' \
  'datasource rollback'; do
  grep -Fq "$command" "$rotation"
  grep -Fq "$command" cmd/dkim2d/internal/command/command.go
done
for subject in \
  'OpenLDAP `2.6.13-r4`' \
  'PostgreSQL `18.3-alpine`' \
  'MySQL `8.4`' \
  'MariaDB `10.11`' \
  'Valkey `9.1.0`'; do
  grep -Fq "$subject" docs/reference/compatibility.md
done

refute 'refresh_interval' "$datasources" docs/operator/examples/*.yaml
refute 'response_bytes' "$datasources" docs/operator/examples/*.yaml
refute 'dkim2-datasource-v1' contrib/schema/ldap/layout.ldif
refute 'LDAP and SQL providers are deferred to M22' docs/ARCHITECTURE.md
refute 'architecture-only until M22' docs/ARCHITECTURE.md

run_operator_example_tests() {
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C cmd/dkim2d test \
      -run '^(TestOperatorDatasourceExamplesValidate|TestOperatorDomainExamplesValidate|TestOperatorLDAPBundleMatchesNativeCustody|TestLeastPrivilegeGrantTemplateMatchesPublisherContract)$' \
      ./internal/config ./internal/domainadmin ./internal/datasource/ldap ./internal/datasource/mysql
}
if test -n "$protected_test_tmp"; then
  TMPDIR="$(pwd -P)/$protected_test_tmp" run_operator_example_tests
else
  run_operator_example_tests
fi
for reference in \
  'cmd/dkim2d/README.md' \
  'cmd/dkim2-milter/README.md' \
  'cmd/dkim2ctl/README.md' \
  'cmd/dkim2-dsn-propagator/README.md' \
  'docs/operator/container-supply-chain.md'; do
  grep -Fq "$reference" "$guide"
done

# The propagation deployment contract must stay stated where operators act.
for required in \
  'dsn_propagator_destination_recipient_limit = 1' \
  '-o smtpd_milters=' \
  '-o non_smtpd_milters=' \
  '-o smtpd_client_restrictions=permit_mynetworks,reject' \
  '-o content_filter=' \
  'minimal_backoff_time' \
  'dsn_propagation.pending_lease' \
  'dkim2-dsn-propagator probe --config' \
  'permanent_failure_reply' \
  'unprovisioned_domain' \
  'without Postfix parameter names'; do
  grep -Fq -e "$required" "$guide"
done
for required in \
  'dkim2-dsn-propagator-config-v1' \
  'permanent_failure_reply' \
  'probe --config' \
  'validate --config' \
  'unprovisioned_domain' \
  'docs/operator/postfix-compose.md'; do
  grep -Fq -e "$required" "$propagator"
done
refute 'and is completed separately' "$propagator"
# Only the daemon image declares a healthcheck; the propagator documents that.
test "$(grep -c '^HEALTHCHECK' "$containerfile")" -eq 1
grep -Fq 'HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/usr/local/bin/dkim2d", "probe"]' \
  "$containerfile"
grep -Fq 'no `HEALTHCHECK`' "$propagator"
grep -Fq 'at-least-once' "$propagator"
grep -Fq 'embedded = unverified' docs/reference/known-limitations.md
for document in "$datasources" "$ldap_reference" "$rotation"; do
  grep -Fq 'delivery_status' "$document"
  grep -Fq 'unprovisioned_domain' "$document"
done
grep -Fq 'delivery_status' docs/reference/known-limitations.md
grep -Fq 'unsupported_chain' docs/reference/known-limitations.md
grep -Fq 'at-least-once' docs/reference/known-limitations.md
grep -Fq 'valkey-server` 9.1.0' docs/reference/known-limitations.md
refute 'no DSN is propagated backwards' docs/reference/known-limitations.md
for required in \
  '/v1/dsn/propagate' \
  'X-DKIM2-DSN-Propagate-Capability' \
  'propagation_commit_unresolved' \
  'dsn_propagate_capability_file'; do
  grep -Fq "$required" docs/reference/compatibility.md
done
for required in \
  'received-dsn-golden.json' \
  'dsn-propagation-golden.json' \
  'received-dsn-evaluation' \
  'dsn-propagation-rebuild'; do
  grep -Fq "$required" docs/conformance.md
done
for required in FuzzReceivedDSN FuzzRebuild; do
  grep -Fq "$required" docs/security-testing.md
done

test "$(sed -n 's|^  \(/[^:]*\):$|\1|p' "$openapi" | wc -l | tr -d ' ')" -eq 9
for route in /metrics /healthz /readyz /v1/process /v1/sign /v1/revise /v1/dsn/sign \
  /v1/dsn/propagate /v1/dsn/propagate/commit; do
  grep -Fq "  $route:" "$openapi"
  grep -Fq "\`$route\`" "$daemon"
done
for operation in processMessage signMessage reviseMessage signDeliveryStatus \
  propagateDeliveryStatus commitDeliveryStatusPropagation; do
  grep -Fq "operationId: $operation" "$openapi"
done
for capability in \
  capability_file \
  sign_capability_file \
  revise_capability_file \
  dsn_sign_capability_file \
  dsn_propagate_capability_file; do
  grep -Fq "$capability" "$daemon"
done
for flag in \
  --capability-file \
  --sign-capability-file \
  --revise-capability-file \
  --dsn-sign-capability-file; do
  grep -Fq -- "\"${flag#--}\"" cmd/dkim2ctl/internal/command/command.go
  grep -Fq -- "$flag" "$client"
done
grep -Fq -- '"dsn-propagate-capability-file"' cmd/dkim2ctl/internal/command/command.go
for mode in inbound originator ordinary_transit; do
  grep -Fq "\`$mode\`" "$milter"
done
for probe in \
  'dkim2d probe' \
  'dkim2-milter probe --config'; do
  grep -Fq "$probe" "$daemon" "$milter"
done

for target in check-images images-multiarch image-sbom image-provenance image-vulnerability check-container-release release-guardrails; do
  grep -Fq "make $target" "$supply"
  grep -Eq "^$target:" Makefile
done
for target in check-deployment deployment-postfix deployment-security; do
  grep -Fq "make $target" "$guide"
  grep -Eq "^$target:" Makefile
done
for target in deployment-postfix deployment-security; do
  grep -Fq "make $target" README.md
  grep -Eq "^$target:" Makefile
done
for platform in amd64 arm64; do
  grep -Fq "$platform" "$supply"
done
for label in \
  org.opencontainers.image.source \
  org.opencontainers.image.revision \
  org.opencontainers.image.version \
  org.opencontainers.image.created \
  org.opencontainers.image.vendor \
  org.opencontainers.image.documentation \
  org.opencontainers.image.licenses \
  org.opencontainers.image.title \
  org.opencontainers.image.description; do
  grep -Fq "$label" "$containerfile"
done

for document in README.md "$guide"; do
  grep -Fq 'Exim adapter' "$document"
  grep -Fq 'matrix' "$document"
  grep -Fq 'unqualified_draft06' "$document"
  grep -Fq 'LDAP' "$document"
  grep -Fq 'SQL' "$document"
  refute 'deferred_ldap_sql_migration' "$document"
done

refute_pattern \
  '(inbound-only|does not sign or revise|signing or revision endpoints|protected generated-client capability loader)' \
  "$daemon" "$openapi_readme"
refute_pattern \
  '(example\.(com|org|net)|0\.0\.0\.0:2525|image:[[:space:]]+[^[:space:]]*:latest)' \
  README.md cmd/dkim2d/README.md cmd/dkim2-milter/README.md \
  cmd/dkim2ctl/README.md cmd/dkim2-dsn-propagator/README.md \
  docs/operator docs/specs/openapi/README.md \
  deployments/postfix-compose \
  --include='*.md' --include='*.yaml' --include='*.cf'
