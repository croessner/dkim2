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
  cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$protected_test_tmp" || status=1
    exit "$status"
  }
  trap cleanup EXIT HUP INT TERM
fi

guide=docs/operator/postfix-compose.md
supply=docs/operator/container-supply-chain.md
datasources=docs/operator/datasource-backends.md
ldap_reference=docs/operator/ldap-schema-reference.md
rotation=docs/operator/datasource-key-rotation.md
onboarding=docs/operator/native-domain-onboarding.md
daemon=cmd/dkim2d/README.md
milter=cmd/dkim2-milter/README.md
client=cmd/dkim2ctl/README.md
openapi=docs/specs/openapi/dkim2d.yaml
openapi_readme=docs/specs/openapi/README.md
containerfile=build/container/Containerfile
for document in \
  README.md \
  "$guide" \
  "$supply" \
  "$daemon" \
  "$milter" \
  "$client" \
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

! grep -Fq 'no operator CLI for that workflow is released' README.md
! grep -Fq 'currently accept only `dkim2-datasource-v2`' cmd/dkim2d/README.md
! grep -Fq 'unique staging current entry' cmd/dkim2d/README.md
! grep -Fq 'LDAP atomically claims and later activates the unique `cn=current`' "$datasources"
! grep -Fq '18/6 schema allocation' "$datasources"
! grep -Fq 'stable v2 current fence' "$datasources"
! grep -Fq 'not yet exposed as an operator command' "$rotation"
! grep -Fq 'Until the native domain-onboarding command surface is wired and qualified' "$rotation"
grep -Fq 'native v2 or v3 generation' README.md
grep -Fq 'LDAP, PostgreSQL, MySQL, and' cmd/dkim2d/README.md
grep -Fq 'MariaDB accept an exact complete' cmd/dkim2d/README.md
grep -Fq 'atomic LDAP Add with no placeholder current' cmd/dkim2d/README.md
grep -Fq 'creates `cn=current` through one atomic Add' "$datasources"
grep -Fq '23-attribute/eight-class' "$datasources"
grep -Fq 'native-domain-onboarding.md' "$rotation"
! grep -Fq 'key-manager integration remains a separate project' docs/reference/known-limitations.md
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
  'draft-ietf-dkim-dkim2-spec-04' \
  'draft-chuang-dkim2-dns-04' \
  '127.0.0.1:2525' \
  'milter_protocol = 6' \
  'milter_default_action = tempfail' \
  'Exim' \
  'qualified_linux' \
  'LDAP' \
  'SQL' \
  'PostgreSQL' \
  'read-only' \
  'rollback' \
  'backup'; do
  grep -Fq "$required" "$guide"
done

for reference in \
  'cmd/dkim2d/README.md' \
  'cmd/dkim2-milter/README.md' \
  'cmd/dkim2ctl/README.md' \
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

! grep -Fq 'refresh_interval' "$datasources" docs/operator/examples/*.yaml
! grep -Fq 'response_bytes' "$datasources" docs/operator/examples/*.yaml
! grep -Fq 'dkim2-datasource-v1' contrib/schema/ldap/layout.ldif
! grep -Fq 'LDAP and SQL providers are deferred to M22' docs/ARCHITECTURE.md
! grep -Fq 'architecture-only until M22' docs/ARCHITECTURE.md

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
  'docs/operator/container-supply-chain.md'; do
  grep -Fq "$reference" "$guide"
done

test "$(sed -n 's|^  \(/[^:]*\):$|\1|p' "$openapi" | wc -l | tr -d ' ')" -eq 7
for route in /metrics /healthz /readyz /v1/process /v1/sign /v1/revise /v1/dsn/sign; do
  grep -Fq "  $route:" "$openapi"
  grep -Fq "\`$route\`" "$daemon"
done
for operation in processMessage signMessage reviseMessage signDeliveryStatus; do
  grep -Fq "operationId: $operation" "$openapi"
done
for capability in \
  capability_file \
  sign_capability_file \
  revise_capability_file \
  dsn_sign_capability_file; do
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
  grep -Fq "make $target" Makefile
done
for target in check-deployment deployment-postfix deployment-security; do
  grep -Fq "make $target" "$guide"
  grep -Fq "make $target" Makefile
done
for target in deployment-postfix deployment-security; do
  grep -Fq "make $target" README.md
  grep -Fq "make $target" Makefile
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
  grep -Fq 'qualified_linux' "$document"
  grep -Fq 'LDAP' "$document"
  grep -Fq 'SQL' "$document"
  ! grep -Fq 'deferred_ldap_sql_migration' "$document"
done

! grep -En \
  '(inbound-only|does not sign or revise|signing or revision endpoints|protected generated-client capability loader)' \
  "$daemon" "$openapi_readme"
! grep -ERn \
  '(example\.(com|org|net)|0\.0\.0\.0:2525|image:[[:space:]]+[^[:space:]]*:latest)' \
  README.md cmd/dkim2d/README.md cmd/dkim2-milter/README.md \
  cmd/dkim2ctl/README.md docs/operator docs/specs/openapi/README.md \
  deployments/postfix-compose \
  --include='*.md' --include='*.yaml' --include='*.cf'
