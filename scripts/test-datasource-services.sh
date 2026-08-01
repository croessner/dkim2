#!/bin/sh

set -eu

readonly ldap_image='chrroessner/openldap:2.6.13-r4@sha256:17f2e3485dae92122051da6acdb1091e6d9f1f64d30fd76fd3da3c261c6c778f'
readonly postgresql_image='postgres:18.3-alpine@sha256:54451ecb8ab38c24c3ec123f2fd501303a3a1856a5c66e98cecf2460d5e1e9d7'
readonly ldap_password='synthetic-ldap-runtime-password'
readonly postgresql_password='synthetic-postgresql-runtime-password'

command -v docker >/dev/null 2>&1 || {
	echo 'datasource integration: Docker is required' >&2
	exit 1
}
command -v openssl >/dev/null 2>&1 || {
	echo 'datasource integration: OpenSSL is required' >&2
	exit 1
}

work="$(mktemp -d /tmp/dkim2-datasource-integration.XXXXXX)"
chmod 0700 "$work"
ldap_name="dkim2-ldap-$PPID-$$"
postgresql_name="dkim2-postgresql-$PPID-$$"

# cleanup removes only invocation-owned containers and ignored state.
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	docker rm -f "$ldap_name" "$postgresql_name" >/dev/null 2>&1 || true
	rm -rf "$work"
	exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

umask 077
mkdir "$work/certs" "$work/ldap-init" "$work/ldap-schema"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
	-subj '/CN=DKIM2 disposable datasource CA' \
	-keyout "$work/ca.key" -out "$work/certs/ca.crt" >/dev/null 2>&1

# issue_server_certificate creates one one-day certificate for an exact test name.
issue_server_certificate() {
	name=$1
	openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=$name" \
		-addext "subjectAltName=DNS:$name" \
		-keyout "$work/certs/$name.key" -out "$work/certs/$name.csr" >/dev/null 2>&1
	printf '%s\n' "subjectAltName=DNS:$name" >"$work/certs/$name.ext"
	openssl x509 -req -days 1 -sha256 \
		-in "$work/certs/$name.csr" \
		-CA "$work/certs/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
		-extfile "$work/certs/$name.ext" \
		-out "$work/certs/$name.crt" >/dev/null 2>&1
}

issue_server_certificate ldap.integration.test
issue_server_certificate postgresql.integration.test
openssl genpkey -algorithm ED25519 -out "$work/credential.key" >/dev/null 2>&1
openssl pkey -in "$work/credential.key" -pubout -outform DER \
	-out "$work/credential.spki"
openssl pkey -in "$work/credential.key" -outform DER \
	-out "$work/credential.pkcs8"
spki_base64="$(base64 <"$work/credential.spki" | tr -d '\r\n')"
spki_hex="$(od -An -tx1 -v "$work/credential.spki" | tr -d ' \n')"
private_pkcs8_base64="$(base64 <"$work/credential.pkcs8" | tr -d '\r\n')"
private_pkcs8_hex="$(od -An -tx1 -v "$work/credential.pkcs8" | tr -d ' \n')"

cp contrib/schema/ldap/rnsdkim2.schema "$work/ldap-schema/rnsdkim2.schema"
cp contrib/schema/postgresql/001_dkim2_datasource.sql \
	"$work/certs/001_dkim2_datasource.sql"
chmod 0755 "$work" "$work/certs" "$work/ldap-init" "$work/ldap-schema"
chmod 0644 "$work/certs/"*.crt \
	"$work/certs/001_dkim2_datasource.sql" "$work/ldap-schema/rnsdkim2.schema"
chmod 0600 "$work/certs/"*.key "$work/ca.key" "$work/credential.key"

{
	printf '%s\n' \
		'dn: ou=services,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: services' \
		'' \
		'dn: cn=runtime,ou=services,dc=integration,dc=test' \
		'objectClass: organizationalRole' \
		'objectClass: simpleSecurityObject' \
		'cn: runtime' \
		"userPassword: $ldap_password" \
		'' \
		'dn: ou=dkim2,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: dkim2' \
		'' \
		'dn: ou=dkim2-empty,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: dkim2-empty' \
		'' \
		'dn: ou=generations,ou=dkim2-empty,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: generations' \
		'' \
		'dn: ou=dkim2-corrupt,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: dkim2-corrupt' \
		'' \
		'dn: ou=generations,ou=dkim2-corrupt,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: generations' \
		'' \
		'dn: dkim2Generation=1,ou=generations,ou=dkim2-corrupt,dc=integration,dc=test' \
		'objectClass: dkim2Dataset' \
		'cn: generation-1' \
		'dkim2SchemaVersion: dkim2-datasource-v2' \
		'dkim2Generation: 1' \
		'dkim2DatasetState: committed' \
		'' \
		'dn: cn=current,ou=dkim2,dc=integration,dc=test' \
		'objectClass: dkim2Dataset' \
		'cn: current' \
		'dkim2SchemaVersion: dkim2-datasource-v2' \
		'dkim2Generation: 1' \
		'dkim2DatasetState: committed' \
		'' \
		'dn: ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: generations' \
		'' \
		'dn: dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: dkim2Dataset' \
		'cn: generation-1' \
		'dkim2SchemaVersion: dkim2-datasource-v2' \
		'dkim2Generation: 1' \
		'dkim2DatasetState: committed' \
		'' \
		'dn: ou=handles,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: handles' \
		'' \
		'dn: cn=handle,ou=handles,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: dkim2Handle' \
		'cn: handle' \
		'dkim2Generation: 1' \
		'dkim2HandleID: handle' \
		'' \
		'dn: ou=profiles,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: profiles' \
		'' \
		'dn: cn=profile,ou=profiles,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: dkim2Profile' \
		'cn: profile' \
		'dkim2Generation: 1' \
		'dkim2ProfileID: profile' \
		'dkim2SigningDomain: example.test' \
		'dkim2RecordStatus: active' \
		'' \
		'dn: ou=credentials,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: credentials' \
		'' \
		'dn: cn=credential,ou=credentials,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: dkim2Credential' \
		'cn: credential' \
		'dkim2Generation: 1' \
		'dkim2ProfileID: profile' \
		'dkim2Algorithm: ed25519-sha256' \
		'dkim2Selector: selector' \
		"dkim2PublicKeySPKI:: $spki_base64" \
		'dkim2HandleID: handle' \
		'' \
		'dn: ou=policies,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: policies' \
		'' \
		'dn: cn=policy,ou=policies,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: dkim2Policy' \
		'cn: policy' \
		'dkim2Generation: 1' \
		'dkim2TenantID: tenant' \
		'dkim2SigningDomain: example.test' \
		'dkim2ProfileUse: originator' \
		'dkim2ProfileID: profile' \
		'dkim2RecordStatus: active' \
		'dkim2Rollout: enforce' \
		'dkim2Compatibility: strict' \
		'' \
		'dn: ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: organizationalUnit' \
		'ou: key-material' \
		'' \
		'dn: cn=key,ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=integration,dc=test' \
		'objectClass: dkim2KeyMaterial' \
		'cn: key' \
		'dkim2Generation: 1' \
		'dkim2TenantID: tenant' \
		'dkim2SigningDomain: example.test' \
		'dkim2ProfileUse: originator' \
		'dkim2HandleID: handle' \
		'dkim2Algorithm: ed25519-sha256' \
		"dkim2PublicKeySPKI:: $spki_base64" \
		"dkim2PrivateKeyPKCS8:: $private_pkcs8_base64"
} >"$work/ldap-init/10-dataset.ldif"
chmod 0644 "$work/ldap-init/10-dataset.ldif"

{
	printf '%s\n' \
		'#!/bin/sh' \
		'set -eu' \
		'cp /run/dkim2/postgresql.integration.test.crt /tmp/postgresql.crt' \
		'cp /run/dkim2/postgresql.integration.test.key /tmp/postgresql.key' \
		'chown postgres:postgres /tmp/postgresql.crt /tmp/postgresql.key' \
		'chmod 0600 /tmp/postgresql.key' \
		'exec docker-entrypoint.sh "$@"'
} >"$work/postgresql-entrypoint.sh"
chmod 0755 "$work/postgresql-entrypoint.sh"

{
	printf '%s\n' \
		'\set ON_ERROR_STOP on' \
		"CREATE DATABASE dkim2;" \
		"CREATE DATABASE dkim2_empty;" \
		"CREATE DATABASE dkim2_corrupt;" \
		"CREATE ROLE dkim2_runtime_login LOGIN PASSWORD '$postgresql_password';"
} >"$work/postgresql-bootstrap.sql"
chmod 0644 "$work/postgresql-bootstrap.sql"

{
	printf '%s\n' \
		'\set ON_ERROR_STOP on' \
		'\connect dkim2' \
		'CREATE SCHEMA IF NOT EXISTS dkim2_datasource;' \
		'\ir /run/dkim2/001_dkim2_datasource.sql' \
		"CREATE ROLE dkim2_publisher_login LOGIN PASSWORD 'synthetic-postgresql-publisher-password';" \
		'GRANT dkim2_publisher TO dkim2_publisher_login;' \
		'GRANT dkim2_runtime TO dkim2_runtime_login;' \
		"INSERT INTO dkim2_datasource.dataset_generations VALUES (1, 'dkim2-datasource-v2', 'committed');" \
		'INSERT INTO dkim2_datasource.current_generation VALUES (TRUE, 1);' \
		"INSERT INTO dkim2_datasource.handles VALUES (1, 'handle');" \
		"INSERT INTO dkim2_datasource.profiles VALUES (1, 'profile', 'example.test', 'active', NULL, NULL);" \
		"INSERT INTO dkim2_datasource.credentials VALUES (1, 'profile', 'ed25519-sha256', 'selector', decode('$spki_hex', 'hex'), 'handle');" \
		"INSERT INTO dkim2_datasource.policies VALUES (1, 'tenant', 'example.test', 'originator', 'profile', 'active', 'enforce', 'strict', NULL);" \
		"INSERT INTO dkim2_datasource.key_material VALUES (1, 'tenant', 'example.test', 'originator', 'handle', 'ed25519-sha256', decode('$spki_hex', 'hex'), decode('$private_pkcs8_hex', 'hex'));" \
		'\connect dkim2_empty' \
		'CREATE SCHEMA IF NOT EXISTS dkim2_datasource;' \
		'\ir /run/dkim2/001_dkim2_datasource.sql' \
		'GRANT dkim2_publisher TO dkim2_publisher_login;' \
		'\connect dkim2_corrupt' \
		'CREATE SCHEMA IF NOT EXISTS dkim2_datasource;' \
		'\ir /run/dkim2/001_dkim2_datasource.sql' \
		"INSERT INTO dkim2_datasource.dataset_generations VALUES (1, 'dkim2-datasource-v2', 'committed');" \
		'GRANT dkim2_publisher TO dkim2_publisher_login;'
} >"$work/postgresql-dataset.sql"
chmod 0644 "$work/postgresql-dataset.sql"

docker run -d --name "$ldap_name" \
	-p 127.0.0.1::636 \
	-e LDAP_BASE_DN='dc=integration,dc=test' \
	-e LDAP_ADMIN_PASSWORD='synthetic-ldap-admin-password' \
	-e LDAP_ALLOW_ANON_BIND=false \
	-e LDAP_CREATE_PEOPLE_OU=false \
	-e LDAP_CREATE_GROUPS_OU=false \
	-e LDAP_ENABLE_LDAP=false \
	-e LDAP_ENABLE_LDAPS=true \
	-e LDAP_ENABLE_TLS=true \
	-e LDAP_REQUIRE_TLS=false \
	-e LDAP_EXTRA_SCHEMAS='' \
	-e LDAP_TLS_CA_FILE=/run/dkim2/ca.crt \
	-e LDAP_TLS_CERT_FILE=/run/dkim2/ldap.integration.test.crt \
	-e LDAP_TLS_KEY_FILE=/run/dkim2/ldap.integration.test.key \
	-v "$work/certs:/run/dkim2:ro" \
	-v "$work/ldap-init:/docker-entrypoint-initdb.d:ro" \
	-v "$work/ldap-schema:/etc/openldap/custom-schema:ro" \
	"$ldap_image" >/dev/null

docker run -d --name "$postgresql_name" \
	-p 127.0.0.1::5432 \
	-e POSTGRES_PASSWORD='synthetic-postgresql-admin-password' \
	-v "$work/certs:/run/dkim2:ro" \
	-v "$work/postgresql-entrypoint.sh:/usr/local/bin/dkim2-entrypoint.sh:ro" \
	-v "$work/postgresql-bootstrap.sql:/docker-entrypoint-initdb.d/10-bootstrap.sql:ro" \
	-v "$work/postgresql-dataset.sql:/docker-entrypoint-initdb.d/30-dataset.sql:ro" \
	--entrypoint /usr/local/bin/dkim2-entrypoint.sh \
	"$postgresql_image" postgres \
	-c ssl=on -c ssl_cert_file=/tmp/postgresql.crt -c ssl_key_file=/tmp/postgresql.key \
	-c password_encryption=scram-sha-256 >/dev/null

# wait_healthy rejects exited, unhealthy, and unbounded service startup.
wait_healthy() {
	container=$1
	attempt=0
	while [ "$attempt" -lt 120 ]; do
		state="$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")"
		case "$state" in
		'running healthy'|'running ')
			return 0
			;;
		exited*|dead*)
			docker logs "$container" >&2 || true
			return 1
			;;
		esac
		attempt=$((attempt + 1))
		sleep 0.25
	done
	docker logs "$container" >&2 || true
	return 1
}

wait_healthy "$ldap_name"
wait_healthy "$postgresql_name"
ldap_port="$(docker port "$ldap_name" 636/tcp | sed -n 's/.*://p')"
postgresql_port="$(docker port "$postgresql_name" 5432/tcp | sed -n 's/.*://p')"
test -n "$ldap_port" && test -n "$postgresql_port"

run_qualification() {
	DKIM2_DATASOURCE_CA="$work/certs/ca.crt" \
	DKIM2_LDAP_PORT="$ldap_port" \
	DKIM2_LDAP_SERVER_NAME='ldap.integration.test' \
	DKIM2_LDAP_PASSWORD="$ldap_password" \
	DKIM2_POSTGRESQL_PORT="$postgresql_port" \
	DKIM2_POSTGRESQL_SERVER_NAME='postgresql.integration.test' \
	DKIM2_POSTGRESQL_PASSWORD="$postgresql_password" \
	GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test -tags=datasourceintegration \
			-run '^TestDisposableNetworkProvider' -count=1 -timeout=45s \
			./internal/datasource/parity
}

run_qualification
run_qualification

DKIM2_DATASOURCE_CA="$work/certs/ca.crt" \
DKIM2_LDAP_PORT="$ldap_port" \
DKIM2_POSTGRESQL_PORT="$postgresql_port" \
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
	go -C cmd/dkim2d test -tags=datasourceintegration \
		-run '^TestDisposableMigrationBootstrapPublishers$' -count=1 -timeout=50s \
		./internal/migration

if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_publisher; UPDATE dkim2_datasource.dataset_generations SET dataset_state = 'staging' WHERE generation = 1;" \
	>/dev/null 2>&1; then
	echo 'datasource integration: committed PostgreSQL generation was mutable' >&2
	exit 1
fi
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_runtime; INSERT INTO dkim2_datasource.handles VALUES (1, 'forbidden');" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL runtime role acquired write authority' >&2
	exit 1
fi

mkdir -p .artifacts/datasource-integration
candidate="$(GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
	go -C tools run ./cmd/candidateid -root ..)"
{
	printf '%s\n' \
		'{' \
		'  "schema": "dkim2.datasource-integration-report.v1",' \
		'  "base_revision": "f30fecbd35ae3afd1b590ddfe55ee45f0cf6555a",' \
		"  \"candidate_snapshot_sha256\": \"$candidate\"," \
		"  \"ldap_image\": \"$ldap_image\"," \
		"  \"postgresql_image\": \"$postgresql_image\"," \
		'  "runs": 2,' \
		'  "checks": [' \
		'    "ldap_parity_and_denials",' \
		'    "postgresql_parity_and_denials",' \
		'    "ldap_absent_to_first_concurrency_fence",' \
		'    "postgresql_absent_to_first_concurrency_fence",' \
		'    "ldap_pointerless_nonempty_denial",' \
		'    "postgresql_pointerless_nonempty_denial",' \
		'    "postgresql_committed_immutability",' \
		'    "postgresql_runtime_write_denial"' \
		'  ],' \
		'  "overall": "pass"' \
		'}'
} >.artifacts/datasource-integration/report.json
