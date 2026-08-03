#!/bin/sh

set -eu
umask 077

readonly repository_root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)"
readonly final_report='.artifacts/datasource-integration/report.json'
readonly ldap_image='chrroessner/openldap:2.6.13-r4@sha256:17f2e3485dae92122051da6acdb1091e6d9f1f64d30fd76fd3da3c261c6c778f'
readonly postgresql_image='postgres:18.3-alpine@sha256:54451ecb8ab38c24c3ec123f2fd501303a3a1856a5c66e98cecf2460d5e1e9d7'
readonly mysql_image='mysql:8.4@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb'
readonly mariadb_image='mariadb:10.11@sha256:be981e4113326ada8d6004174dd09eeaefc03094037f811182a52d4f2e737350'
readonly ldap_password='synthetic-ldap-runtime-password'
readonly postgresql_password='synthetic-postgresql-runtime-password'
readonly mysql_password='synthetic-mysql-runtime-password'
readonly mariadb_password='synthetic-mariadb-runtime-password'

# report_sha256 returns one portable exact file identity.
report_sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

# report_link_count returns the exact link count on supported test hosts.
report_link_count() {
	if stat -f '%l' "$1" >/dev/null 2>&1; then
		stat -f '%l' "$1"
	else
		stat -c '%h' "$1"
	fi
}

# validate_report_file applies the repository-owned closed v2 collector.
validate_report_file() {
	GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C "$repository_root/tools" run ./cmd/reference \
		-root "$repository_root" check-datasource-report \
		<"$1" >/dev/null
}

# publish_report atomically installs one already validated invocation-owned report.
publish_report() {
	source=$1
	directory=${final_report%/*}
	if test -L .artifacts || test -L "$directory" || test -L "$final_report"; then
		return 1
	fi
	mkdir -p "$directory"
	report_install="$(mktemp "$directory/.report.XXXXXX")"
	if ! cp "$source" "$report_install" || ! chmod 0600 "$report_install" ||
		test "$(report_link_count "$report_install")" != 1 ||
		! validate_report_file "$report_install"; then
		rm -f "$report_install"
		report_install=
		return 1
	fi
	if test "${DKIM2_REPORT_INJECT_INSTALL_FAILURE:-0}" = 1; then
		rm -f "$report_install"
		report_install=
		return 1
	fi
	if ! mv "$report_install" "$final_report"; then
		rm -f "$report_install"
		report_install=
		return 1
	fi
	report_install=
	if test -L "$final_report" || test "$(report_link_count "$final_report")" != 1 ||
		! validate_report_file "$final_report" ||
		test "$(report_sha256 "$source")" != "$(report_sha256 "$final_report")"; then
		rm -f "$final_report"
		return 1
	fi
}

# Every invocation invalidates prior PASS evidence before prerequisites or preflight.
if test -L .artifacts || test -L .artifacts/datasource-integration; then
	echo 'datasource integration: unsafe report artifact path' >&2
	exit 1
fi
if test -L "$final_report"; then
	rm -f "$final_report"
	echo 'datasource integration: unsafe final report target' >&2
	exit 1
fi
if test -e "$final_report" && test "$(report_link_count "$final_report")" != 1; then
	rm -f "$final_report"
	echo 'datasource integration: unsafe final report link count' >&2
	exit 1
fi
rm -f "$final_report"
report_install=
case "${DKIM2_REPORT_LIFECYCLE_TEST:-}" in
preflight)
	exit 0
	;;
failure)
	echo 'datasource integration: injected report lifecycle failure' >&2
	exit 1
	;;
atomic_failure)
	lifecycle_root="$(mktemp -d /tmp/dkim2-report-lifecycle.XXXXXX)"
	lifecycle_source=${DKIM2_REPORT_LIFECYCLE_SOURCE:-}
	if test -z "$lifecycle_source" || test -L "$lifecycle_source" ||
		test "$(report_link_count "$lifecycle_source")" != 1; then
		rm -rf "$lifecycle_root"
		exit 1
	fi
	DKIM2_REPORT_INJECT_INSTALL_FAILURE=1
	export DKIM2_REPORT_INJECT_INSTALL_FAILURE
	if publish_report "$lifecycle_source"; then
		rm -rf "$lifecycle_root"
		exit 1
	fi
	rm -rf "$lifecycle_root"
	exit 1
	;;
"")
	;;
*)
	echo 'datasource integration: invalid report lifecycle test mode' >&2
	exit 1
	;;
esac

command -v docker >/dev/null 2>&1 || {
	echo 'datasource integration: Docker is required' >&2
	exit 1
}
command -v openssl >/dev/null 2>&1 || {
	echo 'datasource integration: OpenSSL is required' >&2
	exit 1
}

# expect_equal reports only a fixed assertion label and bounded count values.
expect_equal() {
	label=$1
	actual=$2
	expected=$3
	if test "$actual" != "$expected"; then
		echo "datasource integration: $label count mismatch (actual=$actual expected=$expected)" >&2
		exit 1
	fi
}

work="$(mktemp -d /tmp/dkim2-datasource-integration.XXXXXX)"
chmod 0700 "$work"
ldap_name="dkim2-ldap-$PPID-$$"
ldap_admin_name="dkim2-ldap-admin-$PPID-$$"
postgresql_name="dkim2-postgresql-$PPID-$$"
mysql_name="dkim2-mysql-$PPID-$$"
mariadb_name="dkim2-mariadb-$PPID-$$"

# cleanup removes only invocation-owned containers and ignored state.
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if test -n "$report_install"; then
		rm -f "$report_install"
	fi
	docker rm -fv "$ldap_name" "$ldap_admin_name" "$postgresql_name" "$mysql_name" "$mariadb_name" >/dev/null 2>&1 || true
	rm -rf "$work"
	exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
issue_server_certificate mysql.integration.test
issue_server_certificate mariadb.integration.test
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
cp contrib/schema/ldap/rnsdkim2.schema "$work/certs/rnsdkim2.schema"
cp contrib/schema/ldap/acl.conf "$work/certs/acl.conf"
cp contrib/schema/postgresql/001_dkim2_datasource.sql \
	"$work/certs/001_dkim2_datasource.sql"
cp contrib/schema/postgresql/003_native_domain_onboarding.sql \
	"$work/certs/003_dkim2_postgresql_onboarding.sql"
cp contrib/schema/mysql/001_dkim2_datasource.sql \
	"$work/certs/001_dkim2_mysql_datasource.sql"
cp contrib/schema/mysql/003_native_domain_onboarding.sql \
	"$work/certs/003_dkim2_mysql_onboarding.sql"
sed \
	-e 's/__DATABASE__/dkim2_fresh/g' \
	-e "s/__RUNTIME_ACCOUNT__/'dkim2_runtime_login'@'%'/g" \
	-e "s/__PUBLISHER_ACCOUNT__/'dkim2_publisher_login'@'%'/g" \
	-e "s/__SNAPSHOT_ACCOUNT__/'dkim2_snapshot_login'@'%'/g" \
	-e "s/__STAGING_ACCOUNT__/'dkim2_staging_login'@'%'/g" \
	-e "s/__ACTIVATION_ACCOUNT__/'dkim2_activation_login'@'%'/g" \
	contrib/schema/mysql/002_least_privilege_grants.sql.example \
	>"$work/certs/002_dkim2_mysql_fresh_grants.sql"
chmod 0755 "$work" "$work/certs" "$work/ldap-init" "$work/ldap-schema"
chmod 0644 "$work/certs/"*.crt \
	"$work/certs/001_dkim2_datasource.sql" "$work/ldap-schema/rnsdkim2.schema" \
	"$work/certs/rnsdkim2.schema" "$work/certs/acl.conf"
chmod 0644 "$work/certs/001_dkim2_mysql_datasource.sql"
chmod 0644 "$work/certs/003_dkim2_postgresql_onboarding.sql" \
	"$work/certs/003_dkim2_mysql_onboarding.sql" \
	"$work/certs/002_dkim2_mysql_fresh_grants.sql"
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
		"CREATE DATABASE dkim2_fresh;" \
		"CREATE ROLE dkim2_runtime_login LOGIN PASSWORD '$postgresql_password';" \
		"CREATE ROLE dkim2_snapshot_login LOGIN PASSWORD 'synthetic-sql-snapshot-password';" \
		"CREATE ROLE dkim2_staging_login LOGIN PASSWORD 'synthetic-sql-staging-password';" \
		"CREATE ROLE dkim2_activation_login LOGIN PASSWORD 'synthetic-sql-activation-password';"
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
		'\ir /run/dkim2/003_dkim2_postgresql_onboarding.sql' \
		'GRANT dkim2_snapshot TO dkim2_snapshot_login;' \
		'GRANT dkim2_stager TO dkim2_staging_login;' \
		'GRANT dkim2_activator TO dkim2_activation_login;' \
		'\connect dkim2_empty' \
		'CREATE SCHEMA IF NOT EXISTS dkim2_datasource;' \
		'\ir /run/dkim2/001_dkim2_datasource.sql' \
		'\ir /run/dkim2/003_dkim2_postgresql_onboarding.sql' \
		'GRANT dkim2_publisher TO dkim2_publisher_login;' \
		'\connect dkim2_corrupt' \
		'CREATE SCHEMA IF NOT EXISTS dkim2_datasource;' \
		'\ir /run/dkim2/001_dkim2_datasource.sql' \
		"INSERT INTO dkim2_datasource.dataset_generations VALUES (1, 'dkim2-datasource-v2', 'committed');" \
		'\ir /run/dkim2/003_dkim2_postgresql_onboarding.sql' \
		'GRANT dkim2_publisher TO dkim2_publisher_login;' \
		'\connect dkim2_fresh' \
		'CREATE SCHEMA IF NOT EXISTS dkim2_datasource;' \
		'\ir /run/dkim2/001_dkim2_datasource.sql' \
		'\ir /run/dkim2/003_dkim2_postgresql_onboarding.sql'
} >"$work/postgresql-dataset.sql"
chmod 0644 "$work/postgresql-dataset.sql"

{
	printf '%s\n' \
		'#!/bin/sh' \
		'set -eu' \
		'test -n "${DKIM2_TLS_NAME:-}"' \
		'cp "/run/dkim2/$DKIM2_TLS_NAME.crt" /tmp/dkim2-mysql.crt' \
		'cp "/run/dkim2/$DKIM2_TLS_NAME.key" /tmp/dkim2-mysql.key' \
		'cp /run/dkim2/ca.crt /tmp/dkim2-ca.crt' \
		'chown mysql:mysql /tmp/dkim2-mysql.crt /tmp/dkim2-mysql.key /tmp/dkim2-ca.crt' \
		'chmod 0600 /tmp/dkim2-mysql.key' \
		'exec docker-entrypoint.sh "$@"'
} >"$work/mysql-entrypoint.sh"
chmod 0755 "$work/mysql-entrypoint.sh"

# write_mysql_dataset creates one server-specific least-authority bootstrap.
write_mysql_dataset() {
	runtime_password=$1
	publisher_password=$2
	output=$3
	{
		printf '%s\n' \
			"CREATE USER 'dkim2_runtime_login'@'%' IDENTIFIED BY '$runtime_password' REQUIRE SSL;" \
			"CREATE USER 'dkim2_publisher_login'@'%' IDENTIFIED BY '$publisher_password' REQUIRE SSL;" \
			"CREATE USER 'dkim2_snapshot_login'@'%' IDENTIFIED BY 'synthetic-sql-snapshot-password' REQUIRE SSL;" \
			"CREATE USER 'dkim2_staging_login'@'%' IDENTIFIED BY 'synthetic-sql-staging-password' REQUIRE SSL;" \
			"CREATE USER 'dkim2_activation_login'@'%' IDENTIFIED BY 'synthetic-sql-activation-password' REQUIRE SSL;"
		for database in dkim2 dkim2_empty dkim2_corrupt; do
			printf '%s\n' \
				"CREATE DATABASE $database CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;" \
				"USE $database;" \
				'SOURCE /run/dkim2/001_dkim2_mysql_datasource.sql;'
		done
		for table in dkim2_dataset_generations dkim2_current_generation \
			dkim2_handles dkim2_profiles dkim2_credentials dkim2_policies \
			dkim2_key_material; do
			printf '%s\n' \
				"GRANT SELECT ON dkim2.$table TO 'dkim2_runtime_login'@'%';"
		done
		for database in dkim2 dkim2_empty dkim2_corrupt; do
			for table in dkim2_dataset_generations dkim2_current_generation \
				dkim2_handles dkim2_profiles \
				dkim2_credentials dkim2_policies dkim2_key_material; do
				printf '%s\n' \
					"GRANT SELECT ON $database.$table TO 'dkim2_publisher_login'@'%';"
			done
			for table in dkim2_dataset_generations dkim2_current_generation \
				dkim2_handles dkim2_profiles dkim2_credentials dkim2_policies \
				dkim2_key_material; do
				printf '%s\n' \
					"GRANT INSERT ON $database.$table TO 'dkim2_publisher_login'@'%';"
			done
			printf '%s\n' \
				"GRANT UPDATE ON $database.dkim2_publication_lock TO 'dkim2_publisher_login'@'%';" \
				"GRANT UPDATE ON $database.dkim2_dataset_generations TO 'dkim2_publisher_login'@'%';" \
				"GRANT UPDATE ON $database.dkim2_current_generation TO 'dkim2_publisher_login'@'%';"
		done
		printf '%s\n' \
			'USE dkim2;' \
			"INSERT INTO dkim2_dataset_generations VALUES (1, 'dkim2-datasource-v2', 'staging');" \
			"INSERT INTO dkim2_handles VALUES (1, 'handle');" \
			"INSERT INTO dkim2_profiles VALUES (1, 'profile', 'example.test', 'active', NULL, NULL);" \
			"INSERT INTO dkim2_credentials VALUES (1, 'profile', 'ed25519-sha256', 'selector', UNHEX('$spki_hex'), 'handle');" \
			"INSERT INTO dkim2_policies VALUES (1, 'tenant', 'example.test', 'originator', 'profile', 'active', 'enforce', 'strict', NULL);" \
			"INSERT INTO dkim2_key_material VALUES (1, 'tenant', 'example.test', 'originator', 'handle', 'ed25519-sha256', UNHEX('$spki_hex'), UNHEX('$private_pkcs8_hex'));" \
			"UPDATE dkim2_dataset_generations SET dataset_state = 'committed' WHERE generation = 1;" \
			'INSERT INTO dkim2_current_generation VALUES (1, 1);' \
			'USE dkim2_corrupt;' \
			"INSERT INTO dkim2_dataset_generations VALUES (1, 'dkim2-datasource-v2', 'staging');" \
			"INSERT INTO dkim2_handles VALUES (1, 'orphan');" \
			"UPDATE dkim2_dataset_generations SET dataset_state = 'committed' WHERE generation = 1;" \
			'USE dkim2;'
		for database in dkim2 dkim2_empty dkim2_corrupt; do
			printf '%s\n' \
				"USE $database;" \
				'SOURCE /run/dkim2/003_dkim2_mysql_onboarding.sql;'
			for table in dkim2_dataset_generations dkim2_current_generation \
				dkim2_handles dkim2_profiles dkim2_credentials dkim2_policies \
				dkim2_key_material; do
				printf '%s\n' \
					"REVOKE INSERT ON $database.$table FROM 'dkim2_publisher_login'@'%';"
			done
			printf '%s\n' \
				"REVOKE UPDATE ON $database.dkim2_dataset_generations FROM 'dkim2_publisher_login'@'%';" \
				"REVOKE UPDATE ON $database.dkim2_current_generation FROM 'dkim2_publisher_login'@'%';" \
				"REVOKE UPDATE ON $database.dkim2_publication_lock FROM 'dkim2_publisher_login'@'%';" \
				"GRANT SELECT ON $database.dkim2_publication_lock TO 'dkim2_publisher_login'@'%';" \
				"GRANT UPDATE (singleton) ON $database.dkim2_publication_lock TO 'dkim2_publisher_login'@'%';"
			for table in dkim2_dataset_generations dkim2_current_generation \
				dkim2_handles dkim2_profiles \
				dkim2_credentials dkim2_policies dkim2_key_material; do
				printf '%s\n' \
					"GRANT SELECT ON $database.$table TO 'dkim2_publisher_login'@'%';" \
					"GRANT SELECT ON $database.$table TO 'dkim2_snapshot_login'@'%';" \
					"GRANT SELECT ON $database.$table TO 'dkim2_staging_login'@'%';" \
					"GRANT SELECT ON $database.$table TO 'dkim2_activation_login'@'%';"
			done
			for routine in dkim2_v2_insert_generation dkim2_v2_insert_handle \
				dkim2_v2_insert_profile dkim2_v2_insert_credential \
				dkim2_v2_insert_policy dkim2_v2_insert_key_material \
				dkim2_v2_seal_generation dkim2_v2_insert_current \
				dkim2_v2_update_current; do
				printf '%s\n' \
					"GRANT EXECUTE ON PROCEDURE $database.$routine TO 'dkim2_publisher_login'@'%';"
			done
			for routine in dkim2_v3_lock_observe dkim2_v3_lock_for_update \
				dkim2_v3_claim_lock dkim2_v3_release_lock \
				dkim2_v3_insert_generation dkim2_v3_insert_handle \
				dkim2_v3_insert_profile dkim2_v3_insert_credential \
				dkim2_v3_insert_policy dkim2_v3_insert_key_material \
				dkim2_v3_seal_generation; do
				printf '%s\n' \
					"GRANT EXECUTE ON PROCEDURE $database.$routine TO 'dkim2_staging_login'@'%';"
			done
			printf '%s\n' \
				"GRANT EXECUTE ON PROCEDURE $database.dkim2_v3_lock_observe TO 'dkim2_snapshot_login'@'%';" \
				"GRANT EXECUTE ON PROCEDURE $database.dkim2_v3_lock_observe TO 'dkim2_activation_login'@'%';" \
				"GRANT EXECUTE ON PROCEDURE $database.dkim2_v3_lock_for_update TO 'dkim2_activation_login'@'%';" \
				"GRANT EXECUTE ON PROCEDURE $database.dkim2_v3_current_for_update TO 'dkim2_activation_login'@'%';" \
				"GRANT EXECUTE ON PROCEDURE $database.dkim2_v3_lock_candidate_root TO 'dkim2_activation_login'@'%';" \
				"GRANT EXECUTE ON PROCEDURE $database.dkim2_v3_activate TO 'dkim2_activation_login'@'%';"
		done
		printf '%s\n' \
			'CREATE DATABASE dkim2_fresh CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;' \
			'USE dkim2_fresh;' \
			'SOURCE /run/dkim2/001_dkim2_mysql_datasource.sql;' \
			'SOURCE /run/dkim2/003_dkim2_mysql_onboarding.sql;' \
			'SOURCE /run/dkim2/002_dkim2_mysql_fresh_grants.sql;' \
			'CREATE TABLE dkim2_integration_ready (singleton BOOLEAN PRIMARY KEY);' \
			'INSERT INTO dkim2_integration_ready VALUES (TRUE);'
		printf '%s\n' 'FLUSH PRIVILEGES;'
	} >"$output"
	chmod 0644 "$output"
}

write_mysql_dataset "$mysql_password" 'synthetic-mysql-publisher-password' \
	"$work/mysql-dataset.sql"
write_mysql_dataset "$mariadb_password" 'synthetic-mariadb-publisher-password' \
	"$work/mariadb-dataset.sql"

cat >"$work/certs/ldap-admin-bootstrap.ldif" <<'EOF'
dn: dc=example,dc=test
objectClass: top
objectClass: organization
objectClass: dcObject
dc: example
o: example

dn: ou=services,dc=example,dc=test
objectClass: organizationalUnit
ou: services

dn: cn=dkim2-runtime,ou=services,dc=example,dc=test
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: dkim2-runtime
userPassword: synthetic-role-password

dn: cn=dkim2-snapshot,ou=services,dc=example,dc=test
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: dkim2-snapshot
userPassword: synthetic-role-password

dn: cn=dkim2-stager,ou=services,dc=example,dc=test
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: dkim2-stager
userPassword: synthetic-role-password

dn: cn=dkim2-activator,ou=services,dc=example,dc=test
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: dkim2-activator
userPassword: synthetic-role-password

dn: cn=dkim2-publisher,ou=services,dc=example,dc=test
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: dkim2-publisher
userPassword: synthetic-role-password

dn: ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
objectClass: dkim2AdministrationLock
ou: dkim2
dkim2AdminRevision: 1

dn: ou=generations,ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
ou: generations
EOF
chmod 0644 "$work/certs/ldap-admin-bootstrap.ldif"

cat >"$work/ldap-admin-entrypoint.sh" <<'EOF'
#!/bin/sh
set -eu
database=/tmp/dkim2-ldap-admin-db
configuration=/tmp/dkim2-ldap-admin.conf
mkdir -p "$database"
chmod 0700 "$database"
test -r /usr/lib/openldap/openldap/back_mdb.so
cat >"$configuration" <<'CONFIG'
include /etc/openldap/openldap/schema/core.schema
include /run/dkim2/rnsdkim2.schema
modulepath /usr/lib/openldap/openldap
moduleload back_mdb
pidfile /tmp/dkim2-ldap-admin.pid
argsfile /tmp/dkim2-ldap-admin.args
TLSCertificateFile /run/dkim2/ldap.integration.test.crt
TLSCertificateKeyFile /run/dkim2/ldap.integration.test.key
TLSCACertificateFile /run/dkim2/ca.crt
database mdb
maxsize 16777216
suffix dc=example,dc=test
rootdn cn=admin,dc=example,dc=test
rootpw synthetic-root-password
directory /tmp/dkim2-ldap-admin-db
CONFIG
cat /run/dkim2/acl.conf >>"$configuration"
slaptest -f "$configuration" -u
slapadd -f "$configuration" -l /run/dkim2/ldap-admin-bootstrap.ldif
exec slapd -f "$configuration" -h 'ldaps://0.0.0.0:636' -d 1 \
	>/tmp/dkim2-ldap-admin.log 2>&1
EOF
chmod 0755 "$work/ldap-admin-entrypoint.sh"

# start_ldap_admin starts the exact pinned administration service instance.
start_ldap_admin() {
	docker run -d --name "$ldap_admin_name" \
		-p 127.0.0.1::636 \
		--no-healthcheck \
		--add-host ldap.integration.test:127.0.0.1 \
		-v "$work/certs:/run/dkim2:ro" \
		-v "$work/ldap-admin-entrypoint.sh:/usr/local/bin/dkim2-ldap-admin-entrypoint.sh:ro" \
		--entrypoint /usr/local/bin/dkim2-ldap-admin-entrypoint.sh \
		"$ldap_image" >/dev/null
}

# capture_ldap_admin_failure persists only a bounded local diagnostic summary.
capture_ldap_admin_failure() {
	exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$ldap_admin_name" 2>/dev/null || printf '%s' unavailable)"
	raw_log="$work/ldap-admin.raw.log"
	docker cp "$ldap_admin_name:/tmp/dkim2-ldap-admin.log" "$raw_log" >/dev/null 2>&1 || true
	log_digest=unavailable
	error_class=process_lifecycle
	if test -f "$raw_log"; then
		if command -v sha256sum >/dev/null 2>&1; then
			log_digest="$(sha256sum "$raw_log" | awk '{print $1}')"
		else
			log_digest="$(shasum -a 256 "$raw_log" | awk '{print $1}')"
		fi
		if grep -Eqi 'TLS.*(error|failed|unable)|permission denied.*(key|certificate)' "$raw_log"; then
			error_class=tls_initialization
		elif grep -Eqi 'daemon: bind|address already in use|cannot bind' "$raw_log"; then
			error_class=listener_bind
		elif grep -Eqi 'database.*(error|failed)|mdb.*(error|failed)' "$raw_log"; then
			error_class=database_open
		elif grep -Eqi 'config.*(error|failed)|bad configuration' "$raw_log"; then
			error_class=configuration
		fi
	fi
	mkdir -p .artifacts/datasource-integration
	printf '%s\n' \
		"phase=openldap_admin_pid1" \
		"image=$ldap_image" \
		"exit=$exit_code" \
		"error_class=$error_class" \
		"raw_log_sha256=$log_digest" \
		>.artifacts/datasource-integration/ldap-admin-failure.txt
	echo "datasource integration: OpenLDAP administration unavailable class=$error_class exit=$exit_code log_sha256=$log_digest" >&2
}

# wait_ldap_admin proves the exact exec'd PID1, verified TLS identity, and role bind.
wait_ldap_admin() {
	attempt=0
	while test "$attempt" -lt 120; do
		if docker exec "$ldap_admin_name" /bin/sh -c \
			'test "$(cat /proc/1/comm)" = slapd' >/dev/null 2>&1 && \
			docker exec "$ldap_admin_name" env LDAPTLS_CACERT=/run/dkim2/ca.crt \
				ldapwhoami -x -H ldaps://ldap.integration.test:636 \
				-D 'cn=dkim2-runtime,ou=services,dc=example,dc=test' \
				-w synthetic-role-password >/dev/null 2>&1 && \
			docker exec "$ldap_admin_name" env LDAPTLS_CACERT=/run/dkim2/ca.crt \
				ldapsearch -x -LLL -H ldaps://ldap.integration.test:636 \
				-D 'cn=dkim2-runtime,ou=services,dc=example,dc=test' \
				-w synthetic-role-password -b 'ou=dkim2,dc=example,dc=test' \
				-s base '(objectClass=*)' 1.1 >/dev/null 2>&1; then
			return 0
		fi
		state="$(docker inspect --format '{{.State.Status}}' "$ldap_admin_name")"
		if test "$state" != running; then
			capture_ldap_admin_failure
			return 1
		fi
		attempt=$((attempt + 1))
		sleep 0.25
	done
	capture_ldap_admin_failure
	return 1
}

if test "${DKIM2_LDAP_ADMIN_PREFLIGHT_ONLY:-0}" = 1; then
	start_ldap_admin
	wait_ldap_admin
	echo 'datasource integration: OpenLDAP administration preflight pass'
	exit 0
fi

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

start_ldap_admin

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

docker run -d --name "$mysql_name" \
	-p 127.0.0.1::3306 \
	-e MYSQL_ROOT_PASSWORD='synthetic-mysql-admin-password' \
	-e MYSQL_ROOT_HOST='%' \
	-e DKIM2_TLS_NAME='mysql.integration.test' \
	-v "$work/certs:/run/dkim2:ro" \
	-v "$work/mysql-entrypoint.sh:/usr/local/bin/dkim2-entrypoint.sh:ro" \
	-v "$work/mysql-dataset.sql:/docker-entrypoint-initdb.d/30-dataset.sql:ro" \
	--entrypoint /usr/local/bin/dkim2-entrypoint.sh \
	"$mysql_image" mysqld \
	--ssl-ca=/tmp/dkim2-ca.crt --ssl-cert=/tmp/dkim2-mysql.crt \
	--ssl-key=/tmp/dkim2-mysql.key --require-secure-transport=ON >/dev/null

docker run -d --name "$mariadb_name" \
	-p 127.0.0.1::3306 \
	-e MARIADB_ROOT_PASSWORD='synthetic-mariadb-admin-password' \
	-e MARIADB_ROOT_HOST='%' \
	-e DKIM2_TLS_NAME='mariadb.integration.test' \
	-v "$work/certs:/run/dkim2:ro" \
	-v "$work/mysql-entrypoint.sh:/usr/local/bin/dkim2-entrypoint.sh:ro" \
	-v "$work/mariadb-dataset.sql:/docker-entrypoint-initdb.d/30-dataset.sql:ro" \
	--entrypoint /usr/local/bin/dkim2-entrypoint.sh \
	"$mariadb_image" mariadbd \
	--ssl-ca=/tmp/dkim2-ca.crt --ssl-cert=/tmp/dkim2-mysql.crt \
	--ssl-key=/tmp/dkim2-mysql.key --require-secure-transport=ON >/dev/null

# wait_healthy rejects exited, unhealthy, and unbounded service startup.
wait_healthy() {
	container=$1
	label=$2
	attempt=0
	while [ "$attempt" -lt 120 ]; do
		state="$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")"
		case "$state" in
		'running healthy'|'running ')
			return 0
			;;
		exited*|dead*)
			exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$container" 2>/dev/null || printf '%s' unavailable)"
			echo "datasource integration: $label startup failed state=$state exit=$exit_code" >&2
			return 1
			;;
		esac
		attempt=$((attempt + 1))
		sleep 0.25
	done
	echo "datasource integration: $label startup timed out state=$state" >&2
	return 1
}

wait_healthy "$ldap_name" openldap_runtime
echo 'datasource integration: OpenLDAP runtime readiness pass'
wait_ldap_admin
echo 'datasource integration: OpenLDAP administration PID1/TLS/role readiness pass'
wait_healthy "$postgresql_name" postgresql
echo 'datasource integration: PostgreSQL readiness pass'
wait_healthy "$mysql_name" mysql
echo 'datasource integration: MySQL readiness pass'
wait_healthy "$mariadb_name" mariadb
echo 'datasource integration: MariaDB readiness pass'

# wait_mysql_family waits for completed init scripts, not only a running process.
wait_mysql_family() {
	container=$1
	password=$2
	client=$3
	attempt=0
	while [ "$attempt" -lt 120 ]; do
		if docker exec "$container" "$client" -h127.0.0.1 -uroot "-p$password" -NBe \
			'SELECT COUNT(*) FROM dkim2_fresh.dkim2_integration_ready' 2>/dev/null | grep -qx 1; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 0.25
	done
	docker logs "$container" >&2 || true
	return 1
}

wait_mysql_family "$mysql_name" 'synthetic-mysql-admin-password' mysql
wait_mysql_family "$mariadb_name" 'synthetic-mariadb-admin-password' mariadb
if test "${DKIM2_SERVICES_PREFLIGHT_ONLY:-0}" = 1; then
	echo 'datasource integration: exact five-service startup preflight pass'
	exit 0
fi
ldap_port="$(docker port "$ldap_name" 636/tcp | sed -n 's/.*://p')"
ldap_admin_port="$(docker port "$ldap_admin_name" 636/tcp | sed -n 's/.*://p')"
postgresql_port="$(docker port "$postgresql_name" 5432/tcp | sed -n 's/.*://p')"
mysql_port="$(docker port "$mysql_name" 3306/tcp | sed -n 's/.*://p')"
mariadb_port="$(docker port "$mariadb_name" 3306/tcp | sed -n 's/.*://p')"
test -n "$ldap_port" && test -n "$ldap_admin_port" && test -n "$postgresql_port" && \
	test -n "$mysql_port" && test -n "$mariadb_port"
expected_sql_generation=1
qualification_runs=0

run_qualification() {
	sql_generation=$1
	if test "$sql_generation" != "$expected_sql_generation"; then
		echo 'datasource integration: SQL qualification phase order mismatch' >&2
		exit 1
	fi
	DKIM2_DATASOURCE_CA="$work/certs/ca.crt" \
	DKIM2_DATASOURCE_PUBLIC_SPKI="$work/credential.spki" \
	DKIM2_LDAP_PORT="$ldap_port" \
	DKIM2_LDAP_SERVER_NAME='ldap.integration.test' \
	DKIM2_LDAP_PASSWORD="$ldap_password" \
	DKIM2_POSTGRESQL_PORT="$postgresql_port" \
	DKIM2_POSTGRESQL_SERVER_NAME='postgresql.integration.test' \
	DKIM2_POSTGRESQL_PASSWORD="$postgresql_password" \
	DKIM2_MYSQL_PORT="$mysql_port" \
	DKIM2_MYSQL_SERVER_NAME='mysql.integration.test' \
	DKIM2_MYSQL_PASSWORD="$mysql_password" \
	DKIM2_MARIADB_PORT="$mariadb_port" \
	DKIM2_MARIADB_SERVER_NAME='mariadb.integration.test' \
	DKIM2_MARIADB_PASSWORD="$mariadb_password" \
	DKIM2_SQL_EXPECTED_GENERATION="$sql_generation" \
	GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test -tags=datasourceintegration \
			-run '^TestDisposableNetwork' -count=1 -timeout=45s \
			./internal/datasource/parity
	qualification_runs=$((qualification_runs + 1))
}

run_qualification 1
if test "${DKIM2_INITIAL_QUALIFICATION_ONLY:-0}" = 1; then
	echo 'datasource integration: initial provider qualification diagnostic pass'
	exit 0
fi
run_qualification 1
echo 'datasource integration: initial provider qualification pass'

for tuple in "$mysql_name:mysql" "$mariadb_name:mariadb"; do
	container=${tuple%%:*}
	client=${tuple#*:}
	docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 \
		-e "START TRANSACTION; CALL dkim2_v3_claim_lock(1, 'aebagbafaydqqcikbmga2dqpca'); ROLLBACK;"
done

DKIM2_DATASOURCE_CA="$work/certs/ca.crt" \
DKIM2_POSTGRESQL_PORT="$postgresql_port" \
DKIM2_POSTGRESQL_SERVER_NAME='postgresql.integration.test' \
DKIM2_MYSQL_PORT="$mysql_port" \
DKIM2_MYSQL_SERVER_NAME='mysql.integration.test' \
DKIM2_MARIADB_PORT="$mariadb_port" \
DKIM2_MARIADB_SERVER_NAME='mariadb.integration.test' \
DKIM2_SQL_SNAPSHOT_PASSWORD='synthetic-sql-snapshot-password' \
DKIM2_SQL_STAGING_PASSWORD='synthetic-sql-staging-password' \
DKIM2_SQL_ACTIVATION_PASSWORD='synthetic-sql-activation-password' \
DKIM2_POSTGRESQL_OBSERVER_PASSWORD='synthetic-postgresql-admin-password' \
DKIM2_MYSQL_OBSERVER_PASSWORD='synthetic-mysql-admin-password' \
DKIM2_MARIADB_OBSERVER_PASSWORD='synthetic-mariadb-admin-password' \
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
	go -C cmd/dkim2d test -tags=datasourceintegration \
		-run '^TestDisposableSQLAdministration$' -count=1 -timeout=90s \
		./internal/datasource/parity
echo 'datasource integration: SQL administration concurrency pass'
expected_sql_generation=4
run_qualification 4
echo 'datasource integration: post-administration provider qualification pass'

DKIM2_DATASOURCE_CA="$work/certs/ca.crt" \
DKIM2_LDAP_INTEGRATION_ADDRESS="127.0.0.1:$ldap_admin_port" \
DKIM2_LDAP_INTEGRATION_CA="$work/certs/ca.crt" \
DKIM2_LDAP_INTEGRATION_SERVER_NAME='ldap.integration.test' \
DKIM2_POSTGRESQL_PORT="$postgresql_port" \
DKIM2_POSTGRESQL_SERVER_NAME='postgresql.integration.test' \
DKIM2_POSTGRESQL_PASSWORD="$postgresql_password" \
DKIM2_MYSQL_PORT="$mysql_port" \
DKIM2_MYSQL_SERVER_NAME='mysql.integration.test' \
DKIM2_MYSQL_PASSWORD="$mysql_password" \
DKIM2_MARIADB_PORT="$mariadb_port" \
DKIM2_MARIADB_SERVER_NAME='mariadb.integration.test' \
DKIM2_MARIADB_PASSWORD="$mariadb_password" \
DKIM2_SQL_SNAPSHOT_PASSWORD='synthetic-sql-snapshot-password' \
DKIM2_SQL_STAGING_PASSWORD='synthetic-sql-staging-password' \
DKIM2_SQL_ACTIVATION_PASSWORD='synthetic-sql-activation-password' \
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
	go -C cmd/dkim2d test -tags=datasourceintegration \
		-run '^(TestDisposableSQLDomainOnboardingAndRuntimeSigning|TestLDAPOnboardingRealActivationAndReconcile)$' \
		-count=1 -timeout=120s ./internal/domainadmin
echo 'datasource integration: four-backend domain onboarding and activated signing pass'

expected_sql_generation=5
run_qualification 5
echo 'datasource integration: post-activation provider qualification pass'

postgresql_definer_audit="$(docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 \
	-U postgres -d dkim2 -Atqc "
WITH expected(name, kind, arguments) AS (
  VALUES
    ('administration_lock_observe', 'f', ''),
    ('administration_lock_for_update', 'f', ''),
    ('candidate_root_for_update', 'f', 'dkim2_datasource.generation_number, text, bytea'),
    ('administration_lock_claim', 'p', 'dkim2_datasource.generation_number, text'),
    ('administration_lock_release', 'p', 'dkim2_datasource.generation_number, text'),
    ('administration_lock_owned_by', 'f', 'text'),
    ('administration_lock_is_owned', 'f', ''),
    ('generation_is_version', 'f', 'dkim2_datasource.generation_number, text')
), actual AS (
  SELECT routine.oid, routine.proname AS name, routine.prokind::text AS kind,
         oidvectortypes(routine.proargtypes) AS arguments,
         owner_role.rolname AS owner_name, routine.prosecdef, routine.proconfig
    FROM pg_proc AS routine
    JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
    JOIN pg_roles AS owner_role ON owner_role.oid = routine.proowner
   WHERE namespace.nspname = 'dkim2_datasource'
     AND (routine.prosecdef OR routine.proname IN (SELECT name FROM expected))
), valid AS (
  SELECT actual.* FROM actual JOIN expected USING (name, kind, arguments)
   WHERE actual.owner_name = 'postgres' AND actual.prosecdef
     AND actual.proconfig = ARRAY['search_path=pg_catalog, dkim2_datasource']::text[]
)
SELECT concat_ws('|',
  (SELECT count(*) FROM valid),
  (SELECT count(*) FROM actual LEFT JOIN valid USING (oid) WHERE valid.oid IS NULL),
  (SELECT count(*) FROM expected LEFT JOIN valid USING (name, kind, arguments)
    WHERE valid.oid IS NULL)
);" 2>/dev/null)" || postgresql_definer_audit=unavailable
expect_equal postgresql-definer-routines "$postgresql_definer_audit" "8|0|0"

postgresql_acl_audit="$(docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 \
	-U postgres -d dkim2 -Atqc "
WITH expected_routine(name, kind, arguments) AS (
  VALUES
    ('administration_lock_observe', 'f', ''),
    ('administration_lock_for_update', 'f', ''),
    ('candidate_root_for_update', 'f', 'dkim2_datasource.generation_number, text, bytea'),
    ('administration_lock_claim', 'p', 'dkim2_datasource.generation_number, text'),
    ('administration_lock_release', 'p', 'dkim2_datasource.generation_number, text'),
    ('administration_lock_owned_by', 'f', 'text'),
    ('administration_lock_is_owned', 'f', ''),
    ('generation_is_version', 'f', 'dkim2_datasource.generation_number, text')
), expected_acl(name, grantee) AS (
  VALUES
    ('administration_lock_observe', 'postgres'),
    ('administration_lock_observe', 'dkim2_snapshot'),
    ('administration_lock_observe', 'dkim2_stager'),
    ('administration_lock_observe', 'dkim2_activator'),
    ('administration_lock_for_update', 'postgres'),
    ('administration_lock_for_update', 'dkim2_stager'),
    ('administration_lock_for_update', 'dkim2_activator'),
    ('candidate_root_for_update', 'postgres'),
    ('candidate_root_for_update', 'dkim2_activator'),
    ('administration_lock_claim', 'postgres'),
    ('administration_lock_claim', 'dkim2_stager'),
    ('administration_lock_release', 'postgres'),
    ('administration_lock_release', 'dkim2_stager'),
    ('administration_lock_owned_by', 'postgres'),
    ('administration_lock_owned_by', 'dkim2_stager'),
    ('administration_lock_owned_by', 'dkim2_activator'),
    ('administration_lock_is_owned', 'postgres'),
    ('administration_lock_is_owned', 'dkim2_activator'),
    ('generation_is_version', 'postgres'),
    ('generation_is_version', 'dkim2_publisher'),
    ('generation_is_version', 'dkim2_stager')
), routines AS (
  SELECT routine.oid, routine.proname AS name, routine.proowner,
         routine.proacl
    FROM pg_proc AS routine
    JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
    JOIN expected_routine AS expected
      ON expected.name = routine.proname
     AND expected.kind = routine.prokind::text
     AND expected.arguments = oidvectortypes(routine.proargtypes)
   WHERE namespace.nspname = 'dkim2_datasource'
), actual_acl AS (
  SELECT routines.name, coalesce(grantee.rolname, 'PUBLIC') AS grantee,
         expanded_acl.privilege_type
    FROM routines
    CROSS JOIN LATERAL aclexplode(
      coalesce(routines.proacl, acldefault('f', routines.proowner))
    ) AS expanded_acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid = expanded_acl.grantee
)
SELECT concat_ws('|',
  (SELECT count(*) FROM actual_acl JOIN expected_acl USING (name, grantee)
    WHERE privilege_type = 'EXECUTE'),
  (SELECT count(*) FROM actual_acl LEFT JOIN expected_acl USING (name, grantee)
    WHERE expected_acl.name IS NULL OR privilege_type <> 'EXECUTE'),
  (SELECT count(*) FROM expected_acl LEFT JOIN actual_acl USING (name, grantee)
    WHERE actual_acl.name IS NULL OR privilege_type <> 'EXECUTE')
);" 2>/dev/null)" || postgresql_acl_audit=unavailable
expect_equal postgresql-definer-acls "$postgresql_acl_audit" "21|0|0"

DKIM2_DATASOURCE_CA="$work/certs/ca.crt" \
DKIM2_LDAP_PORT="$ldap_port" \
DKIM2_POSTGRESQL_PORT="$postgresql_port" \
DKIM2_MYSQL_PORT="$mysql_port" \
DKIM2_MARIADB_PORT="$mariadb_port" \
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
	-c "BEGIN; SET ROLE dkim2_stager; CALL dkim2_datasource.administration_lock_claim(3, 'aibqibiga4eascqlbqgzav3y4m'); INSERT INTO dkim2_datasource.dataset_generations (generation, schema_version, dataset_state, operation_id, candidate_digest, was_active) VALUES (4, 'dkim2-datasource-v3', 'staging', 'aebagbafaydqqcikbmga2dqpca', decode(repeat('11', 32), 'hex'), FALSE); COMMIT;" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL stager accepted a foreign operation' >&2
	exit 1
fi
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "BEGIN; SET ROLE dkim2_stager; CALL dkim2_datasource.administration_lock_claim(3, 'aibqibiga4eascqlbqgy3dymc4'); INSERT INTO dkim2_datasource.handles VALUES (3, 'forbidden-post-seal'); COMMIT;" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL stager appended post-seal content' >&2
	exit 1
fi
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_activator; INSERT INTO dkim2_datasource.handles VALUES (3, 'forbidden-activator');" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL activator acquired content writes' >&2
	exit 1
fi
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_stager; SELECT * FROM dkim2_datasource.administration_lock;" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL stager acquired direct lock-table reads' >&2
	exit 1
fi
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_stager; UPDATE dkim2_datasource.administration_lock SET lock_operation_id = NULL WHERE singleton;" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL stager acquired direct lock-table writes' >&2
	exit 1
fi
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_snapshot; SELECT * FROM dkim2_datasource.administration_lock_for_update();" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL snapshot acquired physical lock authority' >&2
	exit 1
fi
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_activator; CALL dkim2_datasource.administration_lock_claim(3, 'aibqibiga4eascqlbqgzav3y4m');" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL activator acquired lock-claim authority' >&2
	exit 1
fi
postgresql_direct_candidate_lock="$(docker exec "$postgresql_name" psql \
	-v ON_ERROR_STOP=1 -U postgres -d dkim2 -Atqc \
	"SET ROLE dkim2_activator; SELECT EXISTS (SELECT 1 FROM dkim2_datasource.dataset_generations WHERE generation = 4 FOR UPDATE);" \
	2>/dev/null)" || postgresql_direct_candidate_lock=unavailable
expect_equal postgresql-direct-candidate-root-lock "$postgresql_direct_candidate_lock" f

for tuple in \
	"$mysql_name:mysql:synthetic-mysql-admin-password:$mysql_password" \
	"$mariadb_name:mariadb:synthetic-mariadb-admin-password:$mariadb_password"; do
	container=${tuple%%:*}
	remainder=${tuple#*:}
	client=${remainder%%:*}
	password_pair=${remainder#*:}
	password=${password_pair%%:*}
	runtime_password=${password_pair#*:}
	publisher_password=synthetic-mysql-publisher-password
	if test "$client" = mariadb; then
		publisher_password=synthetic-mariadb-publisher-password
	fi
	runtime_grants="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
		"SELECT SUM(PRIVILEGE_TYPE = 'SELECT'), SUM(PRIVILEGE_TYPE <> 'SELECT') FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA = 'dkim2' AND GRANTEE = CONCAT(CHAR(39), 'dkim2_runtime_login', CHAR(39), '@', CHAR(39), '%', CHAR(39))" 2>/dev/null)" || runtime_grants=unavailable
	expect_equal runtime-table-grants "$runtime_grants" "7	0"
	publisher_grants="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
		"SELECT SUM(PRIVILEGE_TYPE = 'SELECT'), SUM(PRIVILEGE_TYPE = 'INSERT'), SUM(PRIVILEGE_TYPE = 'UPDATE'), SUM(PRIVILEGE_TYPE NOT IN ('SELECT', 'INSERT', 'UPDATE')) FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA = 'dkim2_empty' AND GRANTEE = CONCAT(CHAR(39), 'dkim2_publisher_login', CHAR(39), '@', CHAR(39), '%', CHAR(39))" 2>/dev/null)" || publisher_grants=unavailable
	expect_equal publisher-table-grants "$publisher_grants" "8	0	0	0"
	publisher_allowlist="'dkim2_v2_insert_generation','dkim2_v2_insert_handle','dkim2_v2_insert_profile','dkim2_v2_insert_credential','dkim2_v2_insert_policy','dkim2_v2_insert_key_material','dkim2_v2_seal_generation','dkim2_v2_insert_current','dkim2_v2_update_current'"
	publisher_routines="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
		"SELECT SUM(Routine_type = 'PROCEDURE' AND Routine_name IN ($publisher_allowlist) AND Proc_priv = 'Execute'), SUM(Routine_type <> 'PROCEDURE' OR Routine_name NOT IN ($publisher_allowlist) OR Proc_priv <> 'Execute') FROM mysql.procs_priv WHERE Db = 'dkim2_empty' AND User = 'dkim2_publisher_login' AND Host = '%'" 2>/dev/null)" || publisher_routines=unavailable
	expect_equal publisher-routine-grants "$publisher_routines" "9	0"
	fresh_publisher_grants="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
		"SELECT SUM(PRIVILEGE_TYPE = 'SELECT'), SUM(PRIVILEGE_TYPE = 'INSERT'), SUM(PRIVILEGE_TYPE = 'UPDATE') FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA = 'dkim2_fresh' AND GRANTEE = CONCAT(CHAR(39), 'dkim2_publisher_login', CHAR(39), '@', CHAR(39), '%', CHAR(39))" 2>/dev/null)" || fresh_publisher_grants=unavailable
	expect_equal fresh-publisher-table-grants "$fresh_publisher_grants" "8	0	0"
	fresh_publisher_routines="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
		"SELECT SUM(Routine_type = 'PROCEDURE' AND Routine_name IN ($publisher_allowlist) AND Proc_priv = 'Execute'), SUM(Routine_type <> 'PROCEDURE' OR Routine_name NOT IN ($publisher_allowlist) OR Proc_priv <> 'Execute') FROM mysql.procs_priv WHERE Db = 'dkim2_fresh' AND User = 'dkim2_publisher_login' AND Host = '%'" 2>/dev/null)" || fresh_publisher_routines=unavailable
	expect_equal fresh-publisher-routine-grants "$fresh_publisher_routines" "9	0"
	for database in dkim2 dkim2_empty dkim2_fresh; do
		publisher_columns="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
			"SELECT SUM(PRIVILEGE_TYPE = 'UPDATE' AND TABLE_NAME = 'dkim2_publication_lock' AND COLUMN_NAME = 'singleton'), SUM(NOT (PRIVILEGE_TYPE = 'UPDATE' AND TABLE_NAME = 'dkim2_publication_lock' AND COLUMN_NAME = 'singleton')) FROM information_schema.COLUMN_PRIVILEGES WHERE TABLE_SCHEMA = '$database' AND GRANTEE = CONCAT(CHAR(39), 'dkim2_publisher_login', CHAR(39), '@', CHAR(39), '%', CHAR(39))" 2>/dev/null)" || publisher_columns=unavailable
		expect_equal publisher-column-grants "$publisher_columns" "1	0"
	done
	all_routine_allowlist="$publisher_allowlist,'dkim2_assert_staging','dkim2_assert_v2_staging','dkim2_assert_v3_operation','dkim2_assert_v3_metadata','dkim2_assert_v3_lock','dkim2_v3_lock_observe','dkim2_v3_lock_for_update','dkim2_v3_current_for_update','dkim2_v3_lock_candidate_root','dkim2_v3_insert_generation','dkim2_v3_claim_lock','dkim2_v3_release_lock','dkim2_v3_insert_handle','dkim2_v3_insert_profile','dkim2_v3_insert_credential','dkim2_v3_insert_policy','dkim2_v3_insert_key_material','dkim2_v3_seal_generation','dkim2_v3_activate'"
	for database in dkim2 dkim2_empty dkim2_fresh; do
		routine_definers="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
			"SELECT SUM(ROUTINE_NAME IN ($all_routine_allowlist) AND ROUTINE_TYPE = 'PROCEDURE' AND SECURITY_TYPE = 'DEFINER' AND DEFINER = 'root@localhost'), SUM(ROUTINE_NAME NOT IN ($all_routine_allowlist) OR ROUTINE_TYPE <> 'PROCEDURE' OR SECURITY_TYPE <> 'DEFINER' OR DEFINER <> 'root@localhost') FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = '$database' AND ROUTINE_NAME LIKE 'dkim2\\_%'" 2>/dev/null)" || routine_definers=unavailable
		expect_equal fixed-routine-definers "$routine_definers" "28	0"
	done
	for role_contract in snapshot:7:1 staging:7:11 activation:7:5; do
		role=${role_contract%%:*}
		counts=${role_contract#*:}
		table_count=${counts%%:*}
		routine_count=${counts#*:}
		case "$role" in
		snapshot)
			routine_allowlist="'dkim2_v3_lock_observe'"
			;;
		staging)
			routine_allowlist="'dkim2_v3_lock_observe','dkim2_v3_lock_for_update','dkim2_v3_claim_lock','dkim2_v3_release_lock','dkim2_v3_insert_generation','dkim2_v3_insert_handle','dkim2_v3_insert_profile','dkim2_v3_insert_credential','dkim2_v3_insert_policy','dkim2_v3_insert_key_material','dkim2_v3_seal_generation'"
			;;
		activation)
			routine_allowlist="'dkim2_v3_lock_observe','dkim2_v3_lock_for_update','dkim2_v3_current_for_update','dkim2_v3_lock_candidate_root','dkim2_v3_activate'"
			;;
		esac
		actual_tables="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
			"SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA = 'dkim2' AND PRIVILEGE_TYPE = 'SELECT' AND GRANTEE = CONCAT(CHAR(39), 'dkim2_${role}_login', CHAR(39), '@', CHAR(39), '%', CHAR(39))" 2>/dev/null)" || actual_tables=unavailable
		actual_routines="$(docker exec "$container" "$client" -uroot "-p$password" -NBe \
			"SELECT SUM(Routine_type = 'PROCEDURE' AND Routine_name IN ($routine_allowlist) AND Proc_priv = 'Execute'), SUM(Routine_type <> 'PROCEDURE' OR Routine_name NOT IN ($routine_allowlist) OR Proc_priv <> 'Execute') FROM mysql.procs_priv WHERE Db = 'dkim2' AND User = 'dkim2_${role}_login' AND Host = '%'" 2>/dev/null)" || actual_routines=unavailable
		expect_equal "$role-table-grants" "$actual_tables" "$table_count"
		expect_equal "$role-routine-grants" "$actual_routines" "$routine_count	0"
	done
	if docker exec "$container" "$client" -uroot "-p$password" dkim2 -NBe \
		"UPDATE dkim2_dataset_generations SET dataset_state = 'staging' WHERE generation = 1" \
		>/dev/null 2>&1; then
		echo 'datasource integration: committed MySQL-family generation was mutable' >&2
		exit 1
	fi
	if docker exec "$container" "$client" \
		-udkim2_runtime_login "-p$runtime_password" dkim2 -NBe \
		"INSERT INTO dkim2_handles VALUES (1, 'forbidden')" >/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family runtime role acquired write authority' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_publisher_login "-p$publisher_password" dkim2 -NBe \
		"UPDATE dkim2_publication_lock SET lock_revision = lock_revision + 1 WHERE singleton = 1" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family v2 publisher changed lock revision' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_publisher_login "-p$publisher_password" dkim2 -NBe \
		"UPDATE dkim2_publication_lock SET lock_operation_id = 'aebagbafaydqqcikbmga2dqpca' WHERE singleton = 1" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family v2 publisher changed v3 lock owner' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 -NBe \
		"START TRANSACTION; CALL dkim2_v3_claim_lock(3, 'aibqibiga4eascqlbqgzav3y4m'); CALL dkim2_v3_insert_generation(4, 'aibqibiga4eascqlbqgzav3y4ma', UNHEX(REPEAT('11', 32)), 3); COMMIT" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family accepted an overlong operation' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 -NBe \
		"START TRANSACTION; CALL dkim2_v3_claim_lock(3, 'aibqibiga4eascqlbqgzav3y4m'); CALL dkim2_v3_insert_generation(4, 'short', UNHEX(REPEAT('11', 32)), 3); COMMIT" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family accepted a short operation' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 -NBe \
		"START TRANSACTION; CALL dkim2_v3_claim_lock(3, 'aibqibiga4eascqlbqgzav3y4m'); CALL dkim2_v3_insert_generation(4, 'aibqibiga4eascqlbqgzav3y4m', UNHEX(REPEAT('11', 31)), 3); COMMIT" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family accepted a short digest' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 -NBe \
		"START TRANSACTION; CALL dkim2_v3_claim_lock(3, 'aibqibiga4eascqlbqgzav3y4m'); CALL dkim2_v3_insert_generation(4, 'aibqibiga4eascqlbqgzav3y4m', UNHEX(REPEAT('11', 33)), 3); COMMIT" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family accepted an overlong digest' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 -NBe \
		"SET @digest = UNHEX(REPEAT('11', 32)); START TRANSACTION; CALL dkim2_v3_claim_lock(3, 'aibqibiga4eascqlbqgzav3y4m'); CALL dkim2_v3_insert_generation(4, 'aibqibiga4eascqlbqgzav3y4m', @digest, 3); CALL dkim2_v3_insert_handle(4, 'forbidden-foreign', 'aebagbafaydqqcikbmga2dqpca', @digest, 3); COMMIT" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family stager accepted a foreign operation' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 -NBe \
		"SET @digest = (SELECT candidate_digest FROM dkim2_dataset_generations WHERE generation = 3); START TRANSACTION; CALL dkim2_v3_claim_lock(3, 'aibqibiga4eascqlbqgy3dymc4'); CALL dkim2_v3_insert_handle(3, 'forbidden-post-seal', 'aibqibiga4eascqlbqgy3dymc4', @digest, 3); COMMIT" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family stager appended post-seal content' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_activation_login -psynthetic-sql-activation-password dkim2 -NBe \
		"INSERT INTO dkim2_handles VALUES (3, 'forbidden-activator')" \
		>/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family activator acquired content writes' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_staging_login -psynthetic-sql-staging-password dkim2 -NBe \
		"SELECT * FROM dkim2_publication_lock" >/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family stager acquired direct lock-table reads' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_snapshot_login -psynthetic-sql-snapshot-password dkim2 -NBe \
		"CALL dkim2_v3_lock_for_update()" >/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family snapshot acquired physical lock authority' >&2
		exit 1
	fi
	if docker exec "$container" "$client" -h127.0.0.1 \
		-udkim2_activation_login -psynthetic-sql-activation-password dkim2 -NBe \
		"CALL dkim2_v3_claim_lock(3, 'aibqibiga4eascqlbqgzav3y4m')" >/dev/null 2>&1; then
		echo 'datasource integration: MySQL-family activator acquired lock-claim authority' >&2
		exit 1
	fi
done
if docker exec "$postgresql_name" psql -v ON_ERROR_STOP=1 -U postgres -d dkim2 \
	-c "SET ROLE dkim2_runtime; INSERT INTO dkim2_datasource.handles VALUES (1, 'forbidden');" \
	>/dev/null 2>&1; then
	echo 'datasource integration: PostgreSQL runtime role acquired write authority' >&2
	exit 1
fi

candidate="$(GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
	go -C "$repository_root/tools" run ./cmd/candidateid -root "$repository_root")"
report_candidate="$work/datasource-integration-report.json"
{
	printf '%s\n' \
		'{' \
		'  "schema": "dkim2.datasource-integration-report.v2",' \
		'  "base_revision": "92cd6ccb6f27c449939867914581e26ffe30186d",' \
		"  \"candidate_snapshot_sha256\": \"$candidate\"," \
		"  \"ldap_image\": \"$ldap_image\"," \
		"  \"postgresql_image\": \"$postgresql_image\"," \
		"  \"mysql_image\": \"$mysql_image\"," \
		"  \"mariadb_image\": \"$mariadb_image\"," \
		"  \"runtime_qualification_runs\": $qualification_runs," \
		'  "checks": [' \
		'    "ldap_parity_and_denials",' \
		'    "postgresql_parity_and_denials",' \
		'    "mysql_parity_and_denials",' \
		'    "mariadb_parity_and_denials",' \
		'    "ldap_absent_to_first_concurrency_fence",' \
		'    "postgresql_absent_to_first_concurrency_fence",' \
		'    "ldap_pointerless_nonempty_denial",' \
		'    "postgresql_pointerless_nonempty_denial",' \
		'    "mysql_absent_to_first_concurrency_fence",' \
		'    "mariadb_absent_to_first_concurrency_fence",' \
		'    "mysql_pointerless_nonempty_denial",' \
		'    "mariadb_pointerless_nonempty_denial",' \
		'    "postgresql_v2_to_v3_upgrade_and_two_rotations",' \
		'    "mysql_v2_to_v3_upgrade_and_two_rotations",' \
		'    "mariadb_v2_to_v3_upgrade_and_two_rotations",' \
		'    "postgresql_v3_observed_lock_contention_activation_race",' \
		'    "mysql_v3_observed_lock_contention_activation_race",' \
		'    "mariadb_v3_observed_lock_contention_activation_race",' \
		'    "postgresql_fresh_v3_bootstrap_and_rotation",' \
		'    "mysql_fresh_v3_bootstrap_and_rotation",' \
		'    "mariadb_fresh_v3_bootstrap_and_rotation",' \
		'    "sql_stage_replay_and_canonical_inspection",' \
		'    "sql_v3_runtime_digest_and_private_readback",' \
		'    "postgresql_exact_definer_routine_audit",' \
		'    "postgresql_exact_definer_acl_audit",' \
		'    "postgresql_direct_candidate_root_lock_denial",' \
		'    "mysql_fresh_and_upgrade_grant_routine_sets",' \
		'    "mariadb_fresh_and_upgrade_grant_routine_sets",' \
		'    "mysql_exact_publisher_and_admin_routine_allowlists",' \
		'    "mariadb_exact_publisher_and_admin_routine_allowlists",' \
		'    "mysql_fixed_routine_definer_allowlist",' \
		'    "mariadb_fixed_routine_definer_allowlist",' \
		'    "mysql_v2_publisher_singleton_column_lock_compatibility",' \
		'    "mariadb_v2_publisher_singleton_column_lock_compatibility",' \
		'    "mysql_v2_publisher_lock_metadata_write_denials",' \
		'    "mariadb_v2_publisher_lock_metadata_write_denials",' \
		'    "postgresql_stager_and_activator_denials",' \
		'    "mysql_stager_and_activator_denials",' \
		'    "mariadb_stager_and_activator_denials",' \
		'    "postgresql_direct_lock_table_denials",' \
		'    "mysql_direct_lock_table_denials",' \
		'    "mariadb_direct_lock_table_denials",' \
		'    "postgresql_snapshot_physical_lock_denial",' \
		'    "mysql_snapshot_physical_lock_denial",' \
		'    "mariadb_snapshot_physical_lock_denial",' \
		'    "postgresql_activator_claim_denial",' \
		'    "mysql_activator_claim_denial",' \
		'    "mariadb_activator_claim_denial",' \
		'    "mysql_operation_and_digest_coercion_denials",' \
		'    "mariadb_operation_and_digest_coercion_denials",' \
		'    "postgresql_committed_immutability",' \
		'    "postgresql_runtime_write_denial",' \
		'    "mysql_committed_immutability_and_runtime_write_denial",' \
		'    "mariadb_committed_immutability_and_runtime_write_denial"' \
		'  ],' \
		'  "results": [' \
		"    {\"image\": \"$ldap_image\", \"backend\": \"ldap\", \"check\": \"domain_onboarding_full_flow\", \"result\": \"pass\"}," \
		"    {\"image\": \"$ldap_image\", \"backend\": \"ldap\", \"check\": \"activated_runtime_signing\", \"result\": \"pass\"}," \
		"    {\"image\": \"$ldap_image\", \"backend\": \"ldap\", \"check\": \"app_signing_service_parity\", \"result\": \"pass\"}," \
		"    {\"image\": \"$postgresql_image\", \"backend\": \"postgresql\", \"check\": \"domain_onboarding_full_flow\", \"result\": \"pass\"}," \
		"    {\"image\": \"$postgresql_image\", \"backend\": \"postgresql\", \"check\": \"activated_runtime_signing\", \"result\": \"pass\"}," \
		"    {\"image\": \"$postgresql_image\", \"backend\": \"postgresql\", \"check\": \"app_signing_service_parity\", \"result\": \"pass\"}," \
		"    {\"image\": \"$mysql_image\", \"backend\": \"mysql\", \"check\": \"domain_onboarding_full_flow\", \"result\": \"pass\"}," \
		"    {\"image\": \"$mysql_image\", \"backend\": \"mysql\", \"check\": \"activated_runtime_signing\", \"result\": \"pass\"}," \
		"    {\"image\": \"$mysql_image\", \"backend\": \"mysql\", \"check\": \"app_signing_service_parity\", \"result\": \"pass\"}," \
		"    {\"image\": \"$mariadb_image\", \"backend\": \"mariadb\", \"check\": \"domain_onboarding_full_flow\", \"result\": \"pass\"}," \
		"    {\"image\": \"$mariadb_image\", \"backend\": \"mariadb\", \"check\": \"activated_runtime_signing\", \"result\": \"pass\"}," \
		"    {\"image\": \"$mariadb_image\", \"backend\": \"mariadb\", \"check\": \"app_signing_service_parity\", \"result\": \"pass\"}" \
		'  ],' \
		'  "overall": "pass"' \
		'}'
} >"$report_candidate"

validate_report_file "$report_candidate"
if ! publish_report "$report_candidate"; then
	echo 'datasource integration: report publication failed' >&2
	exit 1
fi
