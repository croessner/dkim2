#!/bin/sh

set -eu

# find_binary resolves one OpenLDAP server tool without weakening the gate.
find_binary() {
	name=$1
	for candidate in "$(command -v "$name" 2>/dev/null || true)" \
		"/usr/sbin/$name" \
		"/usr/local/opt/openldap/libexec/$name" "/opt/homebrew/opt/openldap/libexec/$name" \
		"/usr/local/opt/openldap/sbin/$name" "/opt/homebrew/opt/openldap/sbin/$name"; do
		if test -n "$candidate" && test -x "$candidate"; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done
	echo "LDAP ACL integration: missing $name" >&2
	return 1
}

slapd_bin=$(find_binary slapd)
slapadd_bin=$(find_binary slapadd)
ldapadd_bin=$(find_binary ldapadd)
ldapmodify_bin=$(find_binary ldapmodify)
ldapdelete_bin=$(find_binary ldapdelete)
ldapmodrdn_bin=$(find_binary ldapmodrdn)
ldapsearch_bin=$(find_binary ldapsearch)
ldapwhoami_bin=$(find_binary ldapwhoami)
openssl_bin=$(find_binary openssl)

core_schema=''
for candidate in /etc/ldap/schema/core.schema /etc/openldap/schema/core.schema \
	/usr/local/etc/openldap/schema/core.schema /opt/homebrew/etc/openldap/schema/core.schema; do
	if test -f "$candidate"; then
		core_schema=$candidate
		break
	fi
done
test -n "$core_schema" || {
	echo 'LDAP ACL integration: missing core.schema' >&2
	exit 1
}

work=$(mktemp -d /tmp/dkim2-ldap-acl.XXXXXX)
chmod 0700 "$work"
pid=''

# cleanup stops only the invocation-owned slapd and removes its disposable DB.
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if test -n "$pid"; then
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
	fi
	rm -rf "$work"
	exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$work/db"
port=$((20000 + ($$ % 30000)))
ldaps_port=$((port + 1))
uri="ldap://127.0.0.1:$port"
ldaps_uri="ldaps://127.0.0.1:$ldaps_port"

"$openssl_bin" req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
	-keyout "$work/ldap.key" -out "$work/ldap.crt" >/dev/null 2>&1
chmod 0600 "$work/ldap.key"

{
	printf '%s\n' \
		"include $core_schema" \
		"include $PWD/contrib/schema/ldap/rnsdkim2.schema" \
		"pidfile $work/slapd.pid" \
		"argsfile $work/slapd.args" \
		"TLSCertificateFile $work/ldap.crt" \
		"TLSCertificateKeyFile $work/ldap.key" \
		"TLSCACertificateFile $work/ldap.crt" \
		'database mdb' \
		'maxsize 16777216' \
		'suffix dc=example,dc=test' \
		'rootdn cn=admin,dc=example,dc=test' \
		'rootpw synthetic-root-password' \
		"directory $work/db"
	cat contrib/schema/ldap/acl.conf
} >"$work/slapd.conf"

cat >"$work/bootstrap.ldif" <<'EOF'
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

dn: cn=dkim2-purger,ou=services,dc=example,dc=test
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: dkim2-purger
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

"$slapadd_bin" -f "$work/slapd.conf" -l "$work/bootstrap.ldif" >/dev/null
"$slapd_bin" -f "$work/slapd.conf" -h "$uri $ldaps_uri" -d 0 >"$work/slapd.log" 2>&1 &
pid=$!

attempt=0
while ! "$ldapwhoami_bin" -x -H "$uri" -D 'cn=admin,dc=example,dc=test' \
	-w synthetic-root-password >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if test "$attempt" -ge 80 || ! kill -0 "$pid" 2>/dev/null; then
		cat "$work/slapd.log" >&2
		exit 1
	fi
	sleep 0.1
done

# role runs one LDAP client as an exact disposable service principal.
role() {
	principal=$1
	shift
	"$@" -x -H "$uri" -D "cn=dkim2-$principal,ou=services,dc=example,dc=test" \
		-w synthetic-role-password
}

# require_denied accepts only an LDAP authorization failure from a negative probe.
require_denied() {
	label=$1
	shift
	if "$@" >"$work/negative.out" 2>&1; then
		echo "LDAP ACL integration: unexpected authorization: $label" >&2
		exit 1
	fi
	if ! grep -Eq 'Insufficient access|no write access|result: 50' "$work/negative.out"; then
		echo "LDAP ACL integration: wrong negative outcome: $label" >&2
		sed -n '1,3p' "$work/negative.out" >&2
		exit 1
	fi
}

# require_failure_code freezes one expected non-authorization LDAP outcome.
require_failure_code() {
	label=$1
	pattern=$2
	shift 2
	if "$@" >"$work/negative.out" 2>&1; then
		echo "LDAP ACL integration: unexpected success: $label" >&2
		exit 1
	fi
	if ! grep -Eq "$pattern" "$work/negative.out"; then
		echo "LDAP ACL integration: wrong failure: $label" >&2
		sed -n '1,3p' "$work/negative.out" >&2
		exit 1
	fi
}

cat >"$work/generation-1.ldif" <<'EOF'
dn: dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: dkim2Dataset
objectClass: dkim2AdministrativeMetadata
cn: generation-1
dkim2SchemaVersion: dkim2-datasource-v3
dkim2Generation: 1
dkim2DatasetState: staging
dkim2OperationID: aibqibiga4eascqlbqgzav3y4m
dkim2CandidateDigest: 11111111111111111111111111111111
EOF
role stager "$ldapadd_bin" -f "$work/generation-1.ldif" >/dev/null

cat >"$work/generation-1-content.ldif" <<'EOF'
dn: ou=handles,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
ou: handles

dn: cn=record-1,ou=handles,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: dkim2Handle
cn: record-1
dkim2Generation: 1
dkim2HandleID: handle-1

dn: ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
ou: key-material

dn: cn=record-1,ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: dkim2KeyMaterial
cn: record-1
dkim2Generation: 1
dkim2TenantID: tenant
dkim2SigningDomain: example.test
dkim2ProfileUse: originator
dkim2HandleID: handle-1
dkim2Algorithm: ed25519-sha256
dkim2PublicKeySPKI: public-test-value
dkim2PrivateKeyPKCS8: private-test-value
EOF
role stager "$ldapadd_bin" -f "$work/generation-1-content.ldif" >/dev/null

"$ldapsearch_bin" -x -H "$uri" \
	-D 'cn=dkim2-snapshot,ou=services,dc=example,dc=test' -w synthetic-role-password \
	-LLL -b \
	'cn=record-1,ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' \
	-s base '(objectClass=dkim2KeyMaterial)' dkim2PrivateKeyPKCS8 2>/dev/null |
	grep -q '^dkim2PrivateKeyPKCS8:'

cat >"$work/seal-1.ldif" <<'EOF'
dn: dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2DatasetState
dkim2DatasetState: committed
EOF
role stager "$ldapmodify_bin" \
	-e '!assert=(&(dkim2SchemaVersion=dkim2-datasource-v3)(dkim2Generation=1)(dkim2DatasetState=staging)(dkim2OperationID=aibqibiga4eascqlbqgzav3y4m)(dkim2CandidateDigest=11111111111111111111111111111111)(!(dkim2WasActive=*)))' \
	-f "$work/seal-1.ldif" >/dev/null
"$ldapsearch_bin" -x -H "$uri" \
	-D 'cn=dkim2-stager,ou=services,dc=example,dc=test' -w synthetic-role-password \
	-LLL -b 'dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' \
	-s base '(objectClass=dkim2Dataset)' dkim2DatasetState 2>/dev/null |
	grep -q '^dkim2DatasetState: committed$'
"$ldapsearch_bin" -x -H "$uri" \
	-D 'cn=dkim2-stager,ou=services,dc=example,dc=test' -w synthetic-role-password \
	-LLL -b 'cn=record-1,ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' \
	-s base '(objectClass=dkim2KeyMaterial)' dkim2PrivateKeyPKCS8 2>/dev/null |
	grep -q '^dkim2PrivateKeyPKCS8:'
require_denied 'post-commit stager key delete' \
	"$ldapdelete_bin" -x -H "$uri" -D 'cn=dkim2-stager,ou=services,dc=example,dc=test' \
	-w synthetic-role-password \
	'cn=record-1,ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test'

cat >"$work/forbidden-content.ldif" <<'EOF'
dn: cn=forbidden,ou=handles,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: dkim2Handle
cn: forbidden
dkim2Generation: 1
dkim2HandleID: forbidden
EOF
require_denied 'post-commit stager add' role stager "$ldapadd_bin" -f "$work/forbidden-content.ldif"

cat >"$work/forbidden-root-metadata.ldif" <<'EOF'
dn: dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2OperationID
dkim2OperationID: aibqibiga4eascqlbqgzav3y4z
-
replace: dkim2CandidateDigest
dkim2CandidateDigest: 99999999999999999999999999999999
-
replace: dkim2SchemaVersion
dkim2SchemaVersion: dkim2-datasource-v2
-
replace: dkim2Generation
dkim2Generation: 9
EOF
require_denied 'post-commit stager root metadata modify' role stager "$ldapmodify_bin" -f "$work/forbidden-root-metadata.ldif"
require_denied 'post-commit stager root delete' \
	"$ldapdelete_bin" -x -H "$uri" -D 'cn=dkim2-stager,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test'

cat >"$work/current-1.ldif" <<'EOF'
dn: cn=current,ou=dkim2,dc=example,dc=test
objectClass: dkim2Dataset
objectClass: dkim2AdministrativeMetadata
cn: current
dkim2SchemaVersion: dkim2-datasource-v3
dkim2Generation: 1
dkim2DatasetState: committed
dkim2CandidateDigest: 11111111111111111111111111111111
EOF
require_denied 'stager current bootstrap Add' role stager "$ldapadd_bin" -f "$work/current-1.ldif"
role activator "$ldapadd_bin" -f "$work/current-1.ldif" >/dev/null
"$ldapsearch_bin" -x -H "$uri" \
	-D 'cn=dkim2-stager,ou=services,dc=example,dc=test' -w synthetic-role-password \
	-LLL -b 'cn=current,ou=dkim2,dc=example,dc=test' -s base '(objectClass=dkim2Dataset)' \
	dkim2SchemaVersion dkim2Generation dkim2DatasetState dkim2CandidateDigest 2>/dev/null |
	grep -q '^dkim2Generation: 1$'
require_failure_code 'second bootstrap current Add' 'Already exists|result: 68' \
	role activator "$ldapadd_bin" -f "$work/current-1.ldif"
cat >"$work/publisher-v3-current-core.ldif" <<'EOF'
dn: cn=current,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2Generation
dkim2Generation: 9
EOF
require_denied 'legacy publisher v3 current core modify' \
	role publisher "$ldapmodify_bin" -f "$work/publisher-v3-current-core.ldif"
require_denied 'stager current core modify' \
	role stager "$ldapmodify_bin" -f "$work/publisher-v3-current-core.ldif"
require_denied 'stager current delete' \
	"$ldapdelete_bin" -x -H "$uri" -D 'cn=dkim2-stager,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'cn=current,ou=dkim2,dc=example,dc=test'
require_denied 'stager current rename' \
	"$ldapmodrdn_bin" -x -H "$uri" -D 'cn=dkim2-stager,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'cn=current,ou=dkim2,dc=example,dc=test' 'cn=current-renamed'
require_denied 'activator current delete' \
	"$ldapdelete_bin" -x -H "$uri" -D 'cn=dkim2-activator,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'cn=current,ou=dkim2,dc=example,dc=test'
require_denied 'legacy publisher current delete' \
	"$ldapdelete_bin" -x -H "$uri" -D 'cn=dkim2-publisher,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'cn=current,ou=dkim2,dc=example,dc=test'
require_denied 'activator current rename' \
	"$ldapmodrdn_bin" -x -H "$uri" -D 'cn=dkim2-activator,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'cn=current,ou=dkim2,dc=example,dc=test' 'cn=current-renamed'

cat >"$work/mark-active.ldif" <<'EOF'
dn: dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
changetype: modify
add: dkim2WasActive
dkim2WasActive: TRUE
EOF
role activator "$ldapmodify_bin" -f "$work/mark-active.ldif" >/dev/null

cat >"$work/activator-forbidden.ldif" <<'EOF'
dn: dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2CandidateDigest
dkim2CandidateDigest: 99999999999999999999999999999999
EOF
require_denied 'activator candidate mutation' role activator "$ldapmodify_bin" -f "$work/activator-forbidden.ldif"

cat >"$work/generation-2.ldif" <<'EOF'
dn: dkim2Generation=2,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: dkim2Dataset
objectClass: dkim2AdministrativeMetadata
cn: generation-2
dkim2SchemaVersion: dkim2-datasource-v3
dkim2Generation: 2
dkim2DatasetState: staging
dkim2OperationID: aibqibiga4eascqlbqgzav3y4n
dkim2CandidateDigest: 22222222222222222222222222222222
EOF
role stager "$ldapadd_bin" -f "$work/generation-2.ldif" >/dev/null
cat >"$work/unit-2.ldif" <<'EOF'
dn: ou=handles,dkim2Generation=2,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
ou: handles
EOF
require_denied 'legacy publisher v3 mutation' role publisher "$ldapadd_bin" -f "$work/unit-2.ldif"
role stager "$ldapadd_bin" -f "$work/unit-2.ldif" >/dev/null

cat >"$work/seal-2.ldif" <<'EOF'
dn: dkim2Generation=2,ou=generations,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2DatasetState
dkim2DatasetState: committed
EOF
role stager "$ldapmodify_bin" \
	-e '!assert=(&(dkim2SchemaVersion=dkim2-datasource-v3)(dkim2Generation=2)(dkim2DatasetState=staging)(dkim2OperationID=aibqibiga4eascqlbqgzav3y4n)(dkim2CandidateDigest=22222222222222222222222222222222)(!(dkim2WasActive=*)))' \
	-f "$work/seal-2.ldif" >/dev/null

cat >"$work/current-2.ldif" <<'EOF'
dn: cn=current,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2Generation
dkim2Generation: 2
-
replace: dkim2CandidateDigest
dkim2CandidateDigest: 22222222222222222222222222222222
EOF
role activator "$ldapmodify_bin" \
	-e '!assert=(&(dkim2SchemaVersion=dkim2-datasource-v3)(dkim2Generation=1)(dkim2DatasetState=committed)(dkim2CandidateDigest=11111111111111111111111111111111)(!(dkim2OperationID=*))(!(dkim2WasActive=*)))' \
	-f "$work/current-2.ldif" >/dev/null
require_failure_code 'stale current assertion' 'Assertion Failed|result: 122' \
	role activator "$ldapmodify_bin" \
	-e '!assert=(&(dkim2SchemaVersion=dkim2-datasource-v3)(dkim2Generation=1)(dkim2DatasetState=committed)(dkim2CandidateDigest=11111111111111111111111111111111))' \
	-f "$work/current-2.ldif"
"$ldapsearch_bin" -x -H "$uri" \
	-D 'cn=dkim2-snapshot,ou=services,dc=example,dc=test' -w synthetic-role-password \
	-LLL -b 'cn=current,ou=dkim2,dc=example,dc=test' -s base '(objectClass=dkim2Dataset)' \
	dkim2Generation 2>/dev/null | grep -q '^dkim2Generation: 2$'

# Direct purger-bind abuse proof: it cannot touch current or unrelated entries,
# while an explicit interrupted noncurrent v3 tree is safely completed leaf-first.
require_denied 'purger current generation delete' \
	"$ldapdelete_bin" -x -H "$uri" -D 'cn=dkim2-purger,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'dkim2Generation=2,ou=generations,ou=dkim2,dc=example,dc=test'
require_denied 'purger unrelated service delete' \
	"$ldapdelete_bin" -x -H "$uri" -D 'cn=dkim2-purger,ou=services,dc=example,dc=test' \
	-w synthetic-role-password 'cn=dkim2-runtime,ou=services,dc=example,dc=test'
role purger "$ldapdelete_bin" 'cn=record-1,ou=handles,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' >/dev/null
role purger "$ldapdelete_bin" 'cn=record-1,ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' >/dev/null
role purger "$ldapdelete_bin" 'ou=handles,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' >/dev/null
role purger "$ldapdelete_bin" 'ou=key-material,dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' >/dev/null
role purger "$ldapdelete_bin" 'dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' >/dev/null
require_failure_code 'purger root absence after leaf-first reconciliation' 'No such object|result: 32' \
	role purger "$ldapsearch_bin" -LLL -b 'dkim2Generation=1,ou=generations,ou=dkim2,dc=example,dc=test' -s base '(objectClass=*)' 1.1

cat >"$work/generation-3-v2.ldif" <<'EOF'
dn: dkim2Generation=3,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: dkim2Dataset
cn: generation-3
dkim2SchemaVersion: dkim2-datasource-v2
dkim2Generation: 3
dkim2DatasetState: staging
EOF
role publisher "$ldapadd_bin" -f "$work/generation-3-v2.ldif" >/dev/null
cat >"$work/unit-3-v2.ldif" <<'EOF'
dn: ou=handles,dkim2Generation=3,ou=generations,ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
ou: handles
EOF
role publisher "$ldapadd_bin" -f "$work/unit-3-v2.ldif" >/dev/null
cat >"$work/seal-3-v2.ldif" <<'EOF'
dn: dkim2Generation=3,ou=generations,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2DatasetState
dkim2DatasetState: committed
EOF
role publisher "$ldapmodify_bin" \
	-e '!assert=(&(dkim2SchemaVersion=dkim2-datasource-v2)(dkim2Generation=3)(dkim2DatasetState=staging)(!(dkim2CandidateDigest=*))(!(dkim2OperationID=*)))' \
	-f "$work/seal-3-v2.ldif" >/dev/null

cat >"$work/claim.ldif" <<'EOF'
dn: ou=dkim2,dc=example,dc=test
changetype: modify
add: dkim2AdminLockOwner
dkim2AdminLockOwner: aibqibiga4eascqlbqgzav3y4m
EOF
role stager "$ldapmodify_bin" \
	-e '!assert=(&(dkim2AdminRevision=1)(!(dkim2AdminLockOwner=*)))' \
	-f "$work/claim.ldif" >/dev/null

cat >"$work/steal.ldif" <<'EOF'
dn: ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2AdminLockOwner
dkim2AdminLockOwner: aibqibiga4eascqlbqgzav3y4z
EOF
if role stager "$ldapmodify_bin" \
	-e '!assert=(&(dkim2AdminRevision=1)(!(dkim2AdminLockOwner=*)))' \
	-f "$work/steal.ldif" >/dev/null 2>&1; then
	echo 'LDAP ACL integration: crash-held lock was stolen' >&2
	exit 1
fi

cat >"$work/release.ldif" <<'EOF'
dn: ou=dkim2,dc=example,dc=test
changetype: modify
delete: dkim2AdminLockOwner
dkim2AdminLockOwner: aibqibiga4eascqlbqgzav3y4m
-
replace: dkim2AdminRevision
dkim2AdminRevision: 2
EOF
role stager "$ldapmodify_bin" \
	-e '!assert=(&(dkim2AdminRevision=1)(dkim2AdminLockOwner=aibqibiga4eascqlbqgzav3y4m))' \
	-f "$work/release.ldif" >/dev/null

# A fresh exact v2 current remains bootstrap-compatible for the isolated
# legacy publisher after all v3 denial and activation probes are complete.
"$ldapdelete_bin" -x -H "$uri" -D 'cn=admin,dc=example,dc=test' \
	-w synthetic-root-password 'cn=current,ou=dkim2,dc=example,dc=test' >/dev/null
cat >"$work/current-v2.ldif" <<'EOF'
dn: cn=current,ou=dkim2,dc=example,dc=test
objectClass: dkim2Dataset
cn: current
dkim2SchemaVersion: dkim2-datasource-v2
dkim2Generation: 3
dkim2DatasetState: committed
EOF
role publisher "$ldapadd_bin" -f "$work/current-v2.ldif" >/dev/null
cat >"$work/current-v2-modify.ldif" <<'EOF'
dn: cn=current,ou=dkim2,dc=example,dc=test
changetype: modify
replace: dkim2Generation
dkim2Generation: 3
EOF
role publisher "$ldapmodify_bin" -f "$work/current-v2-modify.ldif" >/dev/null

# Reset only the disposable product subtree, then run the actual Go
# Administrator and domain coordinator across verified LDAPS role sessions.
"$ldapdelete_bin" -x -H "$uri" -D 'cn=admin,dc=example,dc=test' \
	-w synthetic-root-password -r 'ou=dkim2,dc=example,dc=test' >/dev/null
cat >"$work/go-base.ldif" <<'EOF'
dn: ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
objectClass: dkim2AdministrationLock
ou: dkim2
dkim2AdminRevision: 1

dn: ou=generations,ou=dkim2,dc=example,dc=test
objectClass: organizationalUnit
ou: generations
EOF
"$ldapadd_bin" -x -H "$uri" -D 'cn=admin,dc=example,dc=test' \
	-w synthetic-root-password -f "$work/go-base.ldif" >/dev/null
env DKIM2_LDAP_INTEGRATION_ADDRESS="127.0.0.1:$ldaps_port" \
	DKIM2_LDAP_INTEGRATION_CA="$work/ldap.crt" \
	GOCACHE=/tmp/dkim2-go-build-cache \
	go test -count=1 -run '^TestLDAPOnboardingRealActivationAndReconcile$' \
	./cmd/dkim2d/internal/domainadmin

echo 'LDAP ACL integration: pass'
