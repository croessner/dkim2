#!/bin/sh
set -eu

EXIM=${EXIM:-exim}
SIGN_TRANSPORT=${SIGN_TRANSPORT:-dkim2_sign}
REVISE_TRANSPORT=${REVISE_TRANSPORT:-dkim2_revise}
DKIM2_BINARY=${DKIM2_BINARY:-/usr/libexec/dkim2-exim}
SIGN_CONFIG=${SIGN_CONFIG:-/etc/dkim2/sign.yaml}
REVISE_CONFIG=${REVISE_CONFIG:-/etc/dkim2/revise.yaml}
SERVICE_USER=${SERVICE_USER:-Debian-exim}
SERVICE_GROUP=${SERVICE_GROUP:-Debian-exim}
SOCKET_DIR=${SOCKET_DIR:-/run/dkim2-exim}
STATE_DIR=${STATE_DIR:-/var/lib/dkim2-exim}
EVIDENCE_DIR=${EVIDENCE_DIR:-/var/lib/dkim2-exim/evidence}
READINESS_DIR=${READINESS_DIR:-/run/dkim2-exim-readiness}

fail() {
	printf '%s\n' "dkim2-exim deployment validation failed" >&2
	exit 1
}

exact_line() {
	printf '%s\n' "$1" | grep -Fx -- "$2" >/dev/null || fail
}

reject_pattern() {
	printf '%s\n' "$1" | grep -Eq -- "$2" && fail
	return 0
}

spool=$("$EXIM" -bP spool_wireformat 2>/dev/null) || fail
local_scan=$("$EXIM" -bP local_scan 2>/dev/null) || fail
local_scan_timeout=$("$EXIM" -bP local_scan_timeout 2>/dev/null) || fail
sign=$("$EXIM" -bP transport "$SIGN_TRANSPORT" 2>/dev/null) || fail
revise=$("$EXIM" -bP transport "$REVISE_TRANSPORT" 2>/dev/null) || fail
configuration=$("$EXIM" -bP config 2>/dev/null) || fail

exact_line "$spool" "no_spool_wireformat"
exact_line "$local_scan" "dkim2_spool_format = unix_lf"
exact_line "$local_scan" "dkim2_socket = $SOCKET_DIR/local-scan.sock"
exact_line "$local_scan" "dkim2_timeout = 11s"
exact_line "$local_scan_timeout" "local_scan_timeout = 12s"
exact_line "$local_scan" "dkim2_failure_mode = tempfail"
exact_line "$local_scan" "dkim2_max_message_bytes = 33554432"

validate_transport() {
	value=$1
	expected_command=$2
	exact_line "$value" "driver = smtp"
	exact_line "$value" "transport_filter = $expected_command"
	exact_line "$value" "max_rcpt = 1"
	printf '%s\n' "$value" | grep -Eq '^size_addition = -[1-9][0-9]*$' || fail
	exact_line "$value" "transport_filter_timeout = 11s"
	exact_line "$value" "user = $SERVICE_USER"
	exact_line "$value" "group = $SERVICE_GROUP"
}

reject_transport_mutations() {
	name=$1
	printf '%s\n' "$configuration" | awk -v name="$name" '
		{
			line = $0
			sub(/^[[:space:]]+/, "", line)
		}
		line == name ":" { active = 1; next }
		active && line ~ /^[^:]+:$/ { active = 0 }
		active && line ~ /\$sender_address/ { found = 1 }
		active && line ~ /^(return_path|headers_add|headers_remove|headers_rewrite|command|shadow_transport|dkim_[A-Za-z0-9_]*|arc_[A-Za-z0-9_]*|return_path_add|delivery_date_add|envelope_to_add|message_prefix|message_suffix|body_only|headers_only)[[:space:]]*=/ { found = 1 }
		END { exit found ? 0 : 1 }
	' && fail
	return 0
}

validate_transport "$sign" "$DKIM2_BINARY --config $SIGN_CONFIG filter sign -- '\$dkim2_transport_filter_return_path' '\$pipe_addresses'"
validate_transport "$revise" "$DKIM2_BINARY --config $REVISE_CONFIG filter revise -- '\$local_scan_data' '\$dkim2_transport_filter_return_path' '\$pipe_addresses'"
reject_transport_mutations "$SIGN_TRANSPORT"
reject_transport_mutations "$REVISE_TRANSPORT"

for directory in "$SOCKET_DIR" "$STATE_DIR" "$EVIDENCE_DIR" "$READINESS_DIR"; do
	if state=$(stat -c '%a:%U:%G:%F' "$directory" 2>/dev/null); then
		test "$state" = "700:$SERVICE_USER:$SERVICE_GROUP:directory" || fail
	else
		state=$(stat -f '%Lp:%Su:%Sg' "$directory" 2>/dev/null) || fail
		test -d "$directory" || fail
		test "$state" = "700:$SERVICE_USER:$SERVICE_GROUP" || fail
	fi
done

printf '%s\n' "dkim2-exim deployment validation passed"
