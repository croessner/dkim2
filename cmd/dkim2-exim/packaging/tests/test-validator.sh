#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/../../../../" && pwd)
validator="$root/cmd/dkim2-exim/packaging/validate-deployment.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-exim-validator.XXXXXX")
trap 'rm -rf "$work"' 0 1 2 15
mkdir -m 0700 "$work/socket" "$work/state" "$work/state/evidence" "$work/readiness"
user=$(id -un)
group=$(id -gn)

write_fake() {
	size=$1
	raw_extra=${2:-}
	failure=${3:-tempfail}
	max_message=${4:-33554432}
	c_timeout=${5:-11s}
	local_timeout=${6:-12s}
	filter_timeout=${7:-11s}
	return_path_token=${8:-}
	if [ -z "$return_path_token" ]; then
		return_path_token='\$dkim2_transport_filter_return_path'
	fi
	cat >"$work/exim" <<EOF
#!/bin/sh
case "\$*" in
"-bP spool_wireformat") printf '%s\n' 'no_spool_wireformat' ;;
"-bP local_scan") printf '%s\n' 'dkim2_failure_mode = $failure' 'dkim2_max_message_bytes = $max_message' 'dkim2_spool_format = unix_lf' 'dkim2_socket = $work/socket/local-scan.sock' 'dkim2_timeout = $c_timeout' ;;
"-bP local_scan_timeout") printf '%s\n' 'local_scan_timeout = $local_timeout' ;;
"-bP transport dkim2_sign") printf '%s\n' 'driver = smtp' "transport_filter = /opt/dkim2-exim --config /etc/sign.yaml filter sign -- '$return_path_token' '\\\$pipe_addresses'" 'max_rcpt = 1' 'size_addition = $size' 'transport_filter_timeout = $filter_timeout' 'user = $user' 'group = $group' 'headers_add =' 'headers_remove =' 'return_path =' 'dkim_domain =' 'body_only = false' ;;
"-bP transport dkim2_revise") printf '%s\n' 'driver = smtp' "transport_filter = /opt/dkim2-exim --config /etc/revise.yaml filter revise -- '\\\$local_scan_data' '$return_path_token' '\\\$pipe_addresses'" 'max_rcpt = 1' 'size_addition = -1' 'transport_filter_timeout = $filter_timeout' 'user = $user' 'group = $group' 'headers_add =' 'headers_remove =' 'return_path =' 'dkim_domain =' 'body_only = false' ;;
"-bP config") printf '%s\n' '  dkim2_sign:' '    driver = smtp' '$raw_extra' '  dkim2_revise:' '    driver = smtp' ;;
*) exit 1 ;;
esac
EOF
	chmod 0700 "$work/exim"
}

run_validator() {
	EXIM="$work/exim" DKIM2_BINARY=/opt/dkim2-exim \
	SIGN_CONFIG=/etc/sign.yaml REVISE_CONFIG=/etc/revise.yaml \
	SERVICE_USER="$user" SERVICE_GROUP="$group" \
	SOCKET_DIR="$work/socket" STATE_DIR="$work/state" \
	EVIDENCE_DIR="$work/state/evidence" READINESS_DIR="$work/readiness" "$validator"
}

write_fake -1
run_validator >/dev/null
for forbidden_token in '\$return_path' '\${dkim2_transport_filter_return_path}' \
  '\$sender_address' \
  '\${lookup{unsafe}lsearch{/tmp/unsafe}}' '\${run{/bin/sh -c unsafe}{}}'; do
	write_fake -1 '' tempfail 33554432 11s 12s 11s "$forbidden_token"
	if run_validator >/dev/null 2>&1; then
		echo "validator accepted an unsafe transport filter return-path token" >&2
		exit 1
	fi
done
for invalid in -0 0 1 +1; do
	write_fake "$invalid"
	if run_validator >/dev/null 2>&1; then
		echo "validator accepted invalid size_addition" >&2
		exit 1
	fi
done
write_fake -1 '  headers_add = X-Bad: yes'
if run_validator >/dev/null 2>&1; then
	echo "validator accepted a post-filter mutation path" >&2
	exit 1
fi
chmod 0750 "$work/readiness"
if run_validator >/dev/null 2>&1; then
	echo "validator accepted unsafe readiness directory ownership/mode" >&2
	exit 1
fi
chmod 0700 "$work/readiness"
chmod 0750 "$work/state/evidence"
if run_validator >/dev/null 2>&1; then
	echo "validator accepted an unsafe evidence directory" >&2
	exit 1
fi
chmod 0700 "$work/state/evidence"
write_fake -1 'dkim2_revise:
  driver = smtp
  return_path ='
if run_validator >/dev/null 2>&1; then
	echo "validator accepted a revise transport return_path assignment" >&2
	exit 1
fi
write_fake -1 '  return_path ='
if run_validator >/dev/null 2>&1; then
	echo "validator accepted an explicit transport return_path assignment" >&2
	exit 1
fi
write_fake -1 '' fail_open
if run_validator >/dev/null 2>&1; then
	echo "validator accepted a non-tempfail C policy declaration" >&2
	exit 1
fi
write_fake -1 '' tempfail 33554431
if run_validator >/dev/null 2>&1; then
	echo "validator accepted a mismatched C message limit" >&2
	exit 1
fi
for timeout_case in c local filter; do
	case "$timeout_case" in
	c) write_fake -1 '' tempfail 33554432 10s 12s 11s ;;
	local) write_fake -1 '' tempfail 33554432 11s 11s 11s ;;
	filter) write_fake -1 '' tempfail 33554432 11s 12s 10s ;;
	esac
	if run_validator >/dev/null 2>&1; then
		echo "validator accepted a mismatched outer timeout" >&2
		exit 1
	fi
done
