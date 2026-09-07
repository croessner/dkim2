#!/usr/bin/env python3
"""Exercise actual observation admission and compare only opaque state digests in the isolated lane."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import math
from pathlib import Path
import secrets
import socket
import ssl
import time


class Probe:
    """Own verified local fixture HTTP requests without exposing credentials or observation bodies."""

    def __init__(self, username, password_file):
        password = Path(password_file).read_bytes()
        if not 1 <= len(password) <= 1024:
            raise RuntimeError('invalid fixture credential length')
        self.authorization = 'Basic ' + base64.b64encode(username.encode() + b':' + password).decode()
        self.tls = ssl.create_default_context(cafile='/certs/policy-e2e-ca.crt')
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3

    def send(self, body):
        """Send one immutable request over the actual Nauthilus Policy route."""
        connection = http.client.HTTPSConnection('nauthilus-policy', 9443, context=self.tls, timeout=5)
        try:
            connection.request('POST', '/api/v1/policy/decisions', body=body,
                headers={'Authorization': self.authorization, 'Content-Type': 'application/json',
                    'Accept': 'application/json', 'Cache-Control': 'no-store'})
            response = connection.getresponse()
            data = response.read(65537)
            if len(data) > 65536:
                raise RuntimeError('oversized fixture Policy response')
            return response.status, json.loads(data)
        finally:
            connection.close()


def observation(source, signal, subjects, age_seconds=0):
    """Construct one stable event whose retries retain timestamp, IDs and canonical bytes."""
    value = {'version': '1', 'request_id': secrets.token_hex(16),
        'target': {'namespace': 'reputation', 'action': 'observe'},
        'resource': {'type': 'reputation-observation', 'attributes': {
            'reputation.event_id': {'string': source + '.' + secrets.token_hex(32)},
            'reputation.observed_at': {'timestamp': (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).isoformat(timespec='seconds').replace('+00:00', 'Z')},
            'reputation.signal': {'string': signal}, 'reputation.magnitude': {'double': 1.0},
            'reputation.subjects': {'records': [{'fields': [
                {'name': key, 'value': {'string': subject[key]}} for key in ('role', 'kind', 'value')
            ]} for subject in subjects]}}},
        'environment': {'service': 'rspamd', 'instance': 'isolated-fixture', 'protocol': 'milter'},
        'options': {'include_diagnostics': False}}
    return json.dumps(value, separators=(',', ':')).encode()


def seed(args):
    """Admit explicit fixture signer/IP evidence and let the real trusted GeoIP provider derive network/ASN."""
    probe = Probe('FixtureSeeder', args.password_file)
    subjects = [{'role': 'smtp_peer', 'kind': 'ip', 'value': args.peer},
        {'role': 'signer', 'kind': 'dns_domain', 'value': args.domain}]
    if args.signer_only:
        subjects = [subjects[1]]
    for _ in range(args.count):
        body = observation('fixture_seed', args.signal, subjects, args.age_seconds)
        for attempt in range(3):
            status, value = probe.send(body)
            if status == 200 and value.get('effect') == 'permit' and value.get('status', {}).get('code') == 'permit':
                break
            if status == 200 and value.get('status', {}).get('retryable') is True and attempt < 2:
                time.sleep(0.2)
                continue
            raise RuntimeError(f'fixture seed admission failed: HTTP {status}, effect {value.get("effect")}')
    print(f'fixture_seed_events={args.count}')


def require_rejected(probe, body):
    """Require explicit admission rejection rather than accepting transport uncertainty as proof."""
    status, response = probe.send(body)
    if not (status in (400, 403, 422) or status == 200 and response.get('effect') == 'deny'):
        raise RuntimeError('forbidden evidence did not receive an explicit rejection')


def forbidden(args):
    """Prove caller-derived identity and causality never become learning evidence."""
    probe = Probe('ScanWriter', args.password_file)
    snapshot = RedisSnapshot()
    try:
        before = snapshot.digest()
        for kind, value in [('network', '203.0.113.0/24'), ('asn', '64500')]:
            body = observation('scan', 'mail.rspamd.clean', [{'role': 'smtp_peer', 'kind': kind, 'value': value}])
            require_rejected(probe, body)
        for field in ('causality', 'independent', 'policy_influenced', 'evidence_origin', 'source_policy_id'):
            value = json.loads(observation('scan', 'mail.rspamd.clean',
                [{'role': 'smtp_peer', 'kind': 'ip', 'value': args.peer}]))
            value['resource']['attributes']['reputation.' + field] = {'string': 'forged'}
            require_rejected(probe, json.dumps(value, separators=(',', ':')).encode())
        if snapshot.digest() != before:
            raise RuntimeError('rejected caller evidence changed learned state')
    finally:
        snapshot.close()
    print('rspamd_caller_network_asn_causality_rejection=PASS rejected_evidence_state_unchanged=PASS')


class RedisSnapshot:
    """Read only the invocation-owned Nauthilus database through a bounded RESP decoder."""

    def __init__(self):
        self.socket = socket.create_connection(('redis', 6379), timeout=5)
        self.stream = self.socket.makefile('rb')
        self.command('SELECT', '1')

    def command(self, *args):
        """Encode explicit read-only fixture commands without shell interpolation."""
        parts = [f'*{len(args)}\r\n'.encode()]
        for argument in args:
            value = str(argument).encode()
            parts.extend([f'${len(value)}\r\n'.encode(), value, b'\r\n'])
        self.socket.sendall(b''.join(parts))
        return self.read()

    def read(self, depth=0):
        """Bound every nested array and bulk field before allocation."""
        if depth > 4:
            raise RuntimeError('oversized fixture Redis nesting')
        line = self.stream.readline(1024)
        if not line.endswith(b'\r\n'):
            raise RuntimeError('invalid fixture Redis framing')
        kind, value = line[:1], line[1:-2]
        if kind == b'+':
            return value.decode()
        if kind == b':':
            return int(value)
        if kind == b'$':
            size = int(value)
            if not 0 <= size <= 262144:
                raise RuntimeError('invalid fixture Redis bulk size')
            payload = self.stream.read(size + 2)
            if len(payload) != size + 2 or not payload.endswith(b'\r\n'):
                raise RuntimeError('truncated fixture Redis response')
            return payload[:-2].decode()
        if kind == b'*':
            size = int(value)
            if not 0 <= size <= 4096:
                raise RuntimeError('invalid fixture Redis array size')
            return [self.read(depth + 1) for _ in range(size)]
        raise RuntimeError('fixture Redis request failed')

    def digest(self):
        """Hash bounded learned state only; never retain or report manifests, plaintext observations or ciphertext."""
        cursor, keys = '0', set()
        for _ in range(128):
            cursor, page = self.command('SCAN', cursor, 'MATCH', '*reputation:*:state:*', 'COUNT', '100')
            keys.update(page)
            if len(keys) > 4096:
                raise RuntimeError('fixture state exceeds key limit')
            if cursor == '0':
                break
        else:
            raise RuntimeError('fixture state scan exceeds iteration limit')
        state = {}
        for key in sorted(keys):
            fields = self.command('HGETALL', key)
            state[key] = dict(zip(fields[::2], fields[1::2]))
        risk = sum(float(fields.get('operational_mail_filter_risk', 0)) for fields in state.values())
        if not math.isfinite(risk) or risk < 0:
            raise RuntimeError('invalid fixture risk aggregate')
        return {'mail_risk_mass': risk, 'state_keys': len(keys), 'state_digest': hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()}

    def close(self):
        """Release only this read-only fixture connection."""
        self.stream.close()
        self.socket.close()


class OutboxSnapshot(RedisSnapshot):
    """Read only fixed queue ledgers and due indexes using a separate TLS inspection principal."""

    def __init__(self):
        tls = ssl.create_default_context(cafile='/certs/policy-e2e-ca.crt')
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.socket = tls.wrap_socket(socket.create_connection(('outbox-redis', 6379), timeout=5),
            server_hostname='outbox-redis')
        self.stream = self.socket.makefile('rb')
        password = Path('/probe/outbox-inspection-password').read_text()
        if len(password) != 64:
            raise RuntimeError('invalid fixture inspection credential')
        self.command('AUTH', 'inspector', password)

    def empty(self):
        """Require zero capacity and no due members for every fixed shard, without scanning event records."""
        for shard in range(4):
            prefix = f'dkim2:observation:v1:{{{shard}}}:'
            ledger = self.command('HGETALL', prefix + 'capacity')
            due = self.command('ZCARD', prefix + 'due')
            if ledger not in ([], ['total_encrypted_bytes', '0']) or due != 0:
                return False
        return True


def main():
    """Expose a closed local fixture command set without production connection options."""
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['seed', 'forbidden', 'snapshot', 'outbox-empty'])
    parser.add_argument('--password-file')
    parser.add_argument('--peer', default='203.0.113.25')
    parser.add_argument('--domain', default='example.test')
    parser.add_argument('--count', type=int, default=3)
    parser.add_argument('--signal', choices=['fixture.seed', 'fixture.risk'], default='fixture.seed')
    parser.add_argument('--signer-only', action='store_true')
    parser.add_argument('--age-seconds', type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.age_seconds <= 86400:
        parser.error('age must be between zero and one day')
    if not 1 <= args.count <= 100:
        parser.error('count must be between 1 and 100')
    if args.operation in ('snapshot', 'outbox-empty'):
        snapshot = RedisSnapshot() if args.operation == 'snapshot' else OutboxSnapshot()
        try:
            if args.operation == 'outbox-empty':
                if not snapshot.empty():
                    raise SystemExit(1)
            else:
                print(json.dumps(snapshot.digest(), sort_keys=True))
        finally:
            snapshot.close()
    elif args.operation == 'seed':
        seed(args)
    else:
        forbidden(args)


if __name__ == '__main__':
    main()
