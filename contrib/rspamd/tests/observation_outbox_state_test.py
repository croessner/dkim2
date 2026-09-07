#!/usr/bin/env python3
"""Exercise the separate observation state machine against an invocation-owned Redis."""
import concurrent.futures
import json
import re
import secrets
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

MODULE = Path(sys.argv.pop(1)).resolve()
CLUSTER = "--cluster" in sys.argv
if CLUSTER:
    sys.argv.remove("--cluster")

class OutboxStateTest(unittest.TestCase):
    """Verify actual Redis atomicity, bounded storage and fenced ownership."""
    def setUp(self):
        """Allocate only a private Unix socket and synthetic encrypted records."""
        self.directory = tempfile.TemporaryDirectory(prefix='dkim2-observation-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.socket = self.root / 'redis.sock'
        self.script = self.root / 'outbox.lua'
        result = subprocess.run(['lua','-', str(MODULE)], input=b'io.write(assert(loadfile(arg[1]))().redis_script)', capture_output=True, check=True)
        self.script.write_bytes(result.stdout)
        self.start_redis()
        self.prefix = 'dkim2:observation:v1:{0}:'
        self.settings = dict(max_records=2,max_bytes=2048,max_age_ms=60000,lease_ms=1000,max_attempts=3,backoff_min_ms=100,backoff_max_ms=1000,jitter_ms=20,tombstone_limit=2,tombstone_ttl_ms=1000)
        self.tag = 'a'*64
        self.payload = dict(allocation_tag=self.tag,payload_fingerprint='f'*64,key_id='active',nonce='b'*48,ciphertext='c'*128)

    def start_redis(self):
        """Bind the standalone store only to this invocation's private Unix socket."""
        self.server = subprocess.Popen(['redis-server','--port','0','--unixsocket',str(self.socket),'--unixsocketperm','700','--save','','--appendonly','no'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.cleanup_server)
        for _ in range(100):
            if self.socket.exists():
                break
            time.sleep(0.01)
        self.command=['redis-cli','--json','-s',str(self.socket)]

    def cleanup_server(self):
        """Stop only this test's Redis and remove its private files."""
        self.server.terminate()
        self.server.wait(timeout=5)
        self.directory.cleanup()

    def redis(self,*args):
        """Return typed Redis output without network or live configuration."""
        output=subprocess.check_output([*self.command,*map(str,args)])
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            raise AssertionError(f'invocation-owned Redis returned a non-JSON response: {output[:240]!r}') from error

    def execute(self,operation,payload=None):
        """Invoke the real same-slot transition with bounded synthetic inputs."""
        keys=[self.prefix+name for name in ('due','capacity','record:','tombstone_due','tombstone_reason')]
        result = self.redis('--eval',self.script,*keys,',',operation,json.dumps(self.settings),json.dumps(payload or {}))
        if result[0] == 'LEASED':
            result[1] = json.loads(result[1])
        return result

    def test_metrics_report_exact_capacity_and_sweep_outcomes(self):
        """Require sanitized atomic capacity and cleanup facts from the actual transition."""
        reply = self.execute('enqueue', self.payload)
        self.assertEqual(len(reply), 3)
        snapshot = json.loads(reply[2])
        self.assertEqual(snapshot['live_records'], 1)
        self.assertEqual(snapshot['live_bytes'], 128)
        self.assertEqual(snapshot['due_records'], 1)
        self.assertNotIn(self.tag, reply[2])
        self.redis('DEL', self.prefix + 'record:' + self.tag)
        swept = json.loads(self.execute('sweep')[2])
        self.assertEqual(swept['live_records'], 0)
        self.assertEqual(swept['live_bytes'], 0)
        self.assertEqual(swept['due_records'], 0)
        self.assertEqual(swept['missing'], 1)

    def test_optional_metrics_permission_failure_preserves_acknowledgement(self):
        """A denied diagnostic HGET cannot change committed enqueue/acknowledgement results."""
        if '-s' not in self.command:
            self.skipTest('private standalone ACL fault')
        fixture = Path(__file__).with_name('run-policy-e2e.sh').read_text()
        commands = re.search(r"^commands='([^']+)'$", fixture, re.MULTILINE).group(1).split()
        self.redis('ACL', 'SETUSER', 'metrics_fault', 'on', 'nopass', '-@all',
            '~dkim2:observation:v1:*', *[command for command in commands if command != '+hget'])
        self.command.extend(['--user', 'metrics_fault', '--pass', '', '--no-auth-warning'])
        self.assertEqual(self.execute('enqueue', self.payload), ['ENQUEUED'])
        record = self.lease()[1]
        self.assertEqual(self.execute('ack', self.fence(record)), ['ACKED'])
        self.assertEqual(self.redis('HLEN', self.prefix + 'capacity'), 1)
        self.assertEqual(self.redis('ZCARD', self.prefix + 'due'), 0)

    def fence(self,record):
        """Pass only the closed ownership tuple back to a completion transition."""
        return {name:record[name] for name in ('allocation_tag','lease_owner','lease_token','lease_generation')}

    def lease(self,owner='worker',token='1'*32):
        """Claim one due record with a fresh worker token."""
        return self.execute('claim',dict(lease_owner=owner,lease_token=token))

    def test_impossible_retention_fails_closed(self):
        """A corrupt persisted deadline cannot extend the hard maximum retention."""
        self.execute('enqueue',self.payload)
        key=self.prefix+'record:'+self.tag
        created=int(self.redis('HGET',key,'created_at'))
        self.redis('HSET',key,'expires_at',created+700000000)
        self.assertEqual(self.lease(),['CORRUPT'])

    def test_real_idle_expiry(self):
        """An invocation-owned Redis clock drives live expiry and idle tombstone cleanup."""
        self.settings.update(max_age_ms=100,lease_ms=20,tombstone_ttl_ms=50)
        self.assertEqual(self.execute('enqueue',self.payload)[0],['ENQUEUED'][0])
        time.sleep(0.13)
        self.assertEqual(self.execute('sweep')[0],['SWEPT'][0])
        self.assertEqual(self.redis('HGET',self.prefix+'capacity','total_encrypted_bytes'),'0')
        self.assertEqual(self.redis('ZCARD',self.prefix+'tombstone_due'),1)
        time.sleep(0.07)
        self.assertEqual(self.execute('sweep')[0],['SWEPT'][0])
        self.assertEqual(self.redis('HLEN',self.prefix+'tombstone_reason'),0)

    def test_closed_transition_inputs_and_lease_identity(self):
        """Extra transition fields and malformed fencing tuples cannot mutate capacity."""
        self.assertEqual(self.execute('enqueue',dict(self.payload,plaintext='forbidden')),['INVALID'])
        self.assertEqual(self.redis('EXISTS',self.prefix+'capacity'),0)
        self.assertEqual(self.execute('enqueue',self.payload)[0],['ENQUEUED'][0])
        self.assertEqual(self.execute('claim',dict(lease_owner='worker',lease_token='1'*32,extra='forbidden')),['INVALID'])
        current=self.lease()[1]
        malformed={name:current[name] for name in ('allocation_tag','lease_owner','lease_token','lease_generation')}
        malformed['lease_generation']='1'
        self.assertEqual(self.execute('ack',malformed),['INVALID'])
        self.assertEqual(self.redis('EXISTS',self.prefix+'record:'+self.tag),1)

    def test_fixture_acl_allows_restart_and_delivery(self):
        """The least-privilege fixture principal can re-pin metadata and complete real transitions."""
        if '-s' not in self.command:
            self.skipTest('ACL contract uses the private standalone socket; transition tests cover Cluster')
        fixture = Path(__file__).with_name('run-policy-e2e.sh').read_text()
        commands = re.search(r"^commands='([^']+)'$", fixture, re.MULTILINE).group(1).split()
        self.redis('ACL', 'SETUSER', 'outbox', 'on', 'nopass', '-@all',
            '~dkim2:observation:v1:*', *commands)
        self.command.extend(['--user', 'outbox', '--pass', '', '--no-auth-warning'])
        module = MODULE.with_name('observation_allocation.lua')
        dumped = subprocess.run(['lua', '-', str(module)],
            input=b'io.write(assert(loadfile(arg[1]))().redis_script)', capture_output=True, check=True)
        script = self.root / 'allocation.lua'
        script.write_bytes(dumped.stdout)
        for _ in range(2):
            self.assertEqual(self.redis('--eval', script,
                'dkim2:observation:v1:{meta}:allocation', ',', 'a'*64, 4, 0), ['READY'])
        self.assertEqual(self.execute('enqueue', self.payload)[0], ['ENQUEUED'][0])
        record = self.lease()[1]
        self.assertEqual(self.execute('ack', self.fence(record))[0], ['ACKED'][0])
        self.assertEqual(self.execute('sweep')[0], ['SWEPT'][0])

    def test_allocation_metadata_fences_material_drift(self):
        """Concurrent generations pin one material identity and cannot rotate by changing a label."""
        module = MODULE.with_name('observation_allocation.lua')
        dumped = subprocess.run(['lua','-',str(module)], input=b'io.write(assert(loadfile(arg[1]))().redis_script)', capture_output=True, check=True)
        script = self.root / 'allocation.lua'
        script.write_bytes(dumped.stdout)
        key = 'dkim2:observation:v1:{meta}:allocation'
        def pin(identity='a'*64, shards=4, generation=0):
            return self.redis('--eval',script,key,',',identity,shards,generation)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(list(pool.map(lambda _:pin(),range(2))),[['READY'],['READY']])
        self.assertEqual(self.redis('HLEN',key),5)
        for candidate in [('b'*64,4,0),('a'*64,8,0),('b'*64,4,1),('a'*64,4,1)]:
            self.assertEqual(pin(*candidate),['ALLOCATION_MISMATCH'])
        self.redis('HSET',key,'unexpected','forbidden')
        self.assertEqual(pin(),['CORRUPT'])

    def test_capacity_duplicate_collision_and_fencing(self):
        """Duplicates charge once and stale completions cannot affect a reclaimed lease."""
        self.assertEqual(self.execute('enqueue',self.payload)[0],'ENQUEUED')
        self.assertEqual(self.execute('enqueue',self.payload)[0],'DUPLICATE')
        self.assertEqual(self.redis('HLEN',self.prefix+'capacity'),2)
        self.assertEqual(self.execute('enqueue',dict(self.payload,payload_fingerprint='e'*64))[0],'CONFLICT')
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results=list(pool.map(lambda token:self.lease(token=token), ['1'*32,'2'*32]))
        self.assertEqual(sorted(row[0] for row in results),['EMPTY','LEASED'])
        first=next(row for row in results if row[0]=='LEASED')[1]
        clock=self.redis('TIME')
        expired=int(clock[0])*1000+int(clock[1])//1000-1
        self.redis('HSET',self.prefix+'record:'+self.tag,'lease_until',expired)
        self.redis('ZADD',self.prefix+'due',expired,self.tag)
        current=self.lease(token='3'*32)[1]
        self.assertGreater(current['lease_generation'],first['lease_generation'])
        for action in ('retry','ack','dead'):
            self.assertEqual(self.execute(action,self.fence(first))[0],'STALE')
        self.assertEqual(self.execute('ack',self.fence(current))[0],'ACKED')
        self.assertEqual(self.redis('HLEN',self.prefix+'capacity'),1)
        self.assertEqual(self.redis('HGET',self.prefix+'capacity','total_encrypted_bytes'),'0')
        self.assertEqual(self.redis('ZCARD',self.prefix+'due'),0)

    def test_capacity_corruption_and_retry_expiry(self):
        """Capacity rejects excess allocation and retries retain the logical expiry deadline."""
        self.execute('enqueue',self.payload)
        self.execute('enqueue',dict(self.payload,allocation_tag='b'*64))
        self.assertEqual(self.execute('enqueue',dict(self.payload,allocation_tag='c'*64))[0],'FULL')
        self.redis('HSET',self.prefix+'capacity','total_encrypted_bytes',1)
        self.assertEqual(self.lease()[0],'CORRUPT')
        self.redis('HSET',self.prefix+'capacity','total_encrypted_bytes',256)
        claim=self.lease()[1]
        self.settings['backoff_min_ms']=100000
        self.settings['backoff_max_ms']=100000
        self.assertEqual(self.execute('retry',self.fence(claim))[0],'RETRY')
        key=self.prefix+'record:'+claim['allocation_tag']
        expiry=int(self.redis('HGET',key,'expires_at'))
        self.assertGreater(int(self.redis('HGET',key,'next_attempt_at')),expiry)
        self.assertEqual(float(self.redis('ZSCORE',self.prefix+'due',claim['allocation_tag'])),expiry)
        self.assertEqual(self.execute('ack',self.fence(claim))[0],'STALE')

    def test_missing_record_and_schedule_do_not_orphan_capacity(self):
        """The independent sweep also discovers a charged record missing from the schedule."""
        self.execute('enqueue',self.payload)
        self.redis('DEL',self.prefix+'record:'+self.tag)
        self.redis('ZREM',self.prefix+'due',self.tag)
        self.assertEqual(self.execute('sweep')[0],'SWEPT')
        self.assertEqual(self.redis('HGET',self.prefix+'capacity','total_encrypted_bytes'),'0')

    def test_expiry_missing_records_and_tombstones(self):
        """Logical expiry reconciles ledger charges and tombstone pressure cannot block cleanup."""
        for index in range(4):
            tag=format(index,'064x')
            self.assertEqual(self.execute('enqueue',dict(self.payload,allocation_tag=tag))[0],'ENQUEUED')
            self.assertEqual(self.redis('PTTL',self.prefix+'record:'+tag),-1)
            clock=self.redis('TIME')
            expired=int(clock[0])*1000+int(clock[1])//1000-1
            self.redis('HSET',self.prefix+'record:'+tag,'created_at',expired-100,'expires_at',expired,'next_attempt_at',expired-100)
            self.redis('ZADD',self.prefix+'due',expired-100,tag)
            self.assertEqual(self.execute('sweep')[0],'SWEPT')
        self.assertEqual(self.redis('ZCARD',self.prefix+'tombstone_due'),2)
        self.assertEqual(self.redis('HLEN',self.prefix+'capacity'),1)
        self.execute('enqueue',self.payload)
        self.redis('DEL',self.prefix+'record:'+self.tag)
        self.redis('ZADD',self.prefix+'due',1,self.tag)
        self.assertEqual(self.execute('sweep')[0],'SWEPT')
        self.assertEqual(self.redis('HGET',self.prefix+'capacity','total_encrypted_bytes'),'0')
        for tag in self.redis('ZRANGE',self.prefix+'tombstone_due',0,-1):
            self.redis('ZADD',self.prefix+'tombstone_due',1,tag)
        self.execute('sweep')
        self.assertEqual(self.redis('ZCARD',self.prefix+'tombstone_due'),0)
        self.assertEqual(self.redis('HLEN',self.prefix+'tombstone_reason'),0)

if CLUSTER:
    class OutboxClusterTest(OutboxStateTest):
        """Run every state-machine assertion against three invocation-owned loopback primaries."""
        def start_redis(self):
            """Reserve three private loopback endpoint/bus pairs before creating the isolated cluster."""
            held,ports=[],[]
            try:
                for _ in range(100):
                    if len(ports)==3:
                        break
                    port=20000+secrets.randbelow(20000)
                    pair=[]
                    try:
                        for candidate in (port,port+10000):
                            reservation=socket.socket()
                            pair.append(reservation)
                            reservation.bind(('127.0.0.1',candidate))
                    except OSError:
                        for reservation in pair:
                            reservation.close()
                        continue
                    held.extend(pair)
                    ports.append(port)
            finally:
                for reservation in held:
                    reservation.close()
            self.assertEqual(len(ports),3,'three private endpoint pairs must be reserved')
            self.nodes=[]
            self.addCleanup(self.cleanup_nodes)
            for index,port in enumerate(ports):
                directory=self.root/str(index)
                directory.mkdir()
                node=subprocess.Popen(['redis-server','--bind','127.0.0.1','--port',str(port),
                    '--cluster-enabled','yes','--cluster-config-file',str(directory/'nodes.conf'),
                    '--cluster-node-timeout','1000','--dir',str(directory),'--save','','--appendonly','no'],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.nodes.append(node)
            for port in ports:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.02)
                else:
                    self.fail('invocation-owned cluster node did not become ready')
            subprocess.run(['redis-cli','--cluster','create',*[f'127.0.0.1:{port}' for port in ports],
                '--cluster-replicas','0','--cluster-yes'],capture_output=True,check=True,timeout=20)
            self.command=['redis-cli','--json','-c','-h','127.0.0.1','-p',str(ports[0])]
            for _ in range(100):
                if all('cluster_state:ok' in subprocess.check_output(
                    ['redis-cli','--raw','-h','127.0.0.1','-p',str(port),'CLUSTER','INFO'],text=True)
                    for port in ports):
                    break
                time.sleep(0.02)
            else:
                self.fail('invocation-owned cluster did not become healthy')

        def cleanup_nodes(self):
            """Stop only the three processes created by this test, retaining unrelated stores."""
            for node in self.nodes:
                node.terminate()
            for node in self.nodes:
                node.wait(timeout=5)

        def test_exact_cluster_slot_and_cross_slot_rejection(self):
            """All dynamic record and ledger keys share the declared slot; a foreign slot is rejected."""
            keys=[self.prefix+name for name in ('due','capacity','record:','tombstone_due','tombstone_reason')]
            slots={self.redis('CLUSTER','KEYSLOT',key) for key in [*keys,self.prefix+'record:'+self.tag]}
            self.assertEqual(len(slots),1)
            keys[1]='dkim2:observation:v1:{other}:capacity'
            result=subprocess.check_output([*self.command,'--eval',str(self.script),*keys,',','enqueue',
                json.dumps(self.settings),json.dumps(self.payload)],text=True)
            self.assertIn('CROSSSLOT',result)

if __name__ == '__main__':
    unittest.main()
