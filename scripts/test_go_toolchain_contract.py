#!/usr/bin/env python3
"""Lock the exact first-party compiler and internally owned experiment contract."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('lib', 'cmd/dkim2d', 'cmd/dkim2-milter', 'cmd/dkim2-exim', 'cmd/dkim2ctl', 'cmd/dkim2-dsn-propagator', 'tools')
SCRIPTS = ('scripts/test-datasource-services.sh', 'scripts/test-valkey.sh', 'scripts/test-datasource-ldap-acl.sh', 'tools/check-operator-docs.sh', 'contrib/rspamd/tests/run-policy-e2e.sh', 'contrib/rspamd/tests/policy-e2e/verify-two-hop-projection.sh')

class ToolchainContractTest(unittest.TestCase):
    """Check standalone modules, native Make execution, CI, and direct entry points."""
    def test_workspace_and_standalone_modules(self):
        """Every module retains the same compiler when workspace resolution is disabled."""
        for path in ('go.work', *(f'{module}/go.mod' for module in MODULES)):
            with self.subTest(path=path):
                content = (ROOT / path).read_text()
                self.assertRegex(content, r'(?m)^go 1\.27(?:\.0)?$')
                self.assertRegex(content, r'(?m)^toolchain go1\.27\.0$')
                self.assertNotRegex(content, r'(?m)^(?:go|toolchain) .*1\.26')

    def test_make_and_direct_entry_points_own_experiment(self):
        """Unsetting the caller environment must not remove the compiler experiment."""
        make = (ROOT / 'Makefile').read_text()
        self.assertIn('export GOEXPERIMENT := runtimesecret', make)
        self.assertIn('export GOTOOLCHAIN := go1.27.0', make)
        self.assertIn('OPENAPI_GO_TOOLCHAIN := go1.27.0', make)
        self.assertRegex(make, r'(?m)^guardrails:.*check-go-toolchain-contract')
        for path in SCRIPTS:
            with self.subTest(path=path):
                self.assertRegex((ROOT / path).read_text(), r'(?m)^export GOEXPERIMENT=runtimesecret$')
                self.assertRegex((ROOT / path).read_text(), r'(?m)^export GOTOOLCHAIN=go1\.27\.0$')

    def test_ci_and_image_provenance_share_exact_compiler(self):
        """CI and authenticated image inputs cannot keep a second first-party lane."""
        self.assertEqual(json.loads((ROOT / 'build/ci/toolchain.json').read_text())['go']['version'], '1.27.0')
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            for version in re.findall(r'go-version:\s*[\'"]([^\'"]+)', path.read_text()):
                self.assertEqual(version, '1.27.0', path.name)
        docker = (ROOT / 'build/container/Dockerfile').read_text()
        self.assertRegex(docker, r'golang:1\.27\.0-bookworm@sha256:[0-9a-f]{64}')
        self.assertNotIn('golang:1.26', docker)

if __name__ == '__main__':
    unittest.main()
