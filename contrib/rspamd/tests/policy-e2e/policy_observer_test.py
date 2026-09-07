#!/usr/bin/env python3
"""Verify that observation transport evidence retains only bounded opaque metadata."""
import json
from pathlib import Path
import tempfile
import unittest

from policy_observer import State


class ObservationEvidenceTest(unittest.TestCase):
    """Protect frozen payload correlation without logging observation contents or credentials."""

    def test_observation_metadata_is_bounded_and_redacted(self):
        """Exact retries share one digest while unrelated requests cannot grow evidence without bound."""
        with tempfile.TemporaryDirectory(prefix='dkim2-observer-') as directory:
            root = Path(directory)
            state = State(str(root/'state.json'), str(root/'control.json'))
            body = b'{"peer":"203.0.113.25","private":"synthetic-observation"}'
            digest = state.record_observation(body)
            self.assertEqual(state.record_observation(body), digest)
            state.record_observation_response(digest, 200, b'{"effect":"permit","secret":"forbidden"}')
            saved = json.loads((root/'state.json').read_text())
            self.assertEqual(saved['observation_calls'], 2)
            self.assertEqual(saved['observations'][digest]['received'], 2)
            self.assertEqual(saved['observations'][digest]['forwarded'], 1)
            self.assertEqual(saved['observations'][digest]['last_effect'], 'permit')
            self.assertNotIn('203.0.113.25', (root/'state.json').read_text())
            self.assertNotIn('synthetic-observation', (root/'state.json').read_text())
            self.assertNotIn('forbidden', (root/'state.json').read_text())
            for index in range(260):
                state.record_observation(str(index).encode())
            self.assertLessEqual(len(json.loads((root/'state.json').read_text())['observations']), 256)

    def test_lost_ack_holds_retries_until_explicit_release(self):
        """Permit one real admission, lose its response, and hold duplicates for state comparison."""
        with tempfile.TemporaryDirectory(prefix='dkim2-observer-') as directory:
            root = Path(directory)
            state = State(str(root/'state.json'), str(root/'control.json'))
            digest = state.record_observation(b'canonical')
            self.assertTrue(state.begin_observation_forward(digest, 'drop_ack'))
            self.assertFalse(state.begin_observation_forward(digest, 'drop_ack'))
            state.record_observation_response(digest, 503, b'{}')
            self.assertTrue(state.begin_observation_forward(digest, 'drop_ack'))
            state.record_observation_response(digest, 200, b'{"effect":"permit"}')
            self.assertFalse(state.begin_observation_forward(digest, 'drop_ack'))
            self.assertTrue(state.begin_observation_forward(digest, 'forward'))

    def test_untrusted_mode_and_effect_types_are_closed(self):
        """Malformed fixture control or response fields cannot interrupt evidence capture."""
        with tempfile.TemporaryDirectory(prefix='dkim2-observer-') as directory:
            root = Path(directory)
            state = State(str(root/'state.json'), str(root/'control.json'))
            (root/'control.json').write_text('{"mode":[],"observation_mode":{}}')
            self.assertEqual(state.mode(), 'forward')
            self.assertEqual(state.observation_mode(), 'forward')
            digest = state.record_observation(b'canonical')
            state.record_observation_response(digest, 200, b'{"effect":[]}')
            self.assertEqual(state.observations[digest]['last_effect'], 'invalid')


if __name__ == '__main__':
    unittest.main()
