"""Verify exact bounded queue-drain evidence without observation payload access."""
import unittest
from reputation_probe import OutboxSnapshot


class OutboxSnapshotTest(unittest.TestCase):
    """Reject live, corrupt or incompletely inspected queue state."""

    def test_drain_reads_every_shard_and_no_payload(self):
        for capacity, due, empty in [([], 0, True), (["total_encrypted_bytes", "0"], 0, True),
                (["total_encrypted_bytes", "42", "record:" + "a" * 64, "42"], 1, False),
                (["total_encrypted_bytes", "0"], 1, False), (["unexpected", "0"], 0, False)]:
            with self.subTest(capacity=capacity, due=due):
                snapshot = object.__new__(OutboxSnapshot)
                calls = []
                def command(operation, key):
                    calls.append((operation, key))
                    return capacity if operation == "HGETALL" else due
                snapshot.command = command
                self.assertEqual(empty, snapshot.empty())
                self.assertTrue(all(key.endswith((":capacity", ":due")) for _, key in calls))
                if empty:
                    self.assertEqual(8, len(calls))


if __name__ == "__main__":
    unittest.main()
