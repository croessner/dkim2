#!/usr/bin/env python3
"""Exercise the security-critical real-matrix qualification helper."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("real_matrix_service.py")
SPEC = importlib.util.spec_from_file_location("real_matrix_service", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification helper import failed")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


def operation_request(operation: str) -> bytes:
    """Return one minimal exact operation request."""
    value: dict[str, object] = {
        "api_version": "v1",
        "draft": "draft-ietf-dkim-dkim2-spec-06",
        "message": {
            "fidelity": "exim_transport_filter_crlf",
            "raw_rfc5322_base64": "",
        },
        "smtp": {"mail_from": "sender@example.test", "rcpt_to": ["out@example.test"]},
        "context": {"tenant": "tenant-a", "domain": "example.test"},
    }
    if operation == "revise":
        value["incoming_smtp"] = {
            "mail_from": "sender@example.test",
            "rcpt_to": ["in@example.test"],
        }
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def operation_response(operation: str) -> dict[str, object]:
    """Return one exact successful operation response."""
    return {
        "api_version": "v1",
        "draft": "draft-ietf-dkim-dkim2-spec-06",
        "operation": operation,
        "result": "pass",
        "disposition": "accept",
        "actions": [
            {
                "type": "add_header",
                "name": "Message-Instance",
                "value": " i=1; m=a",
            },
            {
                "type": "add_header",
                "name": "DKIM2-Signature",
                "value": " i=1; s=a",
            },
        ],
    }


class FakeSMTPStream:
    """Provide one deterministic in-memory SMTP conversation."""

    def __init__(self, replies: list[bytes]) -> None:
        self.replies = list(replies)
        self.writes = bytearray()

    def readline(self, _limit: int) -> bytes:
        """Return the next configured SMTP reply line."""
        return self.replies.pop(0)

    def write(self, value: bytes) -> int:
        """Capture one exact client write."""
        self.writes.extend(value)
        return len(value)

    def flush(self) -> None:
        """Flush the in-memory stream."""

    def close(self) -> None:
        """Close the in-memory stream."""


class FakeSMTPConnection:
    """Own one fake socket stream."""

    def __init__(self, stream: FakeSMTPStream) -> None:
        self.stream = stream

    def settimeout(self, _timeout: int) -> None:
        """Accept the bounded client timeout."""

    def makefile(self, _mode: str, buffering: int = 0) -> FakeSMTPStream:
        """Return the sole fake stream."""
        if buffering != 0:
            raise ValueError("unexpected buffering")
        return self.stream

    def close(self) -> None:
        """Close the fake connection."""


class HelperTests(unittest.TestCase):
    """Verify exact helper encoding, parsing, and evidence semantics."""

    def test_smtp_abort_peer_records_only_pre_delivery_structure(self) -> None:
        """Prove one EHLO followed by filter abort records no delivery attempt."""
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            output = root / "abort"
            ready = root / "ready"
            stream = FakeSMTPStream([b"EHLO matrix.example.test\r\n", b""])
            connection = FakeSMTPConnection(stream)
            server = mock.Mock()
            server.accept.side_effect = lambda: (
                connection,
                self.assertEqual(ready.read_bytes(), b"ready\n"),
            )
            with mock.patch.object(HELPER.socket, "socket", return_value=server):
                HELPER.run_smtp_abort_peer(
                    "127.0.0.1", 2526, output, ready
                )
            server.accept.assert_called_once_with()
            self.assertEqual(
                output.read_text(encoding="ascii").splitlines(),
                [
                    "format=dkim2-exim-smtp-abort-v1",
                    "connections=1",
                    "ehlo=1",
                    "mail=0",
                    "rcpt=0",
                    "data=0",
                    "deliveries=0",
                ],
            )

    def test_smtp_abort_peer_records_post_data_filter_abort(self) -> None:
        """Prove an EOF after DATA records an envelope but no delivery."""
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            output = root / "abort"
            ready = root / "ready"
            stream = FakeSMTPStream(
                [
                    b"EHLO matrix.example.test\r\n",
                    b"MAIL FROM:<sender@example.test>\r\n",
                    b"RCPT TO:<recipient@example.test>\r\n",
                    b"DATA\r\n",
                    b"",
                ]
            )
            connection = FakeSMTPConnection(stream)
            server = mock.Mock()
            server.accept.return_value = (connection, object())
            with mock.patch.object(HELPER.socket, "socket", return_value=server):
                HELPER.run_smtp_abort_peer(
                    "127.0.0.1", 2526, output, ready
                )
            self.assertEqual(
                output.read_text(encoding="ascii").splitlines(),
                [
                    "format=dkim2-exim-smtp-abort-v1",
                    "connections=1",
                    "ehlo=1",
                    "mail=1",
                    "rcpt=1",
                    "data=1",
                    "deliveries=0",
                ],
            )

    def test_smtp_abort_peer_requires_exactly_one_greeting(self) -> None:
        """Prove a connection abort before EHLO cannot become evidence."""
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            output = root / "abort"
            ready = root / "ready"
            connection = FakeSMTPConnection(FakeSMTPStream([b""]))
            server = mock.Mock()
            server.accept.return_value = (connection, object())
            with mock.patch.object(HELPER.socket, "socket", return_value=server):
                with self.assertRaises(ValueError):
                    HELPER.run_smtp_abort_peer(
                        "127.0.0.1", 2526, output, ready
                    )
            self.assertFalse(output.exists())

    def test_smtp_readiness_does_not_consume_delivery(self) -> None:
        """Prove readiness is published before the first connection is accepted."""
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            capture = root / "capture"
            ready = root / "ready"
            stream = FakeSMTPStream(
                [
                    b"EHLO matrix.example.test\r\n",
                    b"MAIL FROM:<sender@example.test>\r\n",
                    b"RCPT TO:<recipient@example.test>\r\n",
                    b"DATA\r\n",
                    b"Subject: x\r\n",
                    b"\r\n",
                    b"body\r\n",
                    b".\r\n",
                    b"QUIT\r\n",
                ]
            )
            connection = FakeSMTPConnection(stream)
            server = mock.Mock()
            server.accept.side_effect = lambda: (
                connection,
                self.assertEqual(ready.read_bytes(), b"ready\n"),
            )
            with mock.patch.object(HELPER.socket, "socket", return_value=server):
                HELPER.run_smtp("127.0.0.1", 2526, capture, ready, 1)
            server.accept.assert_called_once_with()
            self.assertGreater(capture.stat().st_size, 8)

    def test_smtp_data_encoding_is_binary_safe_and_exact(self) -> None:
        """Prove LF conversion, dot stuffing, NUL retention, and final CRLF."""
        encoded = HELPER.encode_smtp_data(b"Subject: x\n\n.a\x00\nlast", "lf")
        self.assertEqual(encoded, b"Subject: x\r\n\r\n..a\x00\r\nlast\r\n")
        self.assertEqual(
            HELPER.encode_smtp_data(b"Subject: x\r\n\r\nbody\r\n", "crlf"),
            b"Subject: x\r\n\r\nbody\r\n",
        )
        for malformed, wire_format in (
            (b"x\r\n", "lf"),
            (b"x\n", "crlf"),
            (b"x\r", "crlf"),
        ):
            with self.assertRaises(ValueError):
                HELPER.encode_smtp_data(malformed, wire_format)

    def test_smtp_client_enforces_every_phase(self) -> None:
        """Prove every SMTP phase requires its exact status code."""
        replies = [
            b"220 ready\r\n",
            b"250 hello\r\n",
            b"250 mail\r\n",
            b"250 rcpt\r\n",
            b"354 data\r\n",
            b"250 accepted\r\n",
            b"221 closing\r\n",
        ]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            message = root / "message"
            message.write_bytes(b"Subject: x\n\n.a\x00\n")
            for wrong_index in range(len(replies)):
                wrong = list(replies)
                wrong[wrong_index] = b"550 wrong\r\n"
                stream = FakeSMTPStream(wrong)
                connection = FakeSMTPConnection(stream)
                with mock.patch.object(
                    HELPER.socket, "create_connection", return_value=connection
                ):
                    with self.assertRaises(ValueError):
                        HELPER.run_smtp_client(
                            "127.0.0.1",
                            2525,
                            "sender@example.test",
                            "recipient@example.test",
                            message,
                            "lf",
                            False,
                            root / f"wrong-{wrong_index}",
                        )
            stream = FakeSMTPStream(list(replies))
            connection = FakeSMTPConnection(stream)
            output = root / "success"
            with mock.patch.object(
                HELPER.socket, "create_connection", return_value=connection
            ):
                HELPER.run_smtp_client(
                    "127.0.0.1",
                    2525,
                    "sender@example.test",
                    "recipient@example.test",
                    message,
                    "lf",
                    False,
                    output,
                )
            self.assertIn(b"\r\n..a\x00\r\n.\r\n", stream.writes)
            self.assertEqual(output.read_bytes(), b"".join(replies))
            utf8_replies = [
                b"220 ready\r\n",
                b"250-matrix\r\n",
                b"250-8BITMIME\r\n",
                b"250 SMTPUTF8\r\n",
                *replies[2:],
            ]
            stream = FakeSMTPStream(list(utf8_replies))
            connection = FakeSMTPConnection(stream)
            with mock.patch.object(
                HELPER.socket, "create_connection", return_value=connection
            ):
                HELPER.run_smtp_client(
                    "127.0.0.1",
                    2525,
                    "séndér@example.test",
                    "récipient@example.test",
                    message,
                    "lf",
                    True,
                    root / "utf8-success",
                )
            self.assertIn(b" SMTPUTF8\r\n", stream.writes)
            for missing in (b"250 8BITMIME\r\n", b"250 SMTPUTF8\r\n"):
                stream = FakeSMTPStream([b"220 ready\r\n", missing])
                connection = FakeSMTPConnection(stream)
                with mock.patch.object(
                    HELPER.socket, "create_connection", return_value=connection
                ):
                    with self.assertRaises(ValueError):
                        HELPER.run_smtp_client(
                            "127.0.0.1",
                            2525,
                            "séndér@example.test",
                            "récipient@example.test",
                            message,
                            "lf",
                            True,
                            root / f"missing-{missing[4:8].decode('ascii')}",
                        )

    def test_capture_unpack_is_framed_and_field_exact(self) -> None:
        """Prove framing, envelope removal, header indexing, and fresh outputs."""
        message = (
            b"Subject: x\r\n"
            b"Message-Instance: i=1; m=a\r\n"
            b"DKIM2-Signature: i=1; s=a\r\n"
            b"\r\nbody\r\n"
        )
        payload = (
            b"MAIL FROM:<sender@example.test>\r\n"
            b"RCPT TO:<recipient@example.test>\r\n"
            + message
        )
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            capture = root / "capture"
            capture.write_bytes(struct.pack("!Q", len(payload)) + payload)
            output = root / "message"
            metadata = root / "metadata"
            HELPER.run_unpack(capture, output, metadata)
            self.assertEqual(output.read_bytes(), message)
            fields = dict(
                line.split("=", 1)
                for line in metadata.read_text(encoding="ascii").splitlines()
            )
            self.assertEqual(fields["owned_field_indexes"], "1,2")
            self.assertEqual(fields["owned_field_sequence"], "message-instance,dkim2-signature")
            self.assertIn("last_owned_field_sha256", fields)
            truncated = root / "truncated"
            truncated.write_bytes(struct.pack("!Q", len(payload) + 1) + payload)
            with self.assertRaises(ValueError):
                HELPER.run_unpack(truncated, root / "unused", root / "unused-meta")
            symlink_output = root / "symlink-output"
            symlink_output.symlink_to(output)
            with self.assertRaises(FileExistsError):
                HELPER.run_unpack(
                    capture, symlink_output, root / "symlink-metadata"
                )

    def test_capture_inspection_allows_unowned_fidelity_messages(self) -> None:
        """Prove the independent inspector can preserve unsigned wire fixtures."""
        message = b"Subject: fidelity\r\n\r\nbody\r\n"
        payload = (
            b"MAIL FROM:<sender@example.test>\r\n"
            b"RCPT TO:<recipient@example.test>\r\n" + message
        )
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            capture = root / "capture"
            capture.write_bytes(struct.pack("!Q", len(payload)) + payload)
            output = root / "message"
            metadata = root / "metadata"
            HELPER.run_unpack(capture, output, metadata)
            self.assertEqual(output.read_bytes(), message)
            fields = dict(
                line.split("=", 1)
                for line in metadata.read_text(encoding="ascii").splitlines()
            )
            self.assertEqual(fields["owned_field_count"], "0")
            with self.assertRaises(ValueError):
                HELPER.run_unpack(
                    capture,
                    root / "required-message",
                    root / "required-metadata",
                    True,
                )

    def test_message_inspection_measures_wire_classes_without_content(self) -> None:
        """Prove fixture inspection records only bounded byte-class measurements."""
        message = b"Subject: x\nX-Duplicate: one\nX-Duplicate: two\n folded\n\nbody\x00\n"
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            fixture = root / "fixture"
            fixture.write_bytes(message)
            metadata = root / "metadata"
            HELPER.inspect_message(fixture, "lf", metadata)
            fields = dict(
                line.split("=", 1)
                for line in metadata.read_text(encoding="ascii").splitlines()
            )
            self.assertEqual(fields["raw_bare_lf_count"], "6")
            self.assertEqual(fields["raw_crlf_count"], "0")
            self.assertEqual(fields["duplicate_count"], "2")
            self.assertEqual(fields["folded_count"], "1")
            self.assertEqual(fields["x_duplicate_count"], "2")
            self.assertEqual(fields["x_duplicate_folded_count"], "1")
            self.assertEqual(fields["nul_count"], "1")
            self.assertEqual(fields["authentication_results_count"], "0")
            self.assertEqual(fields["first_header"], "subject")
            self.assertEqual(fields["first_header_received"], "0")

    def test_stable_exim_projection_removes_only_first_received_field(self) -> None:
        """Prove timestamp drift is isolated without masking later byte changes."""
        suffix = (
            b"Subject: x\r\nX-Duplicate: one\r\nX-Duplicate: two\r\n"
            b"\tfolded\r\n\r\nbody\r\n"
        )
        first = b"Received: by mx;\r\n\tone\r\n" + suffix
        second = b"rEcEiVeD: by mx;\r\n\ttwo\r\n" + suffix
        first_stable, first_received = HELPER.stable_exim_message_projection(first)
        second_stable, second_received = HELPER.stable_exim_message_projection(second)
        self.assertTrue(first_received)
        self.assertTrue(second_received)
        self.assertEqual(first_stable, suffix)
        self.assertEqual(first_stable, second_stable)
        changed, changed_received = HELPER.stable_exim_message_projection(
            second.replace(b"X-Duplicate: two", b"X-Duplicate: changed")
        )
        self.assertTrue(changed_received)
        self.assertNotEqual(first_stable, changed)
        unchanged, received = HELPER.stable_exim_message_projection(suffix)
        self.assertFalse(received)
        self.assertEqual(unchanged, suffix)

    def test_proxy_record_closes_operation_and_action_semantics(self) -> None:
        """Prove exact response fields, action order, values, and JSON grammar."""
        for operation in ("sign", "revise"):
            request = operation_request(operation)
            response = operation_response(operation)
            encoded = json.dumps(response, separators=(",", ":")).encode("ascii")
            record = HELPER.build_proxy_record(operation, request, encoded, 200)
            self.assertIn(b"actions=2 ", record)
            self.assertNotIn(b"message_stable_sha256=", record)
            self.assertNotIn(b"message_first_header_received=", record)
            for mutate in (
                lambda value: value.update(operation="revise" if operation == "sign" else "sign"),
                lambda value: value.update(result="temperror"),
                lambda value: value.update(disposition="continue"),
                lambda value: value.update(api_version="v2"),
                lambda value: value.update(draft="draft-ietf-dkim-dkim2-spec-03"),
                lambda value: value["actions"].reverse(),
                lambda value: value["actions"][0].update(type="remove_header"),
                lambda value: value["actions"][0].update(value="bad\nvalue"),
                lambda value: value.update(extra=True),
            ):
                invalid = copy.deepcopy(response)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    HELPER.build_proxy_record(
                        operation,
                        request,
                        json.dumps(invalid, separators=(",", ":")).encode("ascii"),
                        200,
                    )
            with self.assertRaises(ValueError):
                HELPER.build_proxy_record(operation, request, encoded, 201)
        revise_request = operation_request("revise")
        hash_unchanged_revise = operation_response("revise")
        hash_unchanged_revise["actions"] = [hash_unchanged_revise["actions"][1]]
        record = HELPER.build_proxy_record(
            "revise",
            revise_request,
            json.dumps(hash_unchanged_revise, separators=(",", ":")).encode("ascii"),
            200,
        )
        self.assertIn(b"actions=1 ", record)
        duplicate = (
            b'{"smtp":{"mail_from":"a","rcpt_to":["b"]},'
            b'"smtp":{"mail_from":"c","rcpt_to":["d"]}}'
        )
        encoded = json.dumps(operation_response("sign")).encode("ascii")
        with self.assertRaises(ValueError):
            HELPER.build_proxy_record("sign", duplicate, encoded, 200)

    def test_process_proxy_record_binds_stable_received_projection(self) -> None:
        """Prove only process evidence binds the first-Received-stripped digest."""
        message = (
            b"Received: by mx;\r\n\tone\r\nSubject: x\r\n"
            b"X-Duplicate: one\r\nX-Duplicate: two\r\n\tfolded\r\n\r\nbody\r\n"
        )
        stable, first_received = HELPER.stable_exim_message_projection(message)
        self.assertTrue(first_received)
        request = json.dumps(
            {
                "message": {
                    "fidelity": "exim_local_scan_observed_crlf",
                    "raw_rfc5322_base64": base64.b64encode(message).decode("ascii"),
                },
                "smtp": {
                    "mail_from": "sender@example.test",
                    "rcpt_to": ["recipient@example.test"],
                },
            },
            separators=(",", ":"),
        ).encode("ascii")
        record = HELPER.build_proxy_record(
            "process",
            request,
            b'{"actions":[]}',
            200,
        )
        fields = dict(
            field.split(b"=", 1) for field in record.rstrip(b"\n").split(b" ")
        )
        self.assertEqual(fields[b"message_first_header_received"], b"1")
        self.assertEqual(
            fields[b"message_stable_sha256"],
            hashlib.sha256(stable).hexdigest().encode("ascii"),
        )

    def test_proxy_record_is_durable_before_response_call(self) -> None:
        """Prove complete append and source ordering before response exposure."""
        with tempfile.TemporaryDirectory() as raw:
            output = pathlib.Path(raw) / "proxy.log"
            HELPER.append_fsynced(output, b"first\n")
            HELPER.append_fsynced(output, b"second\n")
            self.assertEqual(output.read_bytes(), b"first\nsecond\n")
        source = SCRIPT.read_text(encoding="utf-8")
        append_index = source.index("append_fsynced(self.output, record)")
        response_index = source.index("self.send_response(response.status)")
        self.assertLess(append_index, response_index)


if __name__ == "__main__":
    unittest.main()
