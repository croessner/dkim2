#!/usr/bin/env python3
"""Assert the exact DKIM2 projection and bounded Rspamd Policy request surface."""

import argparse
import json
import re


RESOURCE_KEYS = {
    "dkim2.projection_schema",
    "dkim2.draft",
    "dkim2.projection_binding_algorithm",
    "dkim2.projection_binding",
    "dkim2.verification_state",
    "dkim2.verification_reason",
    "dkim2.scope",
    "dkim2.historical_content",
    "dkim2.historical_signatures",
    "dkim2.custody_structure",
    "dkim2.target_sequence",
    "dkim2.target_message_instance",
    "dkim2.claimed_hop_count",
    "dkim2.authentication_state",
    "dkim2.authentication_reason",
    "dkim2.replay_class",
    "dkim2.local_policy_mode",
    "dkim2.local_policy_verdict",
    "dkim2.local_policy_reason",
    "dkim2.do_not_modify_state",
    "dkim2.do_not_explode_state",
    "dkim2.dns_testing_effective",
    "dkim2.disposition",
    "dkim2.chain",
}

RECEIVED_DSN_KEY = "dkim2.received_dsn_propagation"

ENVIRONMENT_KEYS = {
    "rspamd.scan_action_before_policy",
    "rspamd.metric_score",
    "rspamd.reject_threshold",
    "rspamd.greylist_threshold",
    "rspamd.normalized_signals",
    "rspamd.smtp_client_ip",
    "rspamd.client_class",
    "rspamd.mail_from_class",
    "rspamd.recipient_classes",
    "rspamd.smtp_authenticated",
    "rspamd.recipient_count",
    "rspamd.message_size",
    "rspamd.message_fidelity",
}

HOP_FIELDS = (
    ("sequence", "integer"),
    ("message_instance", "integer"),
    ("hop_binding", "bytes"),
    ("signer_domain", "string"),
    ("signature_algorithms", "strings"),
    ("signature_state", "string"),
    ("custody_transition", "string"),
    ("do_not_modify", "boolean"),
    ("do_not_explode", "boolean"),
    ("feedback", "boolean"),
    ("feed_here", "boolean"),
    ("exploded", "boolean"),
    ("recipe_mode", "string"),
    ("recipe_has_header_changes", "boolean"),
    ("recipe_body_mode", "string"),
    ("recipe_digest", "bytes"),
    ("change_classes", "strings"),
    ("affected_headers", "strings"),
    ("history_header_state", "string"),
    ("history_body_state", "string"),
    ("body_availability", "string"),
    ("change_count", "integer"),
    ("affected_header_count", "integer"),
)


def load(path: str) -> dict:
    """Load one JSON object from a fixture or runtime evidence file."""
    with open(path, "r", encoding="utf-8") as source:
        value = json.load(source)
    assert isinstance(value, dict)
    return value


def leaf(kind: str, value: object) -> dict:
    """Convert a verifier projection value to its Policy leaf representation."""
    if kind == "integer":
        value = str(value)
    return {kind: value}


def expected_chain(response: dict) -> list[dict]:
    """Build the complete ordered Policy chain from every sealed verifier hop."""
    records = []
    for hop in response["verifier_projection"]["hops"]:
        fields = [
            {"name": name, "value": leaf(kind, hop[name])}
            for name, kind in HOP_FIELDS
        ]
        records.append({"fields": fields})
    return records


def expected_resource_keys(response: dict) -> set[str]:
    """Return the closed resource key set implied by the served producer response.

    The optional received delivery-status projection is the only conditional
    resource attribute, so an unexpected presence or absence stays a failure.
    """
    if response.get("delivery_status") is None:
        return RESOURCE_KEYS
    return RESOURCE_KEYS | {RECEIVED_DSN_KEY}


def assert_received_dsn(attributes: dict, response: dict, expected: str | None) -> None:
    """Assert the received delivery-status propagation attribute exactly.

    The attribute must be present with the projected propagation value whenever
    the producer returned the projection, absent otherwise, and equal to the
    caller-declared expectation when the scenario states one.
    """
    projection = response.get("delivery_status")
    if projection is None:
        assert RECEIVED_DSN_KEY not in attributes
        assert expected is None, RECEIVED_DSN_KEY
        return
    assert attributes[RECEIVED_DSN_KEY] == {"string": projection["propagation"]}
    if expected is not None:
        assert projection["propagation"] == expected, RECEIVED_DSN_KEY


def assert_request(
    state: dict,
    response: dict,
    peer_ip: str,
    expected_action: str,
    expected_received_dsn: str | None = None,
) -> None:
    """Assert projection fidelity, environment provenance, and excluded payload classes."""
    request = state["last_request"]
    assert set(request) == {"version", "request_id", "target", "resource", "environment", "options"}
    assert request["version"] == "1"
    assert re.fullmatch(r"[0-9a-f]{16,128}", request["request_id"])
    assert request["target"] == {"namespace": "dkim2", "action": "accept-message-instance"}
    assert request["options"] == {"include_diagnostics": False}

    resource = request["resource"]
    attributes = resource["attributes"]
    assert set(resource) == {"type", "attributes"}
    assert resource["type"] == "dkim2-message-instance"
    assert set(attributes) == expected_resource_keys(response)
    projection = response["verifier_projection"]
    verification = response["verification"]
    authentication = response["authentication"]
    policy = response["policy"]
    expected_scalars = {
        "dkim2.projection_schema": {"string": projection["schema"]},
        "dkim2.draft": {"string": projection["draft"]},
        "dkim2.projection_binding_algorithm": {"string": projection["binding_algorithm"]},
        "dkim2.projection_binding": {"bytes": projection["binding"]},
        "dkim2.verification_state": {"string": verification["state"]},
        "dkim2.verification_reason": {"string": verification["primary_reason"]},
        "dkim2.scope": {"string": verification["scope"]},
        "dkim2.historical_content": {"string": verification["historical_content"]},
        "dkim2.historical_signatures": {"string": verification["historical_signatures"]},
        "dkim2.custody_structure": {"string": verification["custody_structure"]},
        "dkim2.target_sequence": {"integer": verification["target"]["sequence"]},
        "dkim2.target_message_instance": {"integer": verification["target"]["instance"]},
        "dkim2.claimed_hop_count": {"integer": str(len(projection["hops"]))},
        "dkim2.authentication_state": {"string": authentication["state"]},
        "dkim2.authentication_reason": {"string": authentication["primary_reason"]},
        "dkim2.replay_class": {"string": response["replay"]["class"]},
        "dkim2.local_policy_mode": {"string": policy["mode"]},
        "dkim2.local_policy_verdict": {"string": policy["verdict"]},
        "dkim2.local_policy_reason": {"string": policy["primary_reason"]},
        "dkim2.do_not_modify_state": {"string": policy["do_not_modify"]},
        "dkim2.do_not_explode_state": {"string": policy["do_not_explode"]},
        "dkim2.dns_testing_effective": {"boolean": policy["dns_testing_effective"]},
        "dkim2.disposition": {"string": response["disposition"]},
    }
    for name, expected in expected_scalars.items():
        assert attributes[name] == expected, name
    assert attributes["dkim2.chain"] == {"records": expected_chain(response)}
    assert_received_dsn(attributes, response, expected_received_dsn)

    environment = request["environment"]
    environment_attributes = environment["attributes"]
    assert set(environment) == {"service", "instance", "protocol", "attributes"}
    assert environment["service"] == "rspamd"
    assert environment["instance"] == "policy-e2e-mx"
    assert environment["protocol"] == "milter"
    assert set(environment_attributes) == ENVIRONMENT_KEYS
    assert environment_attributes["rspamd.smtp_client_ip"] == {"string": peer_ip}
    assert environment_attributes["rspamd.scan_action_before_policy"] == {
        "string": expected_action
    }
    assert environment_attributes["rspamd.reject_threshold"] == {"double": 15.0}
    assert environment_attributes["rspamd.greylist_threshold"] == {"double": 0.0}
    assert isinstance(environment_attributes["rspamd.metric_score"]["double"], (int, float))
    signals = environment_attributes["rspamd.normalized_signals"]["strings"]
    assert signals == sorted(set(signals))
    assert environment_attributes["rspamd.client_class"] == {"string": "untrusted"}
    assert environment_attributes["rspamd.mail_from_class"] == {"string": "external"}
    assert environment_attributes["rspamd.recipient_classes"] == {"strings": ["local"]}
    assert environment_attributes["rspamd.smtp_authenticated"] == {"boolean": False}
    assert environment_attributes["rspamd.recipient_count"] == {"integer": "1"}
    assert int(environment_attributes["rspamd.message_size"]["integer"]) > 0
    assert environment_attributes["rspamd.message_fidelity"] == {
        "string": "milter_reconstructed_crlf"
    }

    serialized = json.dumps(request, sort_keys=True)
    for excluded in (
        "sender@example.test",
        "recipient@example.test",
        "policy-retry-proof@example.test",
        "deterministic body",
        "authorization",
    ):
        assert excluded not in serialized.lower(), excluded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--response", required=True)
    parser.add_argument("--peer-ip", required=True)
    parser.add_argument("--expected-action", required=True)
    parser.add_argument("--expect-received-dsn")
    args = parser.parse_args()
    state = load(args.state)
    assert state["calls"] >= 1
    assert_request(
        state,
        load(args.response),
        args.peer_ip,
        args.expected_action,
        args.expect_received_dsn,
    )


if __name__ == "__main__":
    main()
