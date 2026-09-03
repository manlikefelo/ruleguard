"""Test data builders.

Every test that needs a rule goes through here. Hard-coded rule dicts inside
test bodies are what makes a suite expensive to change later: add one field to
the model and you are editing eighty tests instead of one function.
"""

from typing import Any

DEFAULT_RULE: dict[str, Any] = {
    "name": "allow-web-dmz",
    "priority": 100,
    "source": "10.0.0.0/24",
    "destination": "10.1.0.0/24",
    "protocol": "tcp",
    "port_start": 80,
    "port_end": 443,
    "action": "allow",
    "enabled": True,
}


def make_rule(**overrides: Any) -> dict[str, Any]:
    """Return a valid rule payload, with any field overridden.

    Pass a field as None to drop it entirely, which is how the negative tests
    build payloads with missing required fields.
    """
    payload = dict(DEFAULT_RULE)
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


def make_stored_rule(rule_id: str = "rule-1", tenant_id: str = "tenant-acme", **overrides: Any):
    """Build a Rule model instance directly, bypassing the HTTP layer.

    The unit tests for the analyzer use this so they do not need a client.
    """
    from app.models import Rule

    payload = make_rule(**overrides)
    return Rule(id=rule_id, tenant_id=tenant_id, **payload)
