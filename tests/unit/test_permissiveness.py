"""Overly permissive rule detection.

An allow rule with any source, any destination and every port. Standard audit
finding, and the one a reviewer looks for first.
"""

import pytest

from app.analyzer import analyze, is_overly_permissive
from tests.factories import make_stored_rule

pytestmark = pytest.mark.unit


def permissive_findings(rules):
    return [f for f in analyze(rules) if f.type == "OVERLY_PERMISSIVE"]


def test_any_any_all_ports_allow_is_flagged():
    """RG-UNIT-060: the textbook any/any/any allow rule is reported."""
    rule = make_stored_rule(
        rule_id="wide-open",
        source="any",
        destination="any",
        protocol="any",
        port_start=0,
        port_end=65535,
        action="allow",
    )
    assert is_overly_permissive(rule) is True


@pytest.mark.parametrize(
    ("source", "destination", "expected"),
    [
        ("any", "any", True),
        ("0.0.0.0/0", "0.0.0.0/0", True),
        ("any", "0.0.0.0/0", True),
        ("0.0.0.0/0", "any", True),
        ("10.0.0.0/8", "any", False),
        ("any", "10.0.0.0/8", False),
        ("10.0.0.0/8", "10.0.0.0/8", False),
    ],
    ids=[
        "keyword-both-sides",
        "cidr-both-sides",
        "keyword-source-cidr-destination",
        "cidr-source-keyword-destination",
        "scoped-source",
        "scoped-destination",
        "scoped-both-sides",
    ],
)
def test_permissiveness_accepts_either_spelling_of_any(source, destination, expected):
    """RG-UNIT-061: a rule written with 0.0.0.0/0 is as permissive as one written 'any'.

    Firewall exports commonly render the wildcard as 0.0.0.0/0. Checking only
    for the literal string 'any' misses every rule that came out of a device
    config, which is most of them.
    """
    rule = make_stored_rule(
        rule_id="candidate",
        source=source,
        destination=destination,
        protocol="any",
        port_start=0,
        port_end=65535,
        action="allow",
    )
    assert is_overly_permissive(rule) is expected


def test_deny_rule_is_never_overly_permissive():
    """RG-UNIT-062: a broad deny is a default-deny posture, not a finding."""
    rule = make_stored_rule(
        rule_id="default-deny",
        source="any",
        destination="any",
        protocol="any",
        port_start=0,
        port_end=65535,
        action="deny",
    )
    assert is_overly_permissive(rule) is False


@pytest.mark.parametrize(
    ("port_start", "port_end", "expected"),
    [
        (0, 65535, True),
        (1, 65535, False),
        (0, 65534, False),
        (80, 443, False),
        (443, 443, False),
        (0, 0, False),
    ],
    ids=[
        "full-range",
        "misses-port-zero",
        "misses-top-port",
        "web-ports-only",
        "single-port",
        "port-zero-only",
    ],
)
def test_permissiveness_requires_the_entire_port_range(port_start, port_end, expected):
    """RG-UNIT-063: anything short of 0-65535 is scoped, however slightly."""
    rule = make_stored_rule(
        rule_id="candidate",
        source="any",
        destination="any",
        protocol="any",
        port_start=port_start,
        port_end=port_end,
        action="allow",
    )
    assert is_overly_permissive(rule) is expected


@pytest.mark.parametrize(
    "protocol",
    ["any", "tcp", "udp", "icmp"],
    ids=["any", "tcp", "udp", "icmp"],
)
def test_permissiveness_is_reported_for_every_protocol(protocol):
    """RG-UNIT-064: any/any across all ports is a finding whatever the protocol.

    A rule opening every TCP port from anywhere to anywhere is not meaningfully
    safer than one opening every protocol.
    """
    rule = make_stored_rule(
        rule_id="candidate",
        source="any",
        destination="any",
        protocol=protocol,
        port_start=0,
        port_end=65535,
        action="allow",
    )
    assert is_overly_permissive(rule) is True


def test_permissive_finding_has_critical_severity():
    """RG-UNIT-065: the finding is reported as critical and names the rule."""
    rule = make_stored_rule(
        rule_id="wide-open",
        name="temp-troubleshooting-rule",
        source="any",
        destination="any",
        protocol="any",
        port_start=0,
        port_end=65535,
        action="allow",
    )
    findings = permissive_findings([rule])
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].rule_id == "wide-open"
    assert "temp-troubleshooting-rule" in findings[0].message


def test_disabled_permissive_rule_is_still_reported():
    """RG-UNIT-066: a disabled any/any allow rule is still worth flagging.

    It is one toggle away from being live, and audit frameworks expect it to
    appear in the report. This differs on purpose from shadowing, where a
    disabled rule genuinely cannot affect traffic.
    """
    rule = make_stored_rule(
        rule_id="dormant",
        source="any",
        destination="any",
        protocol="any",
        port_start=0,
        port_end=65535,
        action="allow",
        enabled=False,
    )
    assert len(permissive_findings([rule])) == 1


def test_scoped_rule_base_produces_no_permissive_findings():
    """RG-UNIT-067: a properly scoped rule base reports nothing."""
    rules = [
        make_stored_rule(rule_id="a", priority=10, source="10.0.0.0/24"),
        make_stored_rule(rule_id="b", priority=20, source="192.168.1.0/24", protocol="udp"),
    ]
    assert permissive_findings(rules) == []


def test_empty_rule_base_has_no_permissive_findings():
    """RG-UNIT-068: an empty rule base produces no permissiveness findings."""
    assert permissive_findings([]) == []
