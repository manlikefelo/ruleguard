"""Redundant rule detection.

Two rules that match the same traffic and take the same action. The second one
adds nothing except audit burden and another line to review.
"""

import pytest

from app.analyzer import analyze, is_duplicate
from tests.factories import make_stored_rule

pytestmark = pytest.mark.unit


def redundant_findings(rules):
    return [f for f in analyze(rules) if f.type == "REDUNDANT"]


def test_identical_rules_are_duplicates():
    """RG-UNIT-040: two rules matching on every field are duplicates."""
    a = make_stored_rule(rule_id="a", priority=10)
    b = make_stored_rule(rule_id="b", priority=20)
    assert is_duplicate(a, b) is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", "10.9.9.0/24"),
        ("destination", "10.8.8.0/24"),
        ("protocol", "udp"),
        ("port_start", 100),
        ("port_end", 9090),
        ("action", "deny"),
    ],
    ids=[
        "different-source",
        "different-destination",
        "different-protocol",
        "different-port-start",
        "different-port-end",
        "different-action",
    ],
)
def test_any_differing_match_field_prevents_duplication(field, value):
    """RG-UNIT-041: changing any one match field stops two rules being duplicates."""
    a = make_stored_rule(rule_id="a", priority=10)
    b = make_stored_rule(rule_id="b", priority=20, **{field: value})
    assert is_duplicate(a, b) is False


@pytest.mark.parametrize(
    ("name_b", "priority_b"),
    [("a-completely-different-name", 20), ("allow-web-dmz", 500)],
    ids=["different-name", "different-priority"],
)
def test_name_and_priority_do_not_affect_duplication(name_b, priority_b):
    """RG-UNIT-042: duplication is about matched traffic, not labels or ordering.

    Renaming a rule does not make it do something different, so a rename must
    not hide a duplicate from the report.
    """
    a = make_stored_rule(rule_id="a", priority=10)
    b = make_stored_rule(rule_id="b", name=name_b, priority=priority_b)
    assert is_duplicate(a, b) is True


def test_redundant_finding_targets_the_lower_priority_rule():
    """RG-UNIT-043: the rule reported is the later one, since it is the dead copy.

    The earlier rule is the one actually doing the work. Telling an operator
    to remove that one instead would change the policy.
    """
    primary = make_stored_rule(rule_id="primary", name="ssh-primary", priority=50)
    copy = make_stored_rule(rule_id="copy", name="ssh-copy", priority=90)
    findings = redundant_findings([primary, copy])
    assert len(findings) == 1
    assert findings[0].rule_id == "copy"
    assert findings[0].duplicate_of == "primary"
    assert findings[0].severity == "medium"


def test_redundant_pair_is_reported_once_not_twice():
    """RG-UNIT-044: a duplicate pair yields one finding, not one per direction.

    Both rules match each other. If the comparison runs both ways without
    guarding on priority, the same pair gets reported from each side.
    """
    primary = make_stored_rule(rule_id="primary", priority=50)
    copy = make_stored_rule(rule_id="copy", priority=90)
    assert len(redundant_findings([primary, copy])) == 1


def test_three_identical_rules_report_the_two_later_copies():
    """RG-UNIT-045: with three copies, the two lower-priority ones are redundant."""
    first = make_stored_rule(rule_id="first", priority=10)
    second = make_stored_rule(rule_id="second", priority=20)
    third = make_stored_rule(rule_id="third", priority=30)
    reported = {f.rule_id for f in redundant_findings([first, second, third])}
    assert reported == {"second", "third"}


def test_disabled_rules_are_excluded_from_redundancy_analysis():
    """RG-UNIT-046: a disabled copy of an active rule is not reported as redundant."""
    active = make_stored_rule(rule_id="active", priority=10, enabled=True)
    disabled = make_stored_rule(rule_id="disabled", priority=20, enabled=False)
    assert redundant_findings([active, disabled]) == []


def test_equal_priority_duplicates_are_still_reported():
    """RG-UNIT-047: two identical rules at the same priority are still redundant.

    One of them is doing nothing regardless of which the device evaluates
    first, so the operator should be told.
    """
    a = make_stored_rule(rule_id="a", priority=50)
    b = make_stored_rule(rule_id="b", priority=50)
    findings = redundant_findings([a, b])
    assert len(findings) == 1


def test_single_rule_is_not_redundant():
    """RG-UNIT-048: a rule is not a duplicate of itself."""
    assert redundant_findings([make_stored_rule(rule_id="only")]) == []


def test_empty_rule_base_has_no_redundancy_findings():
    """RG-UNIT-049: an empty rule base produces no redundancy findings."""
    assert redundant_findings([]) == []


@pytest.mark.parametrize(
    ("source_a", "source_b", "expected"),
    [
        ("any", "any", True),
        ("0.0.0.0/0", "0.0.0.0/0", True),
        ("any", "0.0.0.0/0", True),
        ("10.0.0.0/24", "10.0.0.0/24", True),
        ("10.0.0.0/24", "10.0.1.0/24", False),
    ],
    ids=[
        "both-keyword",
        "both-cidr",
        "keyword-vs-equivalent-cidr",
        "identical-networks",
        "different-networks",
    ],
)
def test_duplicate_detection_normalises_equivalent_networks(source_a, source_b, expected):
    """RG-UNIT-050: two spellings of the same network make two rules duplicates.

    'any' and 0.0.0.0/0 select exactly the same traffic. A rule base that uses
    both spellings still has a duplicate, and a plain string comparison of the
    source field will not see it.
    """
    a = make_stored_rule(rule_id="a", priority=10, source=source_a)
    b = make_stored_rule(rule_id="b", priority=20, source=source_b)
    assert is_duplicate(a, b) is expected
