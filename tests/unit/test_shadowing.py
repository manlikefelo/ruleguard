"""Shadow detection.

A rule is shadowed when an earlier, broader rule already matches everything it
would match. The rule is dead policy: it sits in the rule base looking active
and does nothing.
"""

import pytest

from app.analyzer import analyze, is_shadowed_by
from tests.factories import make_stored_rule

pytestmark = pytest.mark.unit


def shadow_findings(rules):
    return [f for f in analyze(rules) if f.type == "SHADOWED"]


# ------------------------------------------------------- pairwise decisions


def test_broad_rule_shadows_narrow_rule():
    """RG-UNIT-020: a /8 at priority 10 shadows a /24 at priority 100."""
    broad = make_stored_rule(
        rule_id="broad",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    narrow = make_stored_rule(
        rule_id="narrow",
        priority=100,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
    )
    assert is_shadowed_by(narrow, broad) is True


def test_narrow_rule_does_not_shadow_broad_rule():
    """RG-UNIT-021: containment is directional, a /24 cannot shadow a /8."""
    narrow = make_stored_rule(
        rule_id="narrow",
        priority=10,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
    )
    broad = make_stored_rule(
        rule_id="broad",
        priority=100,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    assert is_shadowed_by(broad, narrow) is False


def test_lower_priority_rule_cannot_shadow_higher_priority_rule():
    """RG-UNIT-022: a rule evaluated later never shadows one evaluated earlier."""
    early = make_stored_rule(rule_id="early", priority=10)
    late = make_stored_rule(rule_id="late", priority=100)
    assert is_shadowed_by(early, late) is False


@pytest.mark.parametrize(
    ("shadower_proto", "victim_proto", "expected"),
    [
        ("any", "tcp", True),
        ("any", "udp", True),
        ("tcp", "tcp", True),
        ("tcp", "udp", False),
        ("udp", "tcp", False),
        ("tcp", "any", False),
    ],
    ids=[
        "any-shadows-tcp",
        "any-shadows-udp",
        "tcp-shadows-tcp",
        "tcp-cannot-shadow-udp",
        "udp-cannot-shadow-tcp",
        "tcp-cannot-shadow-any",
    ],
)
def test_shadowing_respects_protocol(shadower_proto, victim_proto, expected):
    """RG-UNIT-023: a rule only shadows traffic whose protocol it actually covers."""
    shadower = make_stored_rule(
        rule_id="shadower",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol=shadower_proto,
        port_start=0,
        port_end=65535,
    )
    victim = make_stored_rule(
        rule_id="victim",
        priority=100,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol=victim_proto,
        port_start=80,
        port_end=443,
    )
    assert is_shadowed_by(victim, shadower) is expected


@pytest.mark.parametrize(
    ("s_start", "s_end", "v_start", "v_end", "expected"),
    [
        (0, 65535, 80, 443, True),
        (80, 443, 80, 443, True),
        (80, 443, 100, 200, True),
        (80, 443, 80, 500, False),
        (100, 200, 80, 443, False),
        (443, 443, 443, 443, True),
    ],
    ids=[
        "full-range-shadows-web",
        "identical-ranges",
        "wider-shadows-narrower",
        "victim-exceeds-shadower",
        "shadower-too-narrow",
        "identical-single-port",
    ],
)
def test_shadowing_requires_full_port_coverage(s_start, s_end, v_start, v_end, expected):
    """RG-UNIT-024: partial port overlap is not enough to shadow a rule."""
    shadower = make_stored_rule(
        rule_id="shadower",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=s_start,
        port_end=s_end,
    )
    victim = make_stored_rule(
        rule_id="victim",
        priority=100,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=v_start,
        port_end=v_end,
    )
    assert is_shadowed_by(victim, shadower) is expected


def test_deny_rule_shadows_allow_rule():
    """RG-UNIT-025: shadowing is about reachability, not about the action.

    A broad deny above a narrow allow means the allow never fires. That is
    still dead policy and still worth reporting.
    """
    deny = make_stored_rule(
        rule_id="deny",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
        action="deny",
    )
    allow = make_stored_rule(
        rule_id="allow",
        priority=100,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
        action="allow",
    )
    assert is_shadowed_by(allow, deny) is True


def test_source_must_be_contained_not_merely_overlapping():
    """RG-UNIT-026: a partially overlapping source does not shadow.

    10.0.0.0/24 and 10.0.0.128/25 share addresses, but the /25 is only half
    covered, so traffic outside the shared part still reaches the later rule.
    """
    shadower = make_stored_rule(
        rule_id="shadower",
        priority=10,
        source="10.0.0.128/25",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    victim = make_stored_rule(
        rule_id="victim",
        priority=100,
        source="10.0.0.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
    )
    assert is_shadowed_by(victim, shadower) is False


# ------------------------------------------------------ whole-base analysis


def test_empty_rule_base_produces_no_findings():
    """RG-UNIT-027: an empty rule base analyses cleanly and returns no findings."""
    assert analyze([]) == []


def test_single_rule_is_never_shadowed():
    """RG-UNIT-028: one rule cannot shadow itself."""
    rule = make_stored_rule(rule_id="only")
    assert shadow_findings([rule]) == []


def test_disabled_rules_are_excluded_from_shadow_analysis():
    """RG-UNIT-029: a disabled rule neither shadows nor gets reported as shadowed.

    Disabled rules are not in the evaluation path, so they cannot hide
    anything, and reporting them as dead adds noise to an audit.
    """
    disabled_broad = make_stored_rule(
        rule_id="disabled",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
        enabled=False,
    )
    live_narrow = make_stored_rule(
        rule_id="live",
        priority=100,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
        enabled=True,
    )
    assert shadow_findings([disabled_broad, live_narrow]) == []


def test_rule_shadowed_by_two_rules_is_reported_once():
    """RG-UNIT-030: a rule covered by two broader rules yields one finding.

    An operator needs to know a rule is dead. Reporting it once per covering
    rule inflates the finding count and makes the report harder to triage.
    """
    first = make_stored_rule(
        rule_id="first",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
        action="allow",
    )
    second = make_stored_rule(
        rule_id="second",
        priority=20,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
        action="deny",
    )
    victim = make_stored_rule(
        rule_id="victim",
        priority=100,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=443,
        port_end=443,
    )
    findings = [f for f in shadow_findings([first, second, victim]) if f.rule_id == "victim"]
    assert len(findings) == 1


def test_chained_shadowing_reports_each_dead_rule():
    """RG-UNIT-031: when A covers B and B covers C, both B and C are reported."""
    a = make_stored_rule(
        rule_id="a",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    b = make_stored_rule(
        rule_id="b",
        priority=20,
        source="10.1.0.0/16",
        destination="10.2.0.0/16",
        protocol="tcp",
        port_start=0,
        port_end=1024,
    )
    c = make_stored_rule(
        rule_id="c",
        priority=30,
        source="10.1.1.0/24",
        destination="10.2.1.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
    )
    shadowed = {f.rule_id for f in shadow_findings([a, b, c])}
    assert shadowed == {"b", "c"}


def test_shadow_finding_names_the_covering_rule():
    """RG-UNIT-032: the finding carries the id of the rule that causes the shadow."""
    broad = make_stored_rule(
        rule_id="broad",
        name="allow-all-internal",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    narrow = make_stored_rule(
        rule_id="narrow",
        name="allow-web-dmz",
        priority=100,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
    )
    findings = shadow_findings([broad, narrow])
    assert len(findings) == 1
    assert findings[0].rule_id == "narrow"
    assert findings[0].shadowed_by == "broad"
    assert findings[0].severity == "high"
    assert "allow-web-dmz" in findings[0].message
    assert "allow-all-internal" in findings[0].message


# --------------------------------------------------------------- priorities


def test_equal_priority_rules_do_not_shadow_each_other():
    """RG-UNIT-033: two rules at the same priority produce no shadow finding.

    With no defined evaluation order between them, calling either one dead is
    a guess. The analyzer should stay quiet rather than pick arbitrarily.
    """
    alpha = make_stored_rule(
        rule_id="alpha",
        priority=50,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    beta = make_stored_rule(
        rule_id="beta",
        priority=50,
        source="10.1.0.0/16",
        destination="10.2.0.0/16",
        protocol="tcp",
        port_start=80,
        port_end=80,
    )
    assert shadow_findings([alpha, beta]) == []


def test_analysis_is_deterministic_across_repeated_runs():
    """RG-UNIT-034: the same rule base gives byte-identical findings every time.

    Run it twenty times. Any dependence on dict ordering, set iteration or
    insertion order shows up here rather than as an intermittent CI failure.
    """
    rules = [
        make_stored_rule(
            rule_id="tie-a",
            priority=50,
            source="10.0.0.0/8",
            destination="10.0.0.0/8",
            protocol="any",
            port_start=0,
            port_end=65535,
            action="allow",
        ),
        make_stored_rule(
            rule_id="tie-b",
            priority=50,
            source="10.0.0.0/8",
            destination="10.0.0.0/8",
            protocol="any",
            port_start=0,
            port_end=65535,
            action="deny",
        ),
        make_stored_rule(
            rule_id="victim",
            priority=100,
            source="10.1.0.0/16",
            destination="10.2.0.0/16",
            protocol="tcp",
            port_start=80,
            port_end=80,
        ),
    ]
    baseline = [f.model_dump() for f in analyze(rules)]
    for run in range(20):
        current = [f.model_dump() for f in analyze(rules)]
        assert current == baseline, f"run {run} differed from the first run"


def test_analysis_output_does_not_depend_on_input_order():
    """RG-UNIT-035: shuffling the rule list does not change the set of findings.

    Rules arrive from a dict-backed store. If the report changes when the
    insertion order changes, two audits of the same policy disagree.
    """
    a = make_stored_rule(
        rule_id="a",
        priority=10,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    b = make_stored_rule(
        rule_id="b",
        priority=50,
        source="10.1.0.0/16",
        destination="10.2.0.0/16",
        protocol="tcp",
        port_start=0,
        port_end=1024,
    )
    c = make_stored_rule(
        rule_id="c",
        priority=90,
        source="10.1.1.0/24",
        destination="10.2.1.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
    )

    def signature(rules):
        return sorted(
            (f.type, f.rule_id, f.shadowed_by, f.duplicate_of) for f in analyze(list(rules))
        )

    forward = signature([a, b, c])
    reverse = signature([c, b, a])
    middle = signature([b, a, c])
    assert forward == reverse == middle


@pytest.mark.parametrize(
    ("earlier_priority", "later_priority", "expected"),
    [
        (1, 2, True),
        (1, 100, True),
        (10, 10, False),
        (10, 9, False),
        (1, 999999, True),
        (999998, 999999, True),
    ],
    ids=[
        "adjacent-priorities",
        "wide-gap",
        "equal-priority-no-shadow",
        "reversed-order-no-shadow",
        "very-large-later-priority",
        "two-very-large-priorities",
    ],
)
def test_priority_comparison_boundaries(earlier_priority, later_priority, expected):
    """RG-UNIT-036: shadow detection compares priorities numerically across the range.

    The model floors priority at 1, so zero and negative values are covered by
    the validation tests in tests/api rather than here.
    """
    earlier = make_stored_rule(
        rule_id="earlier",
        priority=earlier_priority,
        source="10.0.0.0/8",
        destination="10.0.0.0/8",
        protocol="any",
        port_start=0,
        port_end=65535,
    )
    later = make_stored_rule(
        rule_id="later",
        priority=later_priority,
        source="10.1.1.0/24",
        destination="10.2.2.0/24",
        protocol="tcp",
        port_start=80,
        port_end=443,
    )
    assert is_shadowed_by(later, earlier) is expected
