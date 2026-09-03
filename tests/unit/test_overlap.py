"""Network and port overlap maths.

These are the lowest-level helpers in the analyzer. Everything above them
inherits their bugs, so the boundary tables here are deliberately dense.
"""

import pytest

from app.analyzer import (
    network_contains,
    networks_overlap,
    ports_contain,
    ports_overlap,
    protocols_match,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------- networks


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("10.0.0.0/24", "10.0.0.0/24", True),
        ("10.0.0.0/8", "10.1.2.0/24", True),
        ("10.1.2.0/24", "10.0.0.0/8", True),
        ("10.0.0.0/24", "10.0.1.0/24", False),
        ("10.0.0.0/24", "192.168.0.0/24", False),
        ("0.0.0.0/0", "10.0.0.0/24", True),
        ("any", "10.0.0.0/24", True),
        ("any", "any", True),
        ("10.0.0.1/32", "10.0.0.0/24", True),
        ("10.0.0.1/32", "10.0.0.2/32", False),
        ("10.0.0.0/31", "10.0.0.1/32", True),
        ("10.0.0.0/31", "10.0.0.2/32", False),
    ],
    ids=[
        "identical-24",
        "wide-contains-narrow",
        "narrow-inside-wide",
        "adjacent-24s-do-not-overlap",
        "unrelated-networks",
        "default-route-covers-all",
        "any-keyword-covers-all",
        "any-vs-any",
        "host-route-inside-24",
        "two-distinct-host-routes",
        "p2p-link-contains-member",
        "p2p-link-excludes-neighbour",
    ],
)
def test_networks_overlap_truth_table(a, b, expected):
    """RG-UNIT-001: networks_overlap agrees with the CIDR containment truth table."""
    assert networks_overlap(a, b) is expected


@pytest.mark.parametrize(
    ("outer", "inner", "expected"),
    [
        ("10.0.0.0/8", "10.1.2.0/24", True),
        ("10.1.2.0/24", "10.0.0.0/8", False),
        ("10.0.0.0/24", "10.0.0.0/24", True),
        ("0.0.0.0/0", "10.0.0.0/24", True),
        ("0.0.0.0/0", "0.0.0.0/0", True),
        ("any", "10.0.0.0/24", True),
        ("10.0.0.0/24", "any", False),
        ("10.0.0.0/24", "10.0.0.5/32", True),
        ("10.0.0.0/24", "10.0.1.5/32", False),
        ("10.0.0.0/30", "10.0.0.0/31", True),
        ("10.0.0.0/31", "10.0.0.0/30", False),
    ],
    ids=[
        "8-contains-24",
        "24-does-not-contain-8",
        "identical-contains-itself",
        "default-route-contains-24",
        "default-contains-default",
        "any-contains-24",
        "24-does-not-contain-any",
        "24-contains-host",
        "24-excludes-foreign-host",
        "30-contains-31",
        "31-does-not-contain-30",
    ],
)
def test_network_contains_truth_table(outer, inner, expected):
    """RG-UNIT-002: network_contains is directional and handles the any keyword."""
    assert network_contains(outer, inner) is expected


@pytest.mark.parametrize(
    "literal_any",
    ["any", "0.0.0.0/0"],
    ids=["keyword", "cidr"],
)
def test_any_spellings_are_equivalent(literal_any):
    """RG-UNIT-003: the two ways of writing 'the whole internet' behave identically.

    A rule base written by hand uses 'any'. One exported from a device uses
    0.0.0.0/0. The analyzer must not care which spelling it is given.
    """
    assert network_contains(literal_any, "10.0.0.0/24") is True
    assert networks_overlap(literal_any, "192.168.1.0/24") is True


@pytest.mark.parametrize(
    "bad_cidr",
    [
        "10.0.0.0/33",
        "999.1.1.1/24",
        "10.0.0.1/24",
        "",
        "not-a-network",
        "10.0.0.0/",
        "10.0.0.0//24",
    ],
    ids=[
        "prefix-too-long",
        "octet-out-of-range",
        "host-bits-set",
        "empty-string",
        "free-text",
        "trailing-slash",
        "double-slash",
    ],
)
def test_malformed_cidr_raises_value_error(bad_cidr):
    """RG-UNIT-004: malformed CIDR input raises ValueError rather than passing silently.

    A parse failure that returns False instead of raising would make every
    comparison against a broken rule quietly report 'no overlap', which hides
    the problem instead of surfacing it.
    """
    with pytest.raises(ValueError):
        networks_overlap(bad_cidr, "10.0.0.0/24")


def test_ipv6_input_does_not_crash_with_type_error():
    """RG-UNIT-005: an IPv6 rule produces a clean validation error, not a TypeError.

    Either the analyzer supports v6 or it rejects it, but it must not raise an
    unhandled TypeError from comparing an IPv6Network with an IPv4Network.
    """
    with pytest.raises(ValueError):
        networks_overlap("2001:db8::/32", "10.0.0.0/24")


def test_mixed_ipv4_and_ipv6_comparison_is_handled():
    """RG-UNIT-006: comparing a v6 network against a v4 network is a ValueError."""
    with pytest.raises(ValueError):
        network_contains("2001:db8::/32", "10.0.0.0/8")


# ------------------------------------------------------------------- ports


@pytest.mark.parametrize(
    ("a_start", "a_end", "b_start", "b_end", "expected"),
    [
        (80, 443, 80, 443, True),
        (80, 443, 100, 200, True),
        (100, 200, 80, 443, True),
        (80, 443, 444, 500, False),
        (80, 443, 443, 500, True),
        (80, 443, 500, 600, False),
        (443, 443, 443, 443, True),
        (443, 443, 444, 444, False),
        (0, 65535, 443, 443, True),
        (0, 0, 0, 0, True),
        (65535, 65535, 65535, 65535, True),
        (0, 100, 100, 200, True),
        (0, 99, 100, 200, False),
    ],
    ids=[
        "identical-ranges",
        "b-inside-a",
        "a-inside-b",
        "adjacent-ranges-do-not-overlap",
        "touching-ranges-share-443",
        "clearly-disjoint",
        "same-single-port",
        "adjacent-single-ports",
        "full-range-covers-single",
        "port-zero-only",
        "port-65535-only",
        "ranges-touch-at-100",
        "ranges-stop-one-short",
    ],
)
def test_ports_overlap_truth_table(a_start, a_end, b_start, b_end, expected):
    """RG-UNIT-007: port ranges are inclusive at both ends.

    The touching cases matter most. 80-443 and 443-500 both contain port 443,
    so they overlap. A strict less-than comparison gets this wrong.
    """
    assert ports_overlap(a_start, a_end, b_start, b_end) is expected


@pytest.mark.parametrize(
    ("outer_start", "outer_end", "inner_start", "inner_end", "expected"),
    [
        (0, 65535, 80, 443, True),
        (80, 443, 80, 443, True),
        (80, 443, 100, 200, True),
        (100, 200, 80, 443, False),
        (80, 443, 80, 444, False),
        (80, 443, 79, 443, False),
        (443, 443, 443, 443, True),
        (0, 65535, 0, 65535, True),
    ],
    ids=[
        "full-range-contains-web",
        "identical",
        "strict-subset",
        "not-a-subset",
        "inner-exceeds-upper-bound",
        "inner-below-lower-bound",
        "single-port-contains-itself",
        "full-contains-full",
    ],
)
def test_ports_contain_truth_table(outer_start, outer_end, inner_start, inner_end, expected):
    """RG-UNIT-008: ports_contain requires full inclusive coverage."""
    assert ports_contain(outer_start, outer_end, inner_start, inner_end) is expected


def test_ports_overlap_is_symmetric():
    """RG-UNIT-009: swapping the two ranges never changes the answer.

    Asymmetry here would make shadow detection depend on iteration order,
    which is exactly the kind of bug that only shows up under --random-order.
    """
    cases = [(80, 443, 443, 500), (0, 100, 100, 200), (80, 443, 444, 500), (22, 22, 22, 22)]
    for a_start, a_end, b_start, b_end in cases:
        forward = ports_overlap(a_start, a_end, b_start, b_end)
        backward = ports_overlap(b_start, b_end, a_start, a_end)
        assert forward == backward, f"asymmetric for {(a_start, a_end, b_start, b_end)}"


# --------------------------------------------------------------- protocols


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("any", "tcp", True),
        ("any", "udp", True),
        ("any", "icmp", True),
        ("any", "any", True),
        ("tcp", "tcp", True),
        ("tcp", "udp", False),
        ("tcp", "any", False),
        ("udp", "icmp", False),
        ("icmp", "icmp", True),
    ],
    ids=[
        "any-covers-tcp",
        "any-covers-udp",
        "any-covers-icmp",
        "any-covers-any",
        "tcp-covers-tcp",
        "tcp-does-not-cover-udp",
        "tcp-does-not-cover-any",
        "udp-does-not-cover-icmp",
        "icmp-covers-icmp",
    ],
)
def test_protocols_match_truth_table(a, b, expected):
    """RG-UNIT-010: protocol coverage is directional, and only 'any' is a wildcard."""
    assert protocols_match(a, b) is expected
