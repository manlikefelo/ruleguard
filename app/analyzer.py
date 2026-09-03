"""Firewall rule base analysis.

Finds three classes of policy hygiene problem:

  SHADOWED          a higher-priority rule fully covers a later one, so the
                    later rule can never match
  REDUNDANT         two rules with identical match criteria and action
  OVERLY_PERMISSIVE an allow rule with any source, any destination and the
                    full port range
"""

import ipaddress

from app.models import Finding, Rule

ANY_NETWORK = "0.0.0.0/0"


def _to_network(value: str) -> ipaddress.IPv4Network:
    """Parse a CIDR string. The literal 'any' means the whole address space."""
    if value == "any":
        return ipaddress.IPv4Network(ANY_NETWORK)
    return ipaddress.IPv4Network(value)


def networks_overlap(a: str, b: str) -> bool:
    """True if the two networks share at least one address."""
    net_a = _to_network(a)
    net_b = _to_network(b)
    return net_a.overlaps(net_b)


def network_contains(outer: str, inner: str) -> bool:
    """True if every address in inner is also in outer."""
    net_outer = _to_network(outer)
    net_inner = _to_network(inner)
    return net_inner.subnet_of(net_outer)


def ports_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """True if the two inclusive port ranges share at least one port."""
    return a_start < b_end and b_start < a_end


def ports_contain(outer_start: int, outer_end: int, inner_start: int, inner_end: int) -> bool:
    """True if the inner port range sits entirely inside the outer one."""
    return outer_start <= inner_start and inner_end <= outer_end


def protocols_match(a: str, b: str) -> bool:
    """True if protocol a covers protocol b. 'any' covers everything."""
    if a == "any":
        return True
    return a == b


def is_shadowed_by(later: Rule, earlier: Rule) -> bool:
    """True if `later` can never match because `earlier` covers all of it."""
    return (
        earlier.priority < later.priority
        and network_contains(earlier.source, later.source)
        and network_contains(earlier.destination, later.destination)
        and protocols_match(earlier.protocol, later.protocol)
        and ports_contain(earlier.port_start, earlier.port_end, later.port_start, later.port_end)
    )


def is_duplicate(a: Rule, b: Rule) -> bool:
    """True if two rules have identical match criteria and the same action."""
    return (
        a.source == b.source
        and a.destination == b.destination
        and a.protocol == b.protocol
        and a.port_start == b.port_start
        and a.port_end == b.port_end
        and a.action == b.action
    )


def is_overly_permissive(rule: Rule) -> bool:
    """True if the rule allows anything from anywhere to anywhere."""
    return (
        rule.action == "allow"
        and rule.source == "any"
        and rule.destination == "any"
        and rule.port_start == 0
        and rule.port_end == 65535
    )


def analyze(rules: list[Rule]) -> list[Finding]:
    """Run every check over a rule base and return the findings."""
    findings: list[Finding] = []
    enabled = [r for r in rules if r.enabled]

    for rule in enabled:
        for other in enabled:
            if other.id == rule.id:
                continue
            if is_shadowed_by(rule, other):
                findings.append(
                    Finding(
                        type="SHADOWED",
                        severity="high",
                        rule_id=rule.id,
                        shadowed_by=other.id,
                        message=(
                            f"Rule '{rule.name}' is fully shadowed by "
                            f"higher-priority rule '{other.name}'."
                        ),
                    )
                )

    for rule in enabled:
        for other in enabled:
            if other.id == rule.id:
                continue
            if is_duplicate(rule, other) and other.priority < rule.priority:
                findings.append(
                    Finding(
                        type="REDUNDANT",
                        severity="medium",
                        rule_id=rule.id,
                        duplicate_of=other.id,
                        message=(
                            f"Rule '{rule.name}' duplicates higher-priority "
                            f"rule '{other.name}'."
                        ),
                    )
                )

    for rule in rules:
        if is_overly_permissive(rule):
            findings.append(
                Finding(
                    type="OVERLY_PERMISSIVE",
                    severity="critical",
                    rule_id=rule.id,
                    message=(
                        f"Rule '{rule.name}' allows all traffic from any source "
                        f"to any destination on all ports."
                    ),
                )
            )

    return findings
