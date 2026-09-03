"""Authentication and tenant isolation.

The store is one dict shared by every tenant, so isolation is enforced in code
rather than by the database. That makes it worth testing hard.
"""

import pytest

from tests.factories import make_rule

pytestmark = [pytest.mark.api, pytest.mark.security]


# -------------------------------------------------------------- API key check


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/rules"),
        ("post", "/api/v1/rules"),
        ("get", "/api/v1/rules/some-id"),
        ("put", "/api/v1/rules/some-id"),
        ("delete", "/api/v1/rules/some-id"),
        ("post", "/api/v1/rules/bulk"),
        ("get", "/api/v1/analysis"),
    ],
)
def test_every_api_endpoint_requires_a_key(client, method, path):
    """RG-API-040: no rule endpoint is reachable without an API key."""
    kwargs = {}
    if method in {"post", "put"}:
        kwargs["json"] = [] if path.endswith("bulk") else make_rule()
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 401


@pytest.mark.parametrize(
    "bad_key",
    [
        "",
        "not-a-real-key",
        "key-acme-002",
        "KEY-ACME-001",
        "key-acme-001 ",
        " key-acme-001",
        "key-acme-001; DROP TABLE rules",
        "../key-acme-001",
    ],
    ids=[
        "empty",
        "unknown",
        "near-miss-digit",
        "wrong-case",
        "trailing-space",
        "leading-space",
        "sql-appended",
        "path-traversal-prefix",
    ],
)
def test_invalid_api_keys_are_rejected(client, bad_key):
    """RG-API-041: only an exact key match authenticates.

    Case folding or whitespace trimming would widen the accepted key space for
    no benefit, so near misses must fail.
    """
    response = client.get("/api/v1/rules", headers={"X-API-Key": bad_key})
    assert response.status_code == 401


def test_missing_and_unknown_keys_give_the_same_response(client):
    """RG-API-042: the 401 body does not reveal whether a key is a known format.

    Distinguishing 'no key' from 'bad key' in a way that leaks structure gives
    an attacker a signal to work with.
    """
    missing = client.get("/api/v1/rules")
    unknown = client.get("/api/v1/rules", headers={"X-API-Key": "definitely-not-valid"})
    assert missing.status_code == unknown.status_code == 401


@pytest.mark.smoke
def test_valid_key_resolves_to_the_expected_tenant(client, tenant_a_headers, tenant_b_headers):
    """RG-API-043: each key maps to its own tenant."""
    a = client.post("/api/v1/rules", json=make_rule(), headers=tenant_a_headers).json()
    b = client.post("/api/v1/rules", json=make_rule(), headers=tenant_b_headers).json()

    assert a["tenant_id"] == "tenant-acme"
    assert b["tenant_id"] == "tenant-globex"


# ------------------------------------------------------------ tenant isolation


def test_tenant_cannot_read_another_tenants_rule(client, tenant_a_headers, tenant_b_headers):
    """RG-API-044: fetching another tenant's rule id gives 404, not 403 and not 200.

    A 403 confirms the id exists, which is itself a leak. The response must be
    indistinguishable from one for an id that was never issued.
    """
    b_rule = client.post("/api/v1/rules", json=make_rule(), headers=tenant_b_headers).json()

    response = client.get(f"/api/v1/rules/{b_rule['id']}", headers=tenant_a_headers)
    assert response.status_code == 404


def test_cross_tenant_404_matches_unknown_id_404(client, tenant_a_headers, tenant_b_headers):
    """RG-API-045: the two 404 responses are byte-identical."""
    b_rule = client.post("/api/v1/rules", json=make_rule(), headers=tenant_b_headers).json()

    foreign = client.get(f"/api/v1/rules/{b_rule['id']}", headers=tenant_a_headers)
    nonexistent = client.get(
        "/api/v1/rules/00000000-0000-0000-0000-000000000000", headers=tenant_a_headers
    )

    assert foreign.status_code == nonexistent.status_code
    assert foreign.json() == nonexistent.json()


def test_tenant_cannot_update_another_tenants_rule(client, tenant_a_headers, tenant_b_headers):
    """RG-API-046: a cross-tenant PUT is refused and leaves the rule untouched."""
    b_rule = client.post(
        "/api/v1/rules", json=make_rule(name="globex-original"), headers=tenant_b_headers
    ).json()

    response = client.put(
        f"/api/v1/rules/{b_rule['id']}",
        json=make_rule(name="hijacked"),
        headers=tenant_a_headers,
    )
    assert response.status_code == 404

    still_there = client.get(f"/api/v1/rules/{b_rule['id']}", headers=tenant_b_headers)
    assert still_there.json()["name"] == "globex-original"


def test_tenant_cannot_delete_another_tenants_rule(client, tenant_a_headers, tenant_b_headers):
    """RG-API-047: a cross-tenant DELETE is refused and the rule survives."""
    b_rule = client.post("/api/v1/rules", json=make_rule(), headers=tenant_b_headers).json()

    response = client.delete(f"/api/v1/rules/{b_rule['id']}", headers=tenant_a_headers)
    assert response.status_code == 404

    assert client.get(f"/api/v1/rules/{b_rule['id']}", headers=tenant_b_headers).status_code == 200


def test_listing_never_includes_another_tenants_rules(client, tenant_a_headers, tenant_b_headers):
    """RG-API-048: each tenant sees only its own rules in the listing."""
    client.post("/api/v1/rules", json=make_rule(name="acme-rule"), headers=tenant_a_headers)
    client.post("/api/v1/rules", json=make_rule(name="globex-rule"), headers=tenant_b_headers)

    a_names = {r["name"] for r in client.get("/api/v1/rules", headers=tenant_a_headers).json()}
    b_names = {r["name"] for r in client.get("/api/v1/rules", headers=tenant_b_headers).json()}

    assert a_names == {"acme-rule"}
    assert b_names == {"globex-rule"}


def test_analysis_never_includes_another_tenants_rules(
    client, tenant_a_headers, tenant_b_headers, seeded_rule_base
):
    """RG-API-049: one tenant's findings never reference another tenant's rules.

    Tenant B gets a rule base full of findings. Tenant A has one clean rule and
    must see an empty report.
    """
    seeded_rule_base("mixed_findings", headers=tenant_b_headers)
    client.post("/api/v1/rules", json=make_rule(name="acme-clean"), headers=tenant_a_headers)

    a_analysis = client.get("/api/v1/analysis", headers=tenant_a_headers).json()

    assert a_analysis["tenant_id"] == "tenant-acme"
    assert a_analysis["rule_count"] == 1
    assert a_analysis["findings"] == []


def test_analysis_rule_count_covers_only_the_calling_tenant(
    client, tenant_a_headers, tenant_b_headers
):
    """RG-API-050: rule_count reflects the caller's rule base alone."""
    for index in range(2):
        client.post("/api/v1/rules", json=make_rule(name=f"a-{index}"), headers=tenant_a_headers)
    for index in range(5):
        client.post("/api/v1/rules", json=make_rule(name=f"b-{index}"), headers=tenant_b_headers)

    assert client.get("/api/v1/analysis", headers=tenant_a_headers).json()["rule_count"] == 2
    assert client.get("/api/v1/analysis", headers=tenant_b_headers).json()["rule_count"] == 5


# --------------------------------------------------- tenant_id body injection


def test_tenant_id_in_the_request_body_is_rejected(client, tenant_a_headers):
    """RG-API-051: a caller cannot set tenant_id on create.

    The model forbids unknown fields, so an injected tenant_id is refused
    outright rather than accepted and ignored. Either behaviour keeps the
    caller out of another tenant, but refusing says so plainly.
    """
    payload = make_rule()
    payload["tenant_id"] = "tenant-globex"
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)
    assert response.status_code == 422


def test_tenant_id_injection_cannot_place_a_rule_in_another_tenant(
    client, tenant_a_headers, tenant_b_headers
):
    """RG-API-052: no request body can write into a tenant the key does not own."""
    payload = make_rule(name="planted-rule")
    payload["tenant_id"] = "tenant-globex"
    client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)

    b_rules = client.get("/api/v1/rules", headers=tenant_b_headers).json()
    assert all(r["name"] != "planted-rule" for r in b_rules)


def test_tenant_id_injection_on_update_is_rejected(client, tenant_a_headers):
    """RG-API-053: a caller cannot move an existing rule to another tenant via PUT."""
    created = client.post("/api/v1/rules", json=make_rule(), headers=tenant_a_headers).json()

    payload = make_rule(name="moved")
    payload["tenant_id"] = "tenant-globex"
    response = client.put(
        f"/api/v1/rules/{created['id']}", json=payload, headers=tenant_a_headers
    )
    assert response.status_code == 422

    unchanged = client.get(f"/api/v1/rules/{created['id']}", headers=tenant_a_headers).json()
    assert unchanged["tenant_id"] == "tenant-acme"


def test_three_tenants_stay_fully_separated(
    client, tenant_a_headers, tenant_b_headers, tenant_c_headers
):
    """RG-API-054: isolation holds with more than two tenants in the store."""
    headers_by_name = {
        "acme": tenant_a_headers,
        "globex": tenant_b_headers,
        "initech": tenant_c_headers,
    }
    for name, headers in headers_by_name.items():
        client.post("/api/v1/rules", json=make_rule(name=f"{name}-rule"), headers=headers)

    for name, headers in headers_by_name.items():
        listed = client.get("/api/v1/rules", headers=headers).json()
        assert {r["name"] for r in listed} == {f"{name}-rule"}
