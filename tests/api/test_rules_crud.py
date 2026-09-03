"""CRUD contract for /api/v1/rules.

Status codes, response shape and the round trip through the store.
"""

import pytest

from tests.factories import make_rule

pytestmark = pytest.mark.api

RULE_FIELDS = {
    "id",
    "tenant_id",
    "name",
    "priority",
    "source",
    "destination",
    "protocol",
    "port_start",
    "port_end",
    "action",
    "enabled",
}


@pytest.mark.smoke
def test_health_endpoint_reports_ok(client):
    """RG-API-001: /health answers without authentication."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.smoke
def test_create_rule_returns_201_and_the_stored_rule(client, tenant_a_headers):
    """RG-API-002: a valid POST returns 201 and the rule as stored."""
    payload = make_rule(name="allow-web-dmz")
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)

    assert response.status_code == 201
    body = response.json()
    assert set(body) == RULE_FIELDS
    assert body["name"] == "allow-web-dmz"
    assert body["tenant_id"] == "tenant-acme"


def test_created_rule_gets_a_unique_server_generated_id(client, tenant_a_headers):
    """RG-API-003: the server assigns each rule its own id."""
    first = client.post("/api/v1/rules", json=make_rule(), headers=tenant_a_headers).json()
    second = client.post("/api/v1/rules", json=make_rule(), headers=tenant_a_headers).json()

    assert first["id"] != second["id"]
    assert len(first["id"]) == 36


def test_client_supplied_id_is_rejected(client, tenant_a_headers):
    """RG-API-004: a caller cannot choose a rule id.

    Accepting one would let a caller overwrite an existing rule, including
    another tenant's, by guessing its id.
    """
    payload = make_rule()
    payload["id"] = "attacker-chosen-id"
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)
    assert response.status_code == 422


def test_get_rule_returns_the_created_rule(client, tenant_a_headers):
    """RG-API-005: a rule can be fetched by the id returned at creation."""
    created = client.post("/api/v1/rules", json=make_rule(), headers=tenant_a_headers).json()

    response = client.get(f"/api/v1/rules/{created['id']}", headers=tenant_a_headers)
    assert response.status_code == 200
    assert response.json() == created


def test_get_unknown_rule_returns_404(client, tenant_a_headers):
    """RG-API-006: an id that was never issued gives 404."""
    response = client.get("/api/v1/rules/00000000-0000-0000-0000-000000000000", headers=tenant_a_headers)
    assert response.status_code == 404


def test_list_rules_returns_only_this_tenants_rules(client, tenant_a_headers):
    """RG-API-007: listing returns every rule the tenant has created."""
    for index in range(3):
        client.post("/api/v1/rules", json=make_rule(name=f"rule-{index}"), headers=tenant_a_headers)

    response = client.get("/api/v1/rules", headers=tenant_a_headers)
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 3
    assert {r["name"] for r in body} == {"rule-0", "rule-1", "rule-2"}


def test_list_rules_is_empty_for_a_fresh_tenant(client, tenant_a_headers):
    """RG-API-008: a tenant with no rules gets an empty list, not a 404."""
    response = client.get("/api/v1/rules", headers=tenant_a_headers)
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    ("query", "expected_names"),
    [
        ("?enabled=true", {"live-rule"}),
        ("?enabled=false", {"dormant-rule"}),
        ("", {"live-rule", "dormant-rule"}),
    ],
    ids=["only-enabled", "only-disabled", "no-filter"],
)
def test_list_rules_enabled_filter(client, tenant_a_headers, query, expected_names):
    """RG-API-009: the enabled query parameter filters the listing."""
    client.post(
        "/api/v1/rules",
        json=make_rule(name="live-rule", enabled=True),
        headers=tenant_a_headers,
    )
    client.post(
        "/api/v1/rules",
        json=make_rule(name="dormant-rule", enabled=False),
        headers=tenant_a_headers,
    )

    response = client.get(f"/api/v1/rules{query}", headers=tenant_a_headers)
    assert response.status_code == 200
    assert {r["name"] for r in response.json()} == expected_names


def test_update_rule_replaces_every_field(client, tenant_a_headers):
    """RG-API-010: PUT is a full replacement and keeps the original id."""
    created = client.post(
        "/api/v1/rules", json=make_rule(name="before"), headers=tenant_a_headers
    ).json()

    updated_payload = make_rule(
        name="after",
        priority=999,
        source="192.168.0.0/16",
        protocol="udp",
        port_start=53,
        port_end=53,
        action="deny",
    )
    response = client.put(
        f"/api/v1/rules/{created['id']}", json=updated_payload, headers=tenant_a_headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["name"] == "after"
    assert body["priority"] == 999
    assert body["action"] == "deny"


def test_update_unknown_rule_returns_404(client, tenant_a_headers):
    """RG-API-011: updating a rule that does not exist gives 404."""
    response = client.put(
        "/api/v1/rules/00000000-0000-0000-0000-000000000000",
        json=make_rule(),
        headers=tenant_a_headers,
    )
    assert response.status_code == 404


def test_delete_rule_returns_204_and_removes_it(client, tenant_a_headers):
    """RG-API-012: DELETE returns 204 and the rule is gone afterwards."""
    created = client.post("/api/v1/rules", json=make_rule(), headers=tenant_a_headers).json()

    response = client.delete(f"/api/v1/rules/{created['id']}", headers=tenant_a_headers)
    assert response.status_code == 204
    assert response.content == b""

    follow_up = client.get(f"/api/v1/rules/{created['id']}", headers=tenant_a_headers)
    assert follow_up.status_code == 404


def test_delete_unknown_rule_returns_404(client, tenant_a_headers):
    """RG-API-013: deleting a rule that does not exist gives 404."""
    response = client.delete(
        "/api/v1/rules/00000000-0000-0000-0000-000000000000", headers=tenant_a_headers
    )
    assert response.status_code == 404


def test_delete_is_not_idempotent_on_the_second_call(client, tenant_a_headers):
    """RG-API-014: deleting the same rule twice gives 204 then 404."""
    created = client.post("/api/v1/rules", json=make_rule(), headers=tenant_a_headers).json()

    assert client.delete(f"/api/v1/rules/{created['id']}", headers=tenant_a_headers).status_code == 204
    assert client.delete(f"/api/v1/rules/{created['id']}", headers=tenant_a_headers).status_code == 404


def test_enabled_defaults_to_true_when_omitted(client, tenant_a_headers):
    """RG-API-015: a rule created without the enabled field is active."""
    payload = make_rule()
    payload.pop("enabled")
    response = client.post("/api/v1/rules", json=payload, headers=tenant_a_headers)

    assert response.status_code == 201
    assert response.json()["enabled"] is True
