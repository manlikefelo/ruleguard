"""The analysis endpoint and bulk creation.

End to end checks that the analyzer findings reach the caller in the documented
shape, driven from seeded rule bases rather than hand-built dicts.
"""

import pytest

from tests.factories import make_rule

pytestmark = pytest.mark.api


def findings_of(body, finding_type):
    return [f for f in body["findings"] if f["type"] == finding_type]


@pytest.mark.smoke
def test_analysis_on_an_empty_rule_base(client, tenant_a_headers):
    """RG-API-060: an empty rule base analyses cleanly."""
    response = client.get("/api/v1/analysis", headers=tenant_a_headers)

    assert response.status_code == 200
    assert response.json() == {
        "tenant_id": "tenant-acme",
        "rule_count": 0,
        "findings": [],
    }


def test_analysis_response_has_the_documented_shape(client, tenant_a_headers, seeded_rule_base):
    """RG-API-061: the response carries tenant_id, rule_count and findings."""
    seeded_rule_base("simple_shadow", headers=tenant_a_headers)
    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()

    assert set(body) == {"tenant_id", "rule_count", "findings"}
    assert body["rule_count"] == 2
    for finding in body["findings"]:
        assert set(finding) == {
            "type",
            "severity",
            "rule_id",
            "message",
            "shadowed_by",
            "duplicate_of",
        }


def test_shadowed_rule_is_reported_through_the_api(client, tenant_a_headers, seeded_rule_base):
    """RG-API-062: a shadowed rule surfaces as a SHADOWED finding naming both rules."""
    created = seeded_rule_base("simple_shadow", headers=tenant_a_headers)
    broad, narrow = created[0], created[1]

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    shadowed = findings_of(body, "SHADOWED")

    assert len(shadowed) == 1
    assert shadowed[0]["rule_id"] == narrow["id"]
    assert shadowed[0]["shadowed_by"] == broad["id"]
    assert shadowed[0]["severity"] == "high"


def test_redundant_rule_is_reported_through_the_api(client, tenant_a_headers, seeded_rule_base):
    """RG-API-063: a duplicate pair surfaces as one REDUNDANT finding."""
    created = seeded_rule_base("redundant_pair", headers=tenant_a_headers)
    primary, copy = created[0], created[1]

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    redundant = findings_of(body, "REDUNDANT")

    assert len(redundant) == 1
    assert redundant[0]["rule_id"] == copy["id"]
    assert redundant[0]["duplicate_of"] == primary["id"]


def test_overly_permissive_rule_is_reported_through_the_api(
    client, tenant_a_headers, seeded_rule_base
):
    """RG-API-064: an any/any allow rule surfaces as a critical finding."""
    created = seeded_rule_base("overly_permissive", headers=tenant_a_headers)

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    permissive = findings_of(body, "OVERLY_PERMISSIVE")

    assert len(permissive) == 1
    assert permissive[0]["rule_id"] == created[0]["id"]
    assert permissive[0]["severity"] == "critical"


def test_permissive_rule_written_as_cidr_is_reported(client, tenant_a_headers, seeded_rule_base):
    """RG-API-065: 0.0.0.0/0 on both sides is reported the same as the any keyword."""
    seeded_rule_base("permissive_zero_cidr", headers=tenant_a_headers)

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    assert len(findings_of(body, "OVERLY_PERMISSIVE")) == 1


def test_clean_rule_base_produces_no_findings(client, tenant_a_headers, seeded_rule_base):
    """RG-API-066: a well-scoped rule base reports nothing."""
    seeded_rule_base("no_findings", headers=tenant_a_headers)

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    assert body["rule_count"] == 2
    assert body["findings"] == []


def test_disabled_rules_are_excluded_from_shadowing(client, tenant_a_headers, seeded_rule_base):
    """RG-API-067: a disabled broad rule does not shadow the live rule below it."""
    seeded_rule_base("disabled_shadow", headers=tenant_a_headers)

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    assert findings_of(body, "SHADOWED") == []


def test_chained_shadowing_reports_both_dead_rules(client, tenant_a_headers, seeded_rule_base):
    """RG-API-068: in an A covers B covers C chain, both B and C are reported."""
    created = seeded_rule_base("chained_shadow", headers=tenant_a_headers)
    ids = {rule["name"]: rule["id"] for rule in created}

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    shadowed_ids = {f["rule_id"] for f in findings_of(body, "SHADOWED")}

    assert shadowed_ids == {ids["medium-16"], ids["narrow-24"]}


def test_doubly_shadowed_rule_is_reported_once(client, tenant_a_headers, seeded_rule_base):
    """RG-API-069: a rule covered by two broader rules yields a single finding."""
    created = seeded_rule_base("double_shadow", headers=tenant_a_headers)
    victim_id = next(r["id"] for r in created if r["name"] == "victim")

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    victim_findings = [f for f in findings_of(body, "SHADOWED") if f["rule_id"] == victim_id]

    assert len(victim_findings) == 1


def test_repeated_analysis_calls_return_identical_output(
    client, tenant_a_headers, seeded_rule_base
):
    """RG-API-070: twenty consecutive calls on an unchanged rule base agree exactly.

    The store is a dict and the analyzer iterates it. If ordering leaks into
    the output, two audits of the same policy disagree.
    """
    seeded_rule_base("tie_priority", headers=tenant_a_headers)

    baseline = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    for attempt in range(20):
        current = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
        assert current == baseline, f"call {attempt} differed from the first"


def test_deleting_a_rule_updates_the_analysis(client, tenant_a_headers, seeded_rule_base):
    """RG-API-071: removing the covering rule clears the shadow finding."""
    created = seeded_rule_base("simple_shadow", headers=tenant_a_headers)
    broad = created[0]

    before = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    assert len(findings_of(before, "SHADOWED")) == 1

    client.delete(f"/api/v1/rules/{broad['id']}", headers=tenant_a_headers)

    after = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    assert after["rule_count"] == 1
    assert findings_of(after, "SHADOWED") == []


def test_mixed_rule_base_reports_every_finding_type(client, tenant_a_headers, seeded_rule_base):
    """RG-API-072: one rule base can produce all three classes of finding at once."""
    seeded_rule_base("mixed_findings", headers=tenant_a_headers)

    body = client.get("/api/v1/analysis", headers=tenant_a_headers).json()
    types_found = {f["type"] for f in body["findings"]}

    assert types_found == {"SHADOWED", "REDUNDANT", "OVERLY_PERMISSIVE"}


# ------------------------------------------------------------------- bulk


def test_bulk_create_accepts_a_valid_batch(client, tenant_a_headers):
    """RG-API-073: every rule in a valid batch is created."""
    payloads = [make_rule(name=f"bulk-rule-{i}") for i in range(10)]
    response = client.post("/api/v1/rules/bulk", json=payloads, headers=tenant_a_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["created"] == 10
    assert body["failed"] == 0
    assert len(client.get("/api/v1/rules", headers=tenant_a_headers).json()) == 10


def test_bulk_reports_per_item_outcomes(client, tenant_a_headers):
    """RG-API-074: one bad item fails alone and the good ones still get created.

    An all-or-nothing batch makes a caller resubmit a thousand valid rules
    because of one typo, so the endpoint reports each item separately.
    """
    payloads = [
        make_rule(name="good-one"),
        make_rule(name="", priority=5),
        make_rule(name="good-two"),
        make_rule(port_start=443, port_end=80),
    ]
    body = client.post("/api/v1/rules/bulk", json=payloads, headers=tenant_a_headers).json()

    assert body["created"] == 2
    assert body["failed"] == 2
    assert [item["success"] for item in body["results"]] == [True, False, True, False]
    assert body["results"][1]["error"] is not None


def test_bulk_results_are_index_aligned_with_the_request(client, tenant_a_headers):
    """RG-API-075: each result carries the index of the payload it came from."""
    payloads = [make_rule(name="ok-0"), make_rule(name=""), make_rule(name="ok-2")]
    body = client.post("/api/v1/rules/bulk", json=payloads, headers=tenant_a_headers).json()

    assert [item["index"] for item in body["results"]] == [0, 1, 2]


def test_bulk_created_rules_belong_to_the_calling_tenant(
    client, tenant_a_headers, tenant_b_headers
):
    """RG-API-076: bulk creation honours tenant scoping like the single endpoint."""
    client.post("/api/v1/rules/bulk", json=[make_rule(name="acme-bulk")], headers=tenant_a_headers)

    assert client.get("/api/v1/rules", headers=tenant_b_headers).json() == []
    a_rules = client.get("/api/v1/rules", headers=tenant_a_headers).json()
    assert a_rules[0]["tenant_id"] == "tenant-acme"


def test_bulk_with_an_empty_list_creates_nothing(client, tenant_a_headers):
    """RG-API-077: an empty batch is accepted and creates no rules."""
    body = client.post("/api/v1/rules/bulk", json=[], headers=tenant_a_headers).json()
    assert body == {"created": 0, "failed": 0, "results": []}


@pytest.mark.slow
def test_bulk_handles_one_thousand_rules(client, tenant_a_headers):
    """RG-API-078: a thousand-rule batch is accepted and every rule is stored."""
    payloads = [make_rule(name=f"scale-rule-{i}", priority=i + 1) for i in range(1000)]
    response = client.post("/api/v1/rules/bulk", json=payloads, headers=tenant_a_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["created"] == 1000
    assert body["failed"] == 0
    assert len(client.get("/api/v1/rules", headers=tenant_a_headers).json()) == 1000


@pytest.mark.slow
def test_analysis_completes_on_a_large_rule_base(client, tenant_a_headers):
    """RG-API-079: analysis of 300 rules returns a well-formed report."""
    payloads = [
        make_rule(name=f"scale-{i}", priority=i + 1, source=f"10.{i // 256}.{i % 256}.0/24")
        for i in range(300)
    ]
    client.post("/api/v1/rules/bulk", json=payloads, headers=tenant_a_headers)

    response = client.get("/api/v1/analysis", headers=tenant_a_headers)
    assert response.status_code == 200
    assert response.json()["rule_count"] == 300
