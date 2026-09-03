"""Browser tests for the rules screen.

Every assertion goes through Playwright's expect, which retries until the
condition holds or the timeout expires. There are no sleeps in this file and
there is no raw selector: all element access runs through RulesPage.
"""

import pytest
from playwright.sync_api import expect

from tests.factories import make_rule

pytestmark = pytest.mark.ui


@pytest.mark.smoke
def test_page_loads_with_an_empty_rule_table(rules_page):
    """RG-UI-001: the page opens with no rules and the empty state showing."""
    expect(rules_page.rules_table).to_be_visible()
    expect(rules_page.by_testid("rules-empty")).to_be_visible()
    expect(rules_page.error_banner).to_be_hidden()


@pytest.mark.smoke
def test_add_a_rule_and_see_it_in_the_table(rules_page):
    """RG-UI-002: a rule submitted through the form appears in the table."""
    rules_page.add_rule(name="ui-created-rule", priority=42)

    expect(rules_page.rules_table.get_by_text("ui-created-rule")).to_be_visible()
    expect(rules_page.by_testid("rules-empty")).to_be_hidden()


def test_added_rule_shows_the_values_that_were_entered(rules_page):
    """RG-UI-003: the table row reflects the submitted field values."""
    rules_page.add_rule(
        name="dns-egress",
        priority=7,
        source="192.168.10.0/24",
        destination="8.8.8.8/32",
        protocol="udp",
        port_start=53,
        port_end=53,
        action="deny",
    )

    row = rules_page.rules_table.locator("tbody tr").first
    expect(row).to_contain_text("dns-egress")
    expect(row).to_contain_text("192.168.10.0/24")
    expect(row).to_contain_text("udp")
    expect(row).to_contain_text("53-53")
    expect(row).to_contain_text("deny")


def test_delete_a_rule_removes_its_row(rules_page, api_seed):
    """RG-UI-004: the delete button removes the rule from the table."""
    created = api_seed([make_rule(name="doomed-rule")])
    rule_id = created[0]["id"]
    rules_page.open()

    expect(rules_page.rule_row(rule_id)).to_be_visible()
    rules_page.delete_rule(rule_id)

    expect(rules_page.rule_row(rule_id)).to_have_count(0)
    expect(rules_page.by_testid("rules-empty")).to_be_visible()


def test_deleting_one_rule_leaves_the_others(rules_page, api_seed):
    """RG-UI-005: deleting a rule does not disturb its neighbours."""
    created = api_seed(
        [make_rule(name="keep-one"), make_rule(name="remove-me"), make_rule(name="keep-two")]
    )
    doomed = next(r["id"] for r in created if r["name"] == "remove-me")
    rules_page.open()

    rules_page.delete_rule(doomed)

    expect(rules_page.rules_table.locator("tbody tr")).to_have_count(2)
    expect(rules_page.rules_table.get_by_text("keep-one")).to_be_visible()
    expect(rules_page.rules_table.get_by_text("keep-two")).to_be_visible()


def test_run_analysis_shows_findings(rules_page, api_seed):
    """RG-UI-006: the analyze button renders findings in the panel."""
    api_seed(
        [
            make_rule(
                name="wide-open",
                priority=1,
                source="any",
                destination="any",
                protocol="any",
                port_start=0,
                port_end=65535,
                action="allow",
            )
        ]
    )
    rules_page.open()

    rules_page.run_analysis()

    expect(rules_page.by_testid("finding-OVERLY_PERMISSIVE")).to_be_visible()
    expect(rules_page.findings_panel).to_contain_text("wide-open")


def test_analysis_on_a_clean_rule_base_reports_no_findings(rules_page, api_seed):
    """RG-UI-007: a rule base with nothing wrong shows the empty findings state."""
    api_seed([make_rule(name="well-scoped")])
    rules_page.open()

    rules_page.run_analysis()

    expect(rules_page.by_testid("no-findings")).to_be_visible()
    expect(rules_page.by_testid("no-findings")).to_contain_text("1 rules")


def test_analysis_shows_a_shadowed_finding(rules_page, api_seed):
    """RG-UI-008: a shadowed rule is reported in the panel and names both rules."""
    api_seed(
        [
            make_rule(
                name="broad-cover",
                priority=10,
                source="10.0.0.0/8",
                destination="10.0.0.0/8",
                protocol="any",
                port_start=0,
                port_end=65535,
            ),
            make_rule(
                name="dead-rule",
                priority=100,
                source="10.1.1.0/24",
                destination="10.2.2.0/24",
                protocol="tcp",
                port_start=80,
                port_end=443,
            ),
        ]
    )
    rules_page.open()

    rules_page.run_analysis()

    expect(rules_page.by_testid("finding-SHADOWED")).to_be_visible()
    expect(rules_page.findings_panel).to_contain_text("dead-rule")
    expect(rules_page.findings_panel).to_contain_text("broad-cover")


def test_invalid_api_key_shows_the_error_banner(rules_page):
    """RG-UI-009: a rejected request surfaces as a visible error, not a silent failure."""
    rules_page.set_api_key("not-a-valid-key")
    rules_page.add_rule(name="will-not-save")

    expect(rules_page.error_banner).to_be_visible()
    expect(rules_page.error_banner).to_contain_text("Invalid API key")


def test_validation_error_is_shown_to_the_user(rules_page):
    """RG-UI-010: a rule the server rejects produces a readable message."""
    rules_page.add_rule(name="bad-ports", port_start=443, port_end=80)

    expect(rules_page.error_banner).to_be_visible()
    expect(rules_page.error_banner).to_contain_text("port_end")
    expect(rules_page.rules_table.locator("tbody tr")).to_have_count(0)


def test_error_banner_clears_after_a_successful_action(rules_page):
    """RG-UI-011: a stale error does not linger once the next action succeeds."""
    rules_page.add_rule(name="bad-ports", port_start=443, port_end=80)
    expect(rules_page.error_banner).to_be_visible()

    rules_page.add_rule(name="good-rule", port_start=80, port_end=443)

    expect(rules_page.error_banner).to_be_hidden()
    expect(rules_page.rules_table.get_by_text("good-rule")).to_be_visible()


@pytest.mark.security
@pytest.mark.parametrize(
    "payload_name",
    [
        "<script>window.__pwned = true</script>",
        "<img src=x onerror='window.__pwned = true'>",
        "<svg onload='window.__pwned = true'>",
    ],
    ids=["script-tag", "img-onerror", "svg-onload"],
)
def test_script_payloads_in_rule_names_are_rendered_as_text(rules_page, api_seed, payload_name):
    """RG-UI-012: a script-shaped rule name is displayed, never executed.

    Two assertions matter here. The marker the payload tries to set must be
    absent, and the name must be visible as literal text, which proves it was
    escaped rather than stripped.
    """
    created = api_seed([make_rule(name=payload_name)])
    rule_id = created[0]["id"]
    rules_page.open()

    expect(rules_page.rule_name_cell(rule_id)).to_have_text(payload_name)
    assert rules_page.page.evaluate("() => window.__pwned === undefined") is True
    assert rules_page.page.locator("script#injected").count() == 0


@pytest.mark.security
def test_injection_shaped_name_survives_the_round_trip_unchanged(rules_page, api_seed):
    """RG-UI-013: hostile-looking text is stored and shown byte for byte.

    Sanitising on write would corrupt legitimate names. The right place to be
    careful is on render, which the escaping test above covers.
    """
    hostile = "'; DROP TABLE rules; --"
    created = api_seed([make_rule(name=hostile)])
    rules_page.open()

    expect(rules_page.rule_name_cell(created[0]["id"])).to_have_text(hostile)
