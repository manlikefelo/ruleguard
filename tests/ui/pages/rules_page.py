"""Page object for the RuleGuard rules screen.

One method per user action. Tests read as a sequence of intentions rather than
a sequence of clicks.
"""

from playwright.sync_api import Locator

from tests.ui.pages.base_page import BasePage


class RulesPage(BasePage):
    # ------------------------------------------------------------- locators

    @property
    def api_key_input(self) -> Locator:
        return self.by_testid("api-key-input")

    @property
    def add_rule_button(self) -> Locator:
        return self.by_testid("add-rule-btn")

    @property
    def analyze_button(self) -> Locator:
        return self.by_testid("analyze-btn")

    @property
    def rules_table(self) -> Locator:
        return self.by_testid("rules-table")

    @property
    def findings_panel(self) -> Locator:
        return self.by_testid("findings-panel")

    @property
    def error_banner(self) -> Locator:
        return self.by_testid("error-banner")

    @property
    def rows(self) -> Locator:
        """Every data row currently rendered in the rules table."""
        return self.rules_table.locator("tbody tr")

    def row_at(self, index: int) -> Locator:
        return self.rows.nth(index)

    def injected_script_tags(self) -> Locator:
        """Script elements a rule name may have tried to introduce.

        Used by the escaping test to prove a payload was rendered as text
        rather than parsed into the document.
        """
        return self.page.locator("script#injected")

    def rule_row(self, rule_id: str) -> Locator:
        return self.by_testid(f"rule-row-{rule_id}")

    def rule_name_cell(self, rule_id: str) -> Locator:
        return self.by_testid(f"rule-name-{rule_id}")

    def delete_button(self, rule_id: str) -> Locator:
        return self.by_testid(f"delete-rule-{rule_id}")

    # -------------------------------------------------------------- actions

    def set_api_key(self, api_key: str) -> None:
        self.api_key_input.fill(api_key)

    def add_rule(
        self,
        name: str = "allow-web-dmz",
        priority: int = 100,
        source: str = "10.0.0.0/24",
        destination: str = "10.1.0.0/24",
        protocol: str = "tcp",
        port_start: int = 80,
        port_end: int = 443,
        action: str = "allow",
        enabled: bool = True,
    ) -> None:
        self.by_testid("rule-name-input").fill(name)
        self.by_testid("rule-priority-input").fill(str(priority))
        self.by_testid("rule-source-input").fill(source)
        self.by_testid("rule-destination-input").fill(destination)
        self.by_testid("rule-protocol-input").select_option(protocol)
        self.by_testid("rule-port-start-input").fill(str(port_start))
        self.by_testid("rule-port-end-input").fill(str(port_end))
        self.by_testid("rule-action-input").select_option(action)
        self.by_testid("rule-enabled-input").select_option("true" if enabled else "false")
        self.add_rule_button.click()

    def delete_rule(self, rule_id: str) -> None:
        self.delete_button(rule_id).click()

    def run_analysis(self) -> None:
        self.analyze_button.click()

    # -------------------------------------------------------------- queries

    def row_count(self) -> int:
        return self.rows.count()

    def rule_names(self) -> list[str]:
        cells = self.rules_table.locator("tbody tr td:first-child")
        return [cells.nth(i).inner_text() for i in range(cells.count())]

    def named_row(self, name: str) -> Locator:
        """The table cell showing a given rule name."""
        return self.rules_table.get_by_text(name)

    def get_findings(self) -> list[str]:
        messages = self.findings_panel.get_by_test_id("finding-message")
        return [messages.nth(i).inner_text() for i in range(messages.count())]

    def finding_types(self) -> list[str]:
        panel_html = self.findings_panel
        types = []
        for kind in ("SHADOWED", "REDUNDANT", "OVERLY_PERMISSIVE"):
            if panel_html.get_by_test_id(f"finding-{kind}").count():
                types.append(kind)
        return types

    def get_error_text(self) -> str:
        return self.error_banner.inner_text()
