"""Shared page object behaviour.

Selectors live in page objects only. A test that reaches for a raw selector is
a test that breaks when the markup changes, and the point of this layer is that
markup changes touch one file.
"""

from playwright.sync_api import Page


class BasePage:
    def __init__(self, page: Page, base_url: str) -> None:
        self.page = page
        self.base_url = base_url

    def open(self) -> None:
        self.page.goto(self.base_url)

    def by_testid(self, testid: str):
        """Locate by data-testid.

        Every interactive element in the page carries one. No CSS class or
        positional XPath selectors, since both change for cosmetic reasons.
        """
        return self.page.get_by_test_id(testid)
