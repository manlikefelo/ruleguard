"""Shared fixtures.

The important one is clean_store. The repository is a module-level singleton,
so without a reset between tests the suite passes in file order and fails under
--random-order or -n auto. Resetting both before and after each test means no
test can be affected by, or leak into, another one.
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.repository import repository

DATA_DIR = Path(__file__).parent / "data"

TENANT_A_KEY = "key-acme-001"
TENANT_B_KEY = "key-globex-002"
TENANT_C_KEY = "key-initech-003"


@pytest.fixture(autouse=True)
def clean_store():
    """Empty the rule store around every test."""
    repository.clear()
    yield
    repository.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def tenant_a_headers() -> dict[str, str]:
    return {"X-API-Key": TENANT_A_KEY}


@pytest.fixture
def tenant_b_headers() -> dict[str, str]:
    return {"X-API-Key": TENANT_B_KEY}


@pytest.fixture
def tenant_c_headers() -> dict[str, str]:
    return {"X-API-Key": TENANT_C_KEY}


@pytest.fixture(scope="session")
def rule_base_definitions() -> dict[str, list[dict]]:
    with open(DATA_DIR / "rule_bases.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def seeded_rule_base(
    client: TestClient,
    rule_base_definitions: dict[str, list[dict]],
) -> Callable[..., list[dict]]:
    """Load a named rule base from tests/data/rule_bases.json into a tenant.

    Returns the created rules in the order they were posted, so a test can
    refer to them positionally without depending on server-side ordering.
    """

    def _seed(name: str, headers: dict[str, str] | None = None) -> list[dict]:
        if name not in rule_base_definitions:
            raise KeyError(
                f"Unknown rule base {name!r}. Available: {sorted(rule_base_definitions)}"
            )
        headers = headers or {"X-API-Key": TENANT_A_KEY}
        created = []
        for payload in rule_base_definitions[name]:
            response = client.post("/api/v1/rules", json=payload, headers=headers)
            assert response.status_code == 201, response.text
            created.append(response.json())
        return created

    return _seed
