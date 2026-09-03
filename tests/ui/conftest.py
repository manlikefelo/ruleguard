"""UI test fixtures.

The live server runs in its own process rather than a thread. See RG-BUG-006:
the API tests use FastAPI's TestClient, which drives the app through an anyio
portal on the main thread, and starting uvicorn in a thread afterwards
deadlocks during startup. A subprocess shares no event loop state with the test
process, so the two layers stay independent no matter what order they run in.

Because the server is out of process, the autouse clean_store fixture cannot
reach its repository. These tests reset state over HTTP instead, through the
reset_server_state fixture below.
"""

import socket
import subprocess
import sys
import time

import httpx
import pytest

TENANT_KEYS = ["key-acme-001", "key-globex-002", "key-initech-003"]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def live_server() -> str:
    """Run the app with uvicorn in a subprocess and yield its base URL."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Poll /health until it answers rather than sleeping a fixed amount. The
    # deadline is what fails the fixture, so a server that never comes up
    # produces a clear error instead of a hung test run.
    deadline = time.monotonic() + 30
    while True:
        if process.poll() is not None:
            output = process.stdout.read().decode(errors="replace") if process.stdout else ""
            raise RuntimeError(f"uvicorn exited during startup:\n{output}")
        if time.monotonic() > deadline:
            process.terminate()
            raise RuntimeError("uvicorn did not answer /health within 30 seconds")
        try:
            if httpx.get(f"{base_url}/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)

    yield base_url

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    finally:
        # Close the pipe explicitly. Leaving it to the garbage collector raises
        # ResourceWarning during a later test, and the suite treats warnings
        # as errors.
        if process.stdout is not None:
            process.stdout.close()


@pytest.fixture(autouse=True)
def reset_server_state(live_server):
    """Delete every rule from every tenant before and after each UI test.

    The root clean_store fixture resets the in-process repository, which is not
    the one the browser talks to. Without this, UI tests would inherit each
    other's rules and stop being order independent.
    """

    def wipe() -> None:
        with httpx.Client(base_url=live_server, timeout=10) as http:
            for key in TENANT_KEYS:
                headers = {"X-API-Key": key}
                for rule in http.get("/api/v1/rules", headers=headers).json():
                    http.delete(f"/api/v1/rules/{rule['id']}", headers=headers)

    wipe()
    yield
    wipe()


@pytest.fixture
def rules_page(page, live_server):
    """Open the rules screen with tenant A's key already set."""
    from tests.ui.pages.rules_page import RulesPage

    rules = RulesPage(page, live_server)
    rules.open()
    return rules


@pytest.fixture
def api_seed(live_server):
    """Create rules over HTTP so the browser sees them on the next load."""

    def _seed(payloads, api_key="key-acme-001"):
        created = []
        with httpx.Client(base_url=live_server, timeout=10) as http:
            for payload in payloads:
                response = http.post("/api/v1/rules", json=payload, headers={"X-API-Key": api_key})
                assert response.status_code == 201, response.text
                created.append(response.json())
        return created

    return _seed
