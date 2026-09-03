# RuleGuard test plan

**Author:** Felix Githure
**Version:** 1.0
**Status:** Active

---

## 1. Purpose

This plan covers testing of RuleGuard, a service that reads a firewall rule base
and reports three classes of policy hygiene problem: shadowed rules, redundant
rules and overly permissive rules.

The application is small. The reason it needs a plan of this size is that its
output is used to make decisions about production firewall policy. A false
negative means an audit passes a rule base that should have failed. That is a
worse outcome than the tool crashing, because a crash is obvious and a missing
finding is not. RG-BUG-003 in the defect log is exactly this failure mode: the
permissiveness check silently did nothing on rule bases exported from a device,
and the report came back clean.

## 2. Scope

### In scope

| Area | What is covered |
|---|---|
| Analyzer logic | CIDR containment and overlap, port range maths, protocol matching, the three finding rules |
| REST API | Status codes, response schema, field validation, bulk creation, error bodies |
| Authorization | API key handling, tenant isolation across read, write, delete and analysis |
| Input validation | Boundary values, type errors, missing and extra fields, injection-shaped strings |
| Web UI | Rule creation and deletion, running an analysis, error display, output escaping |
| Determinism | Repeated analysis of an unchanged rule base, order independence of the suite itself |

### Out of scope

- Integration with real firewall vendors. Rule bases are supplied as JSON.
- Persistence. The store is in memory by design and is cleared between tests.
- Authentication beyond the static API key map. There are no user accounts.
- Load and performance testing. The suite has two tests marked `slow` that
  confirm a 1,000 rule batch and a 300 rule analysis complete, which is a
  functional check on batch handling rather than a performance measurement.
- IPv6 rule bases. The analyzer is IPv4 only and now rejects v6 input at the
  API boundary rather than accepting it and failing later.
- Browsers other than Chromium.

## 3. Test approach by layer

### 3.1 Unit tests (`tests/unit`, 141 tests)

Direct calls into `app/analyzer.py` with no HTTP layer. This is where the
boundary tables live, because the helpers are pure functions and cheap to
exercise: a parametrized case costs a few microseconds, so the tables can be
dense enough to cover every edge worth naming.

The tables cover CIDR prefixes from /0 to /32, the two spellings of the
wildcard, adjacent networks that must not overlap, partial overlaps that must
not count as containment, malformed input, port boundaries at 0 and 65535,
single-port ranges, ranges that touch at one end, and priority comparisons.

Two tests here exist purely to catch non-determinism. One runs the analyzer
twenty times on the same input and compares output. The other shuffles the rule
list and asserts the findings are unchanged.

### 3.2 API tests (`tests/api`, 145 tests)

Driven through FastAPI's `TestClient` against the real app object, so routing,
dependency injection, validation and serialisation are all in the path. No
mocking of the repository: the tests exercise the same store the application
uses, reset between cases.

Three concerns get most of the weight:

- **Contract.** Status codes and response shape for every endpoint, including
  the ones that are easy to get wrong: 204 with an empty body on delete, 404
  rather than 403 on a cross-tenant read, 422 on an unrecognised field.
- **Validation.** Every field has a boundary table. Name length is checked at
  0, 1, 50, 100, 101 and 500 characters. Ports are checked at both ends and one
  past both ends.
- **Authorization.** Covered separately in section 4.

### 3.3 UI tests (`tests/ui`, 15 tests)

Playwright against Chromium, driving a page served by a uvicorn instance
running in a background thread inside the test process. Running the server
in-process rather than as a subprocess means the same `clean_store` fixture that
resets state for the API tests also resets it here.

All element access goes through the page objects in `tests/ui/pages`. No test
file contains a selector. Every element carries a `data-testid`, so a CSS or
layout change does not break the suite.

The UI layer is deliberately thin. It exists to test the things only a browser
can answer: does a rule name containing a script tag render as text, does the
error banner appear when a request fails, does it clear when the next one
succeeds.

## 4. Security testing

Marked with `@pytest.mark.security` and runnable in isolation with
`pytest -m security`.

**Tenant isolation.** All three tenants share one dict. Isolation is enforced in
application code, not by a database, which makes it worth attacking directly.
The tests confirm that a caller cannot read, update or delete another tenant's
rule, that the analysis endpoint never returns another tenant's findings, and
that a cross-tenant fetch returns a response byte-identical to one for an id
that was never issued. A 403 would confirm the id exists, which is itself a
disclosure.

**Body injection.** A `tenant_id` supplied in the request body must never
override the one derived from the API key. The model forbids unknown fields, so
these requests are rejected outright, and a follow-up test confirms nothing was
written into the target tenant regardless.

**Key handling.** Near-miss keys are checked: wrong case, leading and trailing
whitespace, a key with SQL appended, a path traversal prefix. Any of these
succeeding would mean the comparison had been loosened in a way that widens the
accepted key space.

**Injection-shaped input.** Ten hostile string shapes are stored through the API
and read back to confirm they round-trip unchanged. Sanitising on write would
corrupt legitimate rule names, so the escaping obligation sits on render, and
the UI tests assert the browser treats the payload as text by checking that the
marker it tries to set is never defined.

## 5. Entry criteria

- The application starts and `/health` returns 200.
- Dependencies install from `requirements-dev.txt` without error.
- Interactive API documentation at `/docs` loads and lists all eight endpoints.

## 6. Exit criteria

- All tests pass on Python 3.11 and 3.12.
- The suite passes under `--random-order` and under `-n auto`.
- Line coverage on `app/analyzer.py` is 85% or above. Current: 100%.
- No open defect at Critical or High severity.
- Every defect found has a written root cause and a named regression test.
- CI is green on `main`.

## 7. Environments

| Environment | Configuration |
|---|---|
| Local development | Windows 10, Python 3.12.10, tests run against an in-process app |
| CI, unit and API | ubuntu-latest, Python 3.11 and 3.12 matrix |
| CI, UI | ubuntu-latest, Python 3.12, Chromium via `playwright install --with-deps` |

No environment needs a database, a container runtime or network access to
anything outside the test process.

## 8. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| A missed finding looks identical to a clean rule base | An audit passes policy that should have failed | Every finding rule has both positive and negative cases. The permissiveness check is tested against both spellings of the wildcard after RG-BUG-003 |
| Shared in-memory state leaks between tests | Tests pass in file order and fail in CI | Autouse fixture clears the store before and after every test. Order independence is verified in CI on every run, not just locally |
| Analyzer output depends on dict iteration order | Two audits of the same policy disagree | Findings are sorted before return. Two tests assert stability across twenty runs and across shuffled input |
| Timing-based waits in browser tests | Intermittent CI failures that erode trust in the suite | No `time.sleep` anywhere. Playwright auto-waiting and `expect` assertions only. Server startup polls a readiness flag rather than sleeping |
| Selectors coupled to markup | Cosmetic UI changes break tests | Every element has a `data-testid`. Selectors exist only inside page objects |
| Test suite grows faster than it is maintained | Duplicated setup, expensive changes | All rule payloads come from one factory. Named rule bases live in a single JSON file |

## 9. Deliverables

- Automated suite of 301 tests across three layers
- HTML test report, produced by `pytest-html` and uploaded by CI as an artifact
- Coverage report in XML and terminal form
- `docs/DEFECTS.md`, five defects with reproduction steps, root cause and fix
- `docs/TRACEABILITY.md`, requirements mapped to covering tests
- `docs/TEST_STRATEGY.md`, the reasoning behind the shape of the suite
- GitHub Actions workflow running all three layers on every push and pull request

## 10. Roles

Single contributor project. Felix Githure is responsible for the application
code, the test suite, the defect reports and the CI configuration.

## 11. Test identifiers

Tests carry an ID in their docstring, in the form `RG-<LAYER>-<NNN>`:

| Prefix | Layer |
|---|---|
| `RG-UNIT-nnn` | Analyzer and helper logic |
| `RG-API-nnn` | HTTP contract, validation, authorization |
| `RG-UI-nnn` | Browser tests |
| `RG-BUG-nnn` | Defect reports |

These IDs are what `docs/TRACEABILITY.md` maps requirements onto.
