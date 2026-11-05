# RuleGuard

[![CI](https://github.com/manlikefelo/ruleguard/actions/workflows/ci.yml/badge.svg)](https://github.com/manlikefelo/ruleguard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![Tests](https://img.shields.io/badge/tests-301-brightgreen)
![Coverage](https://img.shields.io/badge/analyzer%20coverage-100%25-brightgreen)

Enterprise firewall rule bases grow to thousands of rules over years of change,
and nobody deletes anything. Three problems accumulate: rules that sit below a
broader rule and can never match, duplicate rules that add review burden without
changing behaviour, and `any/any` allow rules left behind after troubleshooting.
The first two are invisible during a manual review because the rule looks
perfectly reasonable on its own line. RuleGuard reads a rule base and reports
all three.

**This repository is a QA portfolio project.** The service is deliberately small.
The test suite around it, and the defect reports that came out of running it, are
the part worth reading.

---

## What is here

```
                      TEST SUITE (the deliverable)
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  tests/unit/    141 tests   analyzer logic, CIDR and port maths  │
  │       │                     boundary tables, determinism         │
  │       ▼                                                          │
  │  tests/api/     145 tests   HTTP contract, validation,           │
  │       │                     tenant isolation, bulk handling      │
  │       ▼                                                          │
  │  tests/ui/       15 tests   Playwright, page objects,            │
  │                             output escaping, error display       │
  └──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ exercises
  ┌──────────────────────────────────────────────────────────────────┐
  │                  SYSTEM UNDER TEST (scaffolding)                 │
  │                                                                  │
  │   app/main.py        FastAPI routes, 8 endpoints                 │
  │   app/analyzer.py    the three finding rules                     │
  │   app/models.py      Pydantic validation                         │
  │   app/auth.py        API key to tenant resolution                │
  │   app/repository.py  in-memory, tenant-scoped store              │
  │   app/static/        one HTML page, no framework                 │
  └──────────────────────────────────────────────────────────────────┘
```

## Setup

```bash
git clone https://github.com/manlikefelo/ruleguard.git && cd ruleguard
pip install -r requirements-dev.txt
playwright install chromium
pytest
```

That runs all 301 tests, including the browser layer. It takes about 50 seconds.

## Running individual layers

```bash
pytest tests/unit              # 141 tests, under a second
pytest tests/api               # 145 tests, about 3 seconds
pytest tests/ui                # 15 tests, needs chromium

pytest -m smoke                # the minimal path
pytest -m security             # tenant isolation and injection tests
pytest -m "not slow"           # skips the 1,000 rule bulk test

pytest --random-order          # proves order independence
pytest tests/unit tests/api -n auto   # parallel

pytest --cov=app --cov-report=term-missing
pytest --html=report.html --self-contained-html
```

To use the service directly:

```bash
uvicorn app.main:app --reload
```

The UI is at `http://127.0.0.1:8000` and the generated API documentation at
`http://127.0.0.1:8000/docs`. Three API keys are wired in: `key-acme-001`,
`key-globex-002` and `key-initech-003`.

## Test report

`pytest-html` output is uploaded as a CI artifact on every run.

## Documentation

| Document | What is in it |
|---|---|
| [TEST_PLAN.md](docs/TEST_PLAN.md) | Scope, approach per layer, entry and exit criteria, risks |
| [TEST_STRATEGY.md](docs/TEST_STRATEGY.md) | Why the suite is shaped this way, flakiness controls, security rationale |
| [DEFECTS.md](docs/DEFECTS.md) | Six defects with reproduction, root cause, fix and regression test |
| [TRACEABILITY.md](docs/TRACEABILITY.md) | 102 requirements mapped to covering test IDs |

## Defects found

Six real defects, all found by running the tests rather than by reading the code.
Each was written up before the fix went in, which is why the reports quote
failing output instead of describing it.

| ID | Summary | Severity |
|---|---|---|
| RG-BUG-001 | Malformed CIDR accepted on create, then crashed analysis with a 500 | Critical |
| RG-BUG-002 | Port overlap used strict comparison, so single-port rules never overlapped | High |
| RG-BUG-003 | Permissive rules written `0.0.0.0/0` were silently not reported | High |
| RG-BUG-004 | A rule covered by two broader rules was reported twice | Medium |
| RG-BUG-005 | Duplicate rules at equal priority were never reported | Medium |
| RG-BUG-006 | Full suite deadlocked when API tests ran before UI tests | High |

RG-BUG-003 is the most instructive. The check compared the
source against the literal string `"any"`, so a rule written `0.0.0.0/0` was not
reported. Both spellings mean the same thing, and device exports use the second.
The tool returned a clean report on exactly the input it would most often be
given, which for an audit tool is worse than crashing.

RG-BUG-006 was in the test framework rather than the product. Every layer passed
alone and the full run hung forever. It came from starting uvicorn in a thread
after FastAPI's `TestClient` had already set up an event loop on the main thread.
Running the server as a subprocess fixed it.

## What this project demonstrates

| Area | Where to look |
|---|---|
| Boundary value analysis | `tests/unit/test_overlap.py`, dense parametrized tables over CIDR prefixes, port edges and touching ranges |
| Equivalence partitioning | Validation tables in `tests/api/test_validation.py`, valid and invalid classes per field |
| API contract testing | `tests/api/test_rules_crud.py`, status codes, response shape, round trips |
| Security-aware test design | `tests/api/test_authorization.py`, cross-tenant access returning 404 rather than 403, body injection, near-miss API keys |
| XSS verification done properly | `tests/ui/test_rules_ui.py`, asserts the payload renders as literal text *and* that its marker never gets set, so a silently dropped value cannot pass |
| Page Object Model | `tests/ui/pages/`, zero selectors in test files, every element addressed by `data-testid` |
| Flakiness control | No `time.sleep` anywhere, autouse state reset, order independence verified in CI on every push |
| Defect investigation | `docs/DEFECTS.md`, including narrowing a deadlock to a two-test reproduction |
| Test data management | `tests/factories.py` and `tests/data/rule_bases.json`, no hard-coded payloads in tests |
| CI/CD | Three jobs, Python 3.11 and 3.12 matrix, coverage gate, artifacts on failure |

## Test suite at a glance

| Layer | Tests | Focus |
|---|---|---|
| `tests/unit/` | 141 | Analyzer logic, overlap arithmetic, boundaries, determinism |
| `tests/api/` | 145 | Contract, validation, authorization, bulk |
| `tests/ui/` | 15 | User flows, error display, output escaping |
| **Total** | **301** | Coverage on `app/analyzer.py`: **100%** |

## Notes on scope

The service is intentionally minimal, and some of what is missing is a decision
rather than an omission:

- No database. The store is a dict, which is why tenant isolation is enforced in
  application code and gets tested hard.
- No real firewall integration. Rule bases are JSON.
- IPv4 only. IPv6 input is rejected at the API boundary with a clear error
  instead of being accepted and failing later, which is what RG-BUG-001 was.
- The UI exists so there is something for the browser tests to drive. It is one
  HTML file with no framework.

## Tech

Python 3.11+, FastAPI, Pydantic v2, pytest, Playwright, GitHub Actions.
Ruff and Black for linting and formatting.
