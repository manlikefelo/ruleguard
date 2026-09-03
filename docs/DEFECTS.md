# Defect log

Six defects found by running the test suite. The first five came out of the
initial run against the first working build of the analyzer. RG-BUG-006 turned
up later, when the layers were run together for the first time, and is a fault
in the test framework rather than in the application.

Every one was written up before the fix went in, which is why the evidence
sections quote failing output rather than describing it.

Baseline commit for RG-BUG-001 to RG-BUG-005: `110ae71`. Environment: Windows
10, Python 3.12.10, pytest 8.3.4, run locally.

Summary:

| ID | Summary | Severity | Component | Status |
|---|---|---|---|---|
| RG-BUG-001 | Malformed CIDR accepted on create, then crashes analysis with a 500 | Critical | models, analyzer | Fixed |
| RG-BUG-002 | Port overlap misses inclusive boundaries, single-port rules never overlap | High | analyzer | Fixed |
| RG-BUG-003 | Permissive rules written as `0.0.0.0/0` are not reported | High | analyzer | Fixed |
| RG-BUG-004 | Rule covered by two broader rules is reported twice | Medium | analyzer | Fixed |
| RG-BUG-005 | Duplicate rules at equal priority are never reported | Medium | analyzer | Fixed |
| RG-BUG-006 | Full suite deadlocks when API tests run before UI tests | High | test framework | Fixed |

---

### RG-BUG-001: Malformed CIDR is accepted on create and crashes the analysis endpoint

**Severity:** Critical **Priority:** P1 **Component:** app/models.py, app/analyzer.py
**Environment:** local, Python 3.12.10, commit `110ae71`

**Steps to reproduce:**

1. `POST /api/v1/rules` with `source` of `10.0.0.0/8`, everything else valid.
2. `POST /api/v1/rules` with `source` of `10.0.0.0/33`.
3. `GET /api/v1/analysis`.

**Expected:** step 2 returns 422 and the rule is never stored. A netmask of 33
does not exist in IPv4.

**Actual:** step 2 returns 201. Step 3 raises an unhandled exception out of the
route and the request fails with a 500.

```
create with /33 -> 201
analysis CRASHED -> NetmaskValueError: '33' is not a valid netmask
```

One rule alone does not trigger it, because the pairwise loops never parse a
rule that has nothing to compare against. The crash appears as soon as a second
rule exists, so in practice it lands on the first real rule base rather than in
anyone's smoke test.

The same path accepts `999.1.1.1/24`, `10.0.0.1/24` (host bits set), an empty
string, free text, and IPv6 networks such as `2001:db8::/32`. The IPv6 case is
worse than the others: it parses successfully, so it survives until the moment
it is compared against an IPv4 network and raises `TypeError` instead.

**Evidence:** seven failing cases in
`tests/api/test_validation.py::test_malformed_cidr_is_rejected_at_the_api_boundary`
and `::test_ipv6_source_is_rejected_with_a_clear_error`, plus the manual
reproduction above.

**Root cause:** `source` and `destination` were typed as plain `str` on the
model. Nothing parsed them until `_to_network` did, deep inside the analyzer,
by which point the bad value was already persisted and there was no route-level
handler to turn a parse failure into a 4xx.

**Fix:** commit `d85cc30`. Added a field validator on `RuleCreate` that runs the value through
`ipaddress.IPv4Network` at creation time and rejects anything that does not
parse, including IPv6 input, with an explicit message. Validation now happens
once at the boundary rather than on every analysis run.

**Regression tests:** `RG-API-033`, `RG-API-034`, `RG-API-035`, `RG-UNIT-004`,
`RG-UNIT-005`, `RG-UNIT-006`

---

### RG-BUG-002: Port ranges that touch at one end are not treated as overlapping

**Severity:** High **Priority:** P2 **Component:** app/analyzer.py
**Environment:** local, Python 3.12.10, commit `110ae71`

**Steps to reproduce:**

1. Call `ports_overlap(80, 443, 443, 500)`.
2. Call `ports_overlap(443, 443, 443, 443)`.

**Expected:** both return `True`. Port ranges are inclusive at both ends, so
80-443 and 443-500 both contain port 443, and a single-port range overlaps
itself.

**Actual:** both return `False`.

```
FAILED test_ports_overlap_truth_table[touching-ranges-share-443] - assert False is True
FAILED test_ports_overlap_truth_table[same-single-port]         - assert False is True
FAILED test_ports_overlap_truth_table[port-zero-only]           - assert False is True
FAILED test_ports_overlap_truth_table[port-65535-only]          - assert False is True
FAILED test_ports_overlap_truth_table[ranges-touch-at-100]      - assert False is True
```

The single-port cases are the damaging ones. Most firewall rules specify one
port, so `ports_overlap` returned `False` for the majority of realistic
comparisons.

**Root cause:** the implementation was `a_start < b_end and b_start < a_end`,
using strict inequalities on a range whose bounds are inclusive. Where the two
ranges share exactly one port, both comparisons fail. Where a range is a single
port, `a_start < a_end` is false by definition.

**Fix:** commit `d85cc30`. Changed both comparisons to `<=`, giving
`a_start <= b_end and b_start <= a_end`. The adjacent-range cases such as 80-443
against 444-500 still correctly report no overlap.

**Regression tests:** `RG-UNIT-007`, `RG-UNIT-009`

---

### RG-BUG-003: Overly permissive rules written as 0.0.0.0/0 are not reported

**Severity:** High **Priority:** P2 **Component:** app/analyzer.py
**Environment:** local, Python 3.12.10, commit `110ae71`

**Steps to reproduce:**

1. Create a rule with `source` and `destination` both `0.0.0.0/0`, protocol
   `any`, ports 0-65535, action `allow`.
2. `GET /api/v1/analysis`.

**Expected:** one `OVERLY_PERMISSIVE` finding at critical severity.

**Actual:** no findings. The same rule written with the literal string `any` on
both sides is reported correctly.

```
FAILED test_permissiveness_accepts_either_spelling_of_any[cidr-both-sides]
FAILED test_permissiveness_accepts_either_spelling_of_any[keyword-source-cidr-destination]
FAILED test_permissiveness_accepts_either_spelling_of_any[cidr-source-keyword-destination]
FAILED tests/api/test_analysis_endpoint.py::test_permissive_rule_written_as_cidr_is_reported
```

This is the worst kind of miss for an audit tool. It reports nothing and looks
like a clean result. Rule bases exported from a firewall render the wildcard as
`0.0.0.0/0` rather than `any`, so the check silently did nothing on the input it
would most often be given.

**Root cause:** `is_overly_permissive` compared the source and destination
strings against the literal `"any"`. Every other part of the analyzer goes
through `_to_network`, which already treats the two spellings as equivalent;
this one check compared raw strings instead.

**Fix:** commit `d85cc30`. Added an `_is_any_network` helper that parses the value and tests
whether it covers the entire address space, then used it for both the source and
the destination check. Any future spelling that parses to 0.0.0.0/0 is now
handled without another change.

**Regression tests:** `RG-UNIT-061`, `RG-API-065`

---

### RG-BUG-004: A rule shadowed by two broader rules is reported twice

**Severity:** Medium **Priority:** P3 **Component:** app/analyzer.py
**Environment:** local, Python 3.12.10, commit `110ae71`

**Steps to reproduce:**

1. Create a broad allow rule at priority 10 covering 10.0.0.0/8, all ports.
2. Create a broad deny rule at priority 20 covering the same space.
3. Create a narrow rule at priority 100 inside that space.
4. `GET /api/v1/analysis`.

**Expected:** one `SHADOWED` finding for the narrow rule.

**Actual:** two findings for the same rule, one per covering rule.

```
FAILED test_rule_shadowed_by_two_rules_is_reported_once - assert 2 == 1
FAILED tests/api/test_analysis_endpoint.py::test_doubly_shadowed_rule_is_reported_once
```

The finding count is what an operator triages against, so duplicates inflate the
apparent size of the problem. In a rule base with a broad allow and a broad deny
near the top, which is a common shape, every dead rule below them is counted
twice.

**Root cause:** the shadow detection loop appends a finding for every covering
rule it finds rather than stopping at the first one. There is no deduplication
by `rule_id`.

**Fix:** commit `d85cc30`. The loop now records the highest-priority covering rule for each
shadowed rule and emits a single finding naming it. Reporting the highest
priority one is the useful choice: that is the rule the operator has to change
for the shadowed rule to come alive.

**Regression tests:** `RG-UNIT-030`, `RG-API-069`

---

### RG-BUG-005: Duplicate rules at the same priority are never reported

**Severity:** Medium **Priority:** P3 **Component:** app/analyzer.py
**Environment:** local, Python 3.12.10, commit `110ae71`

**Steps to reproduce:**

1. Create two rules with identical source, destination, protocol, port range
   and action, both at priority 50.
2. `GET /api/v1/analysis`.

**Expected:** one `REDUNDANT` finding. One of the two rules does nothing
regardless of which the device evaluates first.

**Actual:** no findings.

```
FAILED test_equal_priority_duplicates_are_still_reported - assert 0 == 1
```

**Root cause:** the redundancy loop reports a rule only when
`other.priority < rule.priority`. The guard exists to stop a duplicate pair
being reported once from each side, but it also discards the equal-priority
case entirely, since neither rule satisfies a strict less-than against the
other.

A related gap surfaced in the same test file: `is_duplicate` compares the
source and destination as raw strings, so a pair written as `any` and
`0.0.0.0/0` is not recognised as duplicated even though the two rules select
identical traffic. Same underlying cause as RG-BUG-003, fixed in the same pass.

**Fix:** commit `d85cc30`. Replaced the priority guard with a comparison that breaks the tie on
rule id when priorities are equal, so exactly one of the pair is reported and
the choice is stable across runs. Network comparison in `is_duplicate` now goes
through parsed networks rather than string equality.

**Regression tests:** `RG-UNIT-044`, `RG-UNIT-047`, `RG-UNIT-050`

---

### RG-BUG-006: Full suite deadlocks when the API tests run before the UI tests

**Severity:** High **Priority:** P2 **Component:** test framework
**Environment:** local, Python 3.12.10, Windows 10, commit `d85cc30`

This one is a defect in the test suite rather than in the application. It is
recorded here because a suite that hangs is a worse problem than most product
bugs: nobody can tell whether the code is broken or the harness is.

**Steps to reproduce:**

1. `pytest tests/unit` passes in about 0.5 seconds.
2. `pytest tests/api` passes in about 3 seconds.
3. `pytest tests/ui` passes in about 22 seconds.
4. `pytest tests` hangs indefinitely at the first UI test.

**Expected:** the full suite completes. Each layer passes in isolation, so the
combination should too.

**Actual:** the run stops at
`tests/ui/test_rules_ui.py::test_page_loads_with_an_empty_rule_table` and never
returns. No failure and no error, so CI would sit at the job timeout rather
than reporting anything useful.

**Evidence:** `pytest-timeout` was installed temporarily to get a traceback out
of the stalled run:

```
tests/api/test_validation.py::test_ipv6_source_is_rejected_with_a_clear_error PASSED [ 48%]
tests/ui/test_rules_ui.py::test_page_loads_with_an_empty_rule_table[chromium]
+++++++++++++++++++++++++++++++++++ Timeout +++++++++++++++++++++++++++++++++++
    event_list = self._selector.select(timeout)
    self._poll(timeout)
```

Narrowed with a two-test probe file: a test using `TestClient` followed by a
test using the `live_server` fixture reproduces it every time, while either one
alone passes. Playwright plus `TestClient` with no `live_server` also passes,
which ruled out the browser as the cause.

**Root cause:** `live_server` started uvicorn in a background thread inside the
test process. FastAPI's `TestClient` drives the app through an anyio portal on
the main thread and leaves event loop state behind after the API tests finish.
Starting uvicorn in a thread afterwards blocks during startup, waiting on a
selector that never fires. Setting an explicit event loop in the server thread
was not enough; the coupling is through process-level state, not the loop
object.

**Fix:** commit `1c2ef12`. `live_server` now runs uvicorn as a subprocess, which
shares no event loop state with the test process. Startup polls `/health` until
it answers, with a deadline that fails the fixture rather than hanging.

The change has a consequence worth naming: the server no longer shares the
in-process repository, so the root `clean_store` fixture cannot reset what the
browser sees. A `reset_server_state` autouse fixture in the UI conftest now
deletes every rule from all three tenants over HTTP before and after each test,
which keeps the UI layer order independent by the same rule as the rest.

A second, smaller issue surfaced during the fix: the subprocess `stdout` pipe
was left for the garbage collector, which raised `ResourceWarning` partway
through a later unit test. Since `pytest.ini` sets `filterwarnings = error`,
that surfaced as an error attributed to an unrelated test. The pipe is now
closed explicitly in teardown.

**Regression test:** covered by CI running `pytest tests/unit tests/api` and
`pytest tests/ui` in the same workflow, and by the full-suite run used to verify
the fix (301 passed in 49.74s).

---

## Notes on triage

Across the first unit and API runs, eight distinct failure causes turned up.
Five were product defects, written up above. The other three were faults in the
tests themselves, recorded here so the triage is honest about the split:

- `test_priority_comparison_boundaries` passed zero and negative priorities to a
  model that validates `priority >= 1`, so the factory raised `ValidationError`
  before the analyzer was ever called. The boundary belongs in the API
  validation tests, and the parametrize table was corrected to stay within the
  values the analyzer can actually receive.
- `test_any_differing_match_field_prevents_duplication` set `port_start` to 8080
  while leaving the default `port_end` at 443, which the model rejects for the
  right reason.
- `test_every_api_endpoint_requires_a_key` passed a JSON body to GET and DELETE,
  which httpx does not accept.

None of the three indicated a problem in the application. Recording them matters
anyway: a suite where every red result is assumed to be a product defect wastes
developer time, and one where every red result is assumed to be a bad test
misses real ones.
