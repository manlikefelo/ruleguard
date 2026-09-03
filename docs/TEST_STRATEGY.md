# Test strategy

The test plan says what gets tested. This says why the suite is shaped the way
it is, and what I would defend in a review.

---

## The pyramid, and why this one is bottom-heavy

301 tests: 141 unit, 145 API, 15 UI.

That is a wide base and a narrow tip, and for this application it is the right
distribution. The reason is that almost all the risk in RuleGuard sits in pure
functions. Whether `10.0.0.0/24` is contained by `10.0.0.0/8`, whether ports
80-443 and 443-500 overlap, whether a rule with source `0.0.0.0/0` counts as
permissive: these are arithmetic questions with exact answers, no I/O, and no
setup cost. A parametrized case runs in microseconds, so the tables can be
dense enough to cover every boundary worth naming rather than a representative
sample.

The API layer is nearly as large as the unit layer, which is less usual. It
earns that because a third of it is authorization testing, and tenant isolation
cannot be verified below the HTTP boundary. The tenant is derived from a header
by a FastAPI dependency; testing the repository directly would skip the code
that actually makes the decision.

The UI layer is deliberately thin. Fifteen tests, covering only what a browser
can answer that a request cannot: does a script tag in a rule name render as
text, does the error banner appear when a request fails and clear when the next
one succeeds. Everything else about rule creation is already settled at the API
layer, and re-asserting it through a browser buys nothing but runtime and
flakiness.

## Why the boundary analysis leans on CIDR and port maths

Because that is where the bugs were. Three of the five defects in the log came
from the comparison helpers, and all three were boundary conditions rather than
logic errors:

- `ports_overlap` used strict `<` on inclusive bounds. Ranges touching at one
  port were judged not to overlap, and a single-port range did not overlap
  itself. Since most firewall rules specify one port, the function returned the
  wrong answer for the majority of realistic inputs while passing anything
  written with two distinct wide ranges.
- `is_overly_permissive` compared source and destination against the literal
  string `"any"`, so a rule written `0.0.0.0/0` was not reported. Device exports
  use the second spelling.
- The shadow loop emitted one finding per covering rule rather than one per
  shadowed rule.

None of these would have been caught by testing typical values. `ports_overlap(80, 443, 100, 200)`
returns the right answer under both the broken and the fixed implementation.
The bug only appears when the two ranges touch, which is why the table includes
80-443 against 443-500 and 80-443 against 444-500 side by side: one must
overlap, one must not, and the pair pins the boundary from both directions.

The same reasoning drives the CIDR table. `/31` and `/32` are in there because
point-to-point links and host routes are real firewall constructs that behave
differently from ordinary subnets. Adjacent networks such as `10.0.0.0/24` and
`10.0.1.0/24` are in there because they look similar to overlapping ones and an
off-by-one in prefix handling would confuse them.

## Flakiness controls

A suite that fails intermittently is worse than no suite, because the team
learns to re-run it rather than read it. Four controls:

**No sleeps.** There is no `time.sleep` in the test suite. Browser tests use
Playwright's auto-waiting through `expect(...)`, which retries until the
condition holds or the timeout expires. Server startup polls uvicorn's own
`started` flag with a deadline rather than guessing at a duration.

**Function-scoped state reset.** The repository is a module-level singleton. An
autouse fixture clears it before and after every test. Clearing both sides is
not redundant: before protects the test from whatever ran previously, after
keeps a failing test from poisoning the next one.

**Order independence, verified rather than assumed.** CI runs the suite three
ways on every push: in declaration order, under `--random-order`, and under
`-n auto`. It is easy to write a suite that passes in file order because test 4
depends on state test 3 left behind. Running it shuffled in CI means that
mistake surfaces on the pull request that introduces it.

**Determinism asserted in the product, not just the tests.** Two tests exist
solely to catch non-deterministic output: one runs the analyzer twenty times on
identical input and compares, the other shuffles the rule list and compares the
finding sets. Both were passing before the fix but only by accident, since the
rules happened to arrive in a stable order. The analyzer now sorts its findings
before returning them, so the guarantee is in the code rather than in the
environment.

## Security test rationale

Three concerns, chosen because they map to how this service would actually fail
in production.

**Tenant isolation is application logic, so it gets attacked directly.** There
is no database enforcing row-level access. One dict holds every tenant's rules,
and the only thing keeping them apart is a comparison in `RuleRepository.get`.
The tests attack every path into that dict: read, update, delete, list and
analysis. The cross-tenant read test asserts 404 rather than 403 specifically,
and a second test asserts the response is byte-identical to a 404 for an id
that never existed, because a distinguishable 403 confirms the id is real.

**Least privilege is the finding the tool exists to report.** The
`OVERLY_PERMISSIVE` check is the closest thing RuleGuard has to a security
control, and RG-BUG-003 showed how quietly it can fail. The parametrized table
now covers both spellings of the wildcard on both sides of the rule, plus the
scoped cases that must not fire.

**Injection-shaped input is tested at the boundary where it matters.** The API
stores hostile strings verbatim and the tests assert they round-trip unchanged.
Sanitising on write would be the wrong fix: it corrupts legitimate names and
gives false confidence, because the escaping obligation belongs to whatever
renders the value. So the UI tests carry that assertion instead, and they check
it properly. Asserting the payload is not visible would pass if the value had
been silently dropped. Instead they assert the name is displayed as literal text
and that the marker the payload tries to set is still undefined, which together
prove it was escaped rather than removed.

## What I would add next

The suite is thorough for what the service does today. Three gaps I would
close if this were going further:

- **Property-based tests** over the CIDR and port helpers. The boundary tables
  are hand-picked, and a Hypothesis strategy generating random network pairs
  would cover the space between the picked values. Symmetry and containment are
  both properties that state cleanly.
- **A contract test against the OpenAPI schema.** FastAPI generates one, and
  nothing currently asserts the responses match it. Today the assertions
  duplicate the schema by hand.
- **Mutation testing** on `app/analyzer.py`. Coverage is 100%, which says every
  line ran, not that a wrong answer would have been caught. Given that three of
  five defects were single-character comparison errors, `mutmut` would be a
  direct check on whether the suite catches exactly that class of mistake.
