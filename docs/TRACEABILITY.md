# Requirements traceability matrix

Every requirement maps to the tests that cover it. Test IDs appear in the
docstring of the test that carries them, so `grep -r "RG-API-044" tests/` finds
the covering test from the ID alone.

Status values: **Covered** means at least one test asserts the requirement and
passes. **Covered (regression)** means the requirement was added or corrected in
response to a defect, and the covering test would have failed before the fix.

---

## 1. Shadowed rule detection

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-001 | A rule fully covered by a higher-priority rule is reported as SHADOWED | RG-UNIT-020, RG-UNIT-032, RG-API-062 | Covered |
| RG-REQ-002 | Containment is directional: a narrow rule does not shadow a broad one | RG-UNIT-021 | Covered |
| RG-REQ-003 | A lower-priority rule never shadows a higher-priority rule | RG-UNIT-022, RG-UNIT-036 | Covered |
| RG-REQ-004 | Shadowing requires the covering rule's protocol to cover the victim's | RG-UNIT-023 | Covered |
| RG-REQ-005 | Shadowing requires full port range coverage, not partial overlap | RG-UNIT-024, RG-UNIT-008 | Covered |
| RG-REQ-006 | Shadowing requires network containment, not partial overlap | RG-UNIT-026, RG-UNIT-002 | Covered |
| RG-REQ-007 | A deny rule can shadow an allow rule | RG-UNIT-025 | Covered |
| RG-REQ-008 | Disabled rules neither shadow nor are reported as shadowed | RG-UNIT-029, RG-API-067 | Covered |
| RG-REQ-009 | A rule covered by two rules is reported exactly once | RG-UNIT-030, RG-API-069 | Covered (regression, RG-BUG-004) |
| RG-REQ-010 | Chained shadowing reports every dead rule in the chain | RG-UNIT-031, RG-API-068 | Covered |
| RG-REQ-011 | Two rules at equal priority produce no shadow finding | RG-UNIT-033 | Covered |
| RG-REQ-012 | The finding names the covering rule and carries high severity | RG-UNIT-032, RG-API-062 | Covered |

## 2. Redundant rule detection

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-020 | Two rules with identical match criteria and action are redundant | RG-UNIT-040, RG-API-063 | Covered |
| RG-REQ-021 | Any differing match field prevents duplication | RG-UNIT-041 | Covered |
| RG-REQ-022 | Name and priority do not affect duplicate detection | RG-UNIT-042 | Covered |
| RG-REQ-023 | The lower-priority copy is the one reported | RG-UNIT-043, RG-API-063 | Covered |
| RG-REQ-024 | A duplicate pair is reported once, not once per direction | RG-UNIT-044 | Covered |
| RG-REQ-025 | Three identical rules report the two later copies | RG-UNIT-045 | Covered |
| RG-REQ-026 | Disabled rules are excluded from redundancy analysis | RG-UNIT-046 | Covered |
| RG-REQ-027 | Duplicates at equal priority are still reported | RG-UNIT-047 | Covered (regression, RG-BUG-005) |
| RG-REQ-028 | Equivalent network spellings count as duplicates | RG-UNIT-050 | Covered (regression, RG-BUG-005) |
| RG-REQ-029 | The finding names the original rule and carries medium severity | RG-UNIT-043 | Covered |

## 3. Overly permissive rule detection

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-040 | An allow rule with any source, any destination and all ports is reported | RG-UNIT-060, RG-API-064 | Covered |
| RG-REQ-041 | Both `any` and `0.0.0.0/0` spellings are recognised | RG-UNIT-061, RG-UNIT-003, RG-API-065 | Covered (regression, RG-BUG-003) |
| RG-REQ-042 | A deny rule is never reported as overly permissive | RG-UNIT-062 | Covered |
| RG-REQ-043 | Anything short of the full port range is not permissive | RG-UNIT-063 | Covered |
| RG-REQ-044 | The finding applies to every protocol including specific ones | RG-UNIT-064 | Covered |
| RG-REQ-045 | A disabled permissive rule is still reported | RG-UNIT-066 | Covered |
| RG-REQ-046 | The finding carries critical severity and names the rule | RG-UNIT-065, RG-API-064 | Covered |
| RG-REQ-047 | A properly scoped rule base reports nothing | RG-UNIT-067, RG-API-066 | Covered |

## 4. Analyzer correctness and determinism

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-060 | An empty rule base analyses cleanly with no findings | RG-UNIT-027, RG-UNIT-049, RG-UNIT-068, RG-API-060 | Covered |
| RG-REQ-061 | A single rule produces no shadowing or redundancy findings | RG-UNIT-028, RG-UNIT-048 | Covered |
| RG-REQ-062 | Repeated analysis of an unchanged rule base gives identical output | RG-UNIT-034, RG-API-070 | Covered |
| RG-REQ-063 | Findings do not depend on the order rules are supplied in | RG-UNIT-035 | Covered |
| RG-REQ-064 | One rule base can produce all three finding types at once | RG-API-072 | Covered |
| RG-REQ-065 | Deleting a rule updates the analysis on the next call | RG-API-071 | Covered |
| RG-REQ-066 | Analysis of a 300 rule base completes and returns a valid report | RG-API-079 | Covered |

## 5. Network and port arithmetic

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-080 | Network overlap follows CIDR containment rules | RG-UNIT-001 | Covered |
| RG-REQ-081 | Network containment is directional | RG-UNIT-002 | Covered |
| RG-REQ-082 | `any` and `0.0.0.0/0` behave identically everywhere | RG-UNIT-003 | Covered |
| RG-REQ-083 | Host routes (/32) and point-to-point links (/31) compare correctly | RG-UNIT-001, RG-UNIT-002 | Covered |
| RG-REQ-084 | Adjacent networks do not overlap | RG-UNIT-001 | Covered |
| RG-REQ-085 | Malformed CIDR raises rather than returning a wrong answer | RG-UNIT-004 | Covered (regression, RG-BUG-001) |
| RG-REQ-086 | IPv6 and mixed-family comparison raise a clear error | RG-UNIT-005, RG-UNIT-006 | Covered (regression, RG-BUG-001) |
| RG-REQ-087 | Port ranges are inclusive at both ends | RG-UNIT-007 | Covered (regression, RG-BUG-002) |
| RG-REQ-088 | Port range containment requires full coverage | RG-UNIT-008 | Covered |
| RG-REQ-089 | Port overlap is symmetric | RG-UNIT-009 | Covered |
| RG-REQ-090 | Protocol matching treats `any` as the only wildcard | RG-UNIT-010 | Covered |

## 6. CRUD contract

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-100 | `/health` answers 200 without authentication | RG-API-001 | Covered |
| RG-REQ-101 | POST returns 201 and the stored rule | RG-API-002 | Covered |
| RG-REQ-102 | The server generates a unique id per rule | RG-API-003 | Covered |
| RG-REQ-103 | A client-supplied id is rejected | RG-API-004 | Covered |
| RG-REQ-104 | GET by id returns the rule as created | RG-API-005 | Covered |
| RG-REQ-105 | GET for an unissued id returns 404 | RG-API-006 | Covered |
| RG-REQ-106 | Listing returns the tenant's rules, empty list when there are none | RG-API-007, RG-API-008 | Covered |
| RG-REQ-107 | The `enabled` query parameter filters the listing | RG-API-009 | Covered |
| RG-REQ-108 | PUT fully replaces the rule and keeps its id | RG-API-010 | Covered |
| RG-REQ-109 | PUT on an unknown id returns 404 | RG-API-011 | Covered |
| RG-REQ-110 | DELETE returns 204 with an empty body and removes the rule | RG-API-012 | Covered |
| RG-REQ-111 | DELETE on an unknown id returns 404 | RG-API-013, RG-API-014 | Covered |
| RG-REQ-112 | `enabled` defaults to true when omitted | RG-API-015 | Covered |
| RG-REQ-113 | Bulk creation reports per-item success and failure | RG-API-073, RG-API-074, RG-API-075 | Covered |
| RG-REQ-114 | Bulk handles a 1,000 rule payload | RG-API-078 | Covered |
| RG-REQ-115 | Bulk respects tenant scoping | RG-API-076 | Covered |
| RG-REQ-116 | An empty bulk request is accepted and creates nothing | RG-API-077 | Covered |
| RG-REQ-117 | The analysis response carries tenant_id, rule_count and findings | RG-API-061 | Covered |

## 7. Tenant isolation and authentication

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-140 | Every rule endpoint requires an API key | RG-API-040 | Covered |
| RG-REQ-141 | Only an exact key match authenticates | RG-API-041 | Covered |
| RG-REQ-142 | Missing and unknown keys give the same 401 | RG-API-042 | Covered |
| RG-REQ-143 | Each key resolves to its own tenant | RG-API-043 | Covered |
| RG-REQ-144 | A cross-tenant read returns 404, not 403 and not 200 | RG-API-044 | Covered |
| RG-REQ-145 | The cross-tenant 404 is identical to an unknown-id 404 | RG-API-045 | Covered |
| RG-REQ-146 | A cross-tenant update is refused and changes nothing | RG-API-046 | Covered |
| RG-REQ-147 | A cross-tenant delete is refused and the rule survives | RG-API-047 | Covered |
| RG-REQ-148 | Listing never includes another tenant's rules | RG-API-048 | Covered |
| RG-REQ-149 | Analysis never includes another tenant's rules | RG-API-049, RG-API-050 | Covered |
| RG-REQ-150 | A `tenant_id` in the request body is rejected on create | RG-API-051, RG-API-052 | Covered |
| RG-REQ-151 | A `tenant_id` in the request body is rejected on update | RG-API-053 | Covered |
| RG-REQ-152 | Isolation holds with three tenants in the store | RG-API-054 | Covered |

## 8. Input validation

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-170 | Name accepts 1 to 100 characters and rejects 0 and 101 | RG-API-020 | Covered |
| RG-REQ-171 | Unicode and emoji names round-trip unchanged | RG-API-021 | Covered |
| RG-REQ-172 | Injection-shaped names are stored verbatim, never interpreted | RG-API-022, RG-UI-013 | Covered |
| RG-REQ-173 | Ports accept 0 to 65535 and reject values outside it | RG-API-023 | Covered |
| RG-REQ-174 | `port_end` must be at or after `port_start` | RG-API-023 | Covered |
| RG-REQ-175 | A port range on an ICMP rule round-trips unchanged | RG-API-024 | Covered |
| RG-REQ-176 | Priority must be a positive integer | RG-API-025 | Covered |
| RG-REQ-177 | Protocol and action are closed lowercase enums | RG-API-026, RG-API-027 | Covered |
| RG-REQ-178 | Every required field is enforced | RG-API-028, RG-API-031 | Covered |
| RG-REQ-179 | Wrong field types are rejected rather than coerced | RG-API-029 | Covered |
| RG-REQ-180 | Unrecognised fields are rejected | RG-API-030 | Covered |
| RG-REQ-181 | Malformed JSON is rejected | RG-API-032 | Covered |
| RG-REQ-182 | Malformed CIDR is rejected at creation | RG-API-033 | Covered (regression, RG-BUG-001) |
| RG-REQ-183 | Valid IPv4 networks and the `any` keyword are accepted | RG-API-034 | Covered |
| RG-REQ-184 | IPv6 input is rejected with a clear error | RG-API-035 | Covered (regression, RG-BUG-001) |

## 9. User interface

| Req ID | Requirement | Covering tests | Status |
|---|---|---|---|
| RG-REQ-200 | The page loads with an empty rule table and no error | RG-UI-001 | Covered |
| RG-REQ-201 | A rule added through the form appears in the table | RG-UI-002, RG-UI-003 | Covered |
| RG-REQ-202 | Deleting a rule removes its row and leaves others alone | RG-UI-004, RG-UI-005 | Covered |
| RG-REQ-203 | Running an analysis renders findings in the panel | RG-UI-006, RG-UI-008 | Covered |
| RG-REQ-204 | A clean rule base shows an explicit no-findings state | RG-UI-007 | Covered |
| RG-REQ-205 | A rejected request shows a readable error | RG-UI-009, RG-UI-010 | Covered |
| RG-REQ-206 | A stale error clears after the next successful action | RG-UI-011 | Covered |
| RG-REQ-207 | Script payloads in rule names render as text, never execute | RG-UI-012 | Covered |

---

## Coverage summary

| Area | Requirements | Covered | Gaps |
|---|---|---|---|
| Shadowed detection | 12 | 12 | none |
| Redundant detection | 10 | 10 | none |
| Permissive detection | 8 | 8 | none |
| Analyzer correctness | 7 | 7 | none |
| Network and port maths | 11 | 11 | none |
| CRUD contract | 18 | 18 | none |
| Tenant isolation | 13 | 13 | none |
| Input validation | 15 | 15 | none |
| User interface | 8 | 8 | none |
| **Total** | **102** | **102** | **none** |

Ten of the 102 requirements are regression coverage, added in response to
RG-BUG-001 through RG-BUG-005. Each of those tests fails against the code as it
stood at commit `110ae71`.
