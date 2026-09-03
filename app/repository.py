"""In-memory, tenant-scoped rule store.

Deliberately not a database. The tests reset this between cases via the
clean_store fixture, which is what keeps the suite order-independent.
"""

import uuid

from app.models import Rule, RuleCreate


class RuleRepository:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def add(self, tenant_id: str, payload: RuleCreate) -> Rule:
        rule = Rule(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            **payload.model_dump(),
        )
        self._rules[rule.id] = rule
        return rule

    def get(self, tenant_id: str, rule_id: str) -> Rule | None:
        """Return the rule only if it belongs to this tenant.

        Callers treat a None here as a 404. A rule that exists but belongs to
        another tenant is indistinguishable from one that does not exist,
        which is the behaviour we want: no cross-tenant existence leak.
        """
        rule = self._rules.get(rule_id)
        if rule is None or rule.tenant_id != tenant_id:
            return None
        return rule

    def list(self, tenant_id: str, enabled: bool | None = None) -> list[Rule]:
        rules = [r for r in self._rules.values() if r.tenant_id == tenant_id]
        if enabled is not None:
            rules = [r for r in rules if r.enabled == enabled]
        return rules

    def replace(self, tenant_id: str, rule_id: str, payload: RuleCreate) -> Rule | None:
        existing = self.get(tenant_id, rule_id)
        if existing is None:
            return None
        updated = Rule(id=rule_id, tenant_id=tenant_id, **payload.model_dump())
        self._rules[rule_id] = updated
        return updated

    def delete(self, tenant_id: str, rule_id: str) -> bool:
        existing = self.get(tenant_id, rule_id)
        if existing is None:
            return False
        del self._rules[rule_id]
        return True

    def clear(self) -> None:
        self._rules.clear()


repository = RuleRepository()
