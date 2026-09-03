"""Pydantic models for firewall rules and analysis output."""

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Protocol = Literal["tcp", "udp", "icmp", "any"]
Action = Literal["allow", "deny"]

ANY_KEYWORD = "any"


def validate_network(value: str) -> str:
    """Reject anything that is not a parseable IPv4 network or the any keyword.

    Fixes RG-BUG-001. These fields used to be plain strings, so a value like
    10.0.0.0/33 was stored happily and then blew up inside the analyzer on the
    next run. Parsing here means a bad network is refused once, at creation,
    instead of breaking every later analysis of that rule base.
    """
    if value == ANY_KEYWORD:
        return value
    try:
        ipaddress.IPv4Network(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"{value!r} is not a valid IPv4 network: {exc}") from exc
    except ipaddress.NetmaskValueError as exc:
        raise ValueError(f"{value!r} has an invalid netmask: {exc}") from exc
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a valid IPv4 network: {exc}") from exc
    return value


class RuleCreate(BaseModel):
    """Inbound payload for creating or replacing a rule.

    The tenant is never taken from the request body. It is resolved from the
    API key by the auth layer, so any tenant_id a caller sends is ignored.
    """

    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=100)
    priority: int = Field(ge=1)
    source: str
    destination: str
    protocol: Protocol
    port_start: int = Field(ge=0, le=65535)
    port_end: int = Field(ge=0, le=65535)
    action: Action
    enabled: bool = True

    @field_validator("source", "destination")
    @classmethod
    def check_network(cls, value: str) -> str:
        return validate_network(value)

    @model_validator(mode="after")
    def check_port_order(self) -> "RuleCreate":
        if self.port_end < self.port_start:
            raise ValueError("port_end must be greater than or equal to port_start")
        return self


class Rule(RuleCreate):
    """A stored rule. Adds the server-generated id and the resolved tenant."""

    id: str
    tenant_id: str


class Finding(BaseModel):
    """One issue reported by the analyzer."""

    type: Literal["SHADOWED", "REDUNDANT", "OVERLY_PERMISSIVE"]
    severity: Literal["low", "medium", "high", "critical"]
    rule_id: str
    message: str
    shadowed_by: str | None = None
    duplicate_of: str | None = None


class AnalysisResult(BaseModel):
    """Response body for GET /api/v1/analysis."""

    tenant_id: str
    rule_count: int
    findings: list[Finding]


class BulkItemResult(BaseModel):
    """Per-item outcome from the bulk create endpoint."""

    index: int
    success: bool
    rule: Rule | None = None
    error: str | None = None


class BulkResult(BaseModel):
    """Response body for POST /api/v1/rules/bulk."""

    created: int
    failed: int
    results: list[BulkItemResult]
