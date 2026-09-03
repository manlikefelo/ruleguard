"""FastAPI application: rule CRUD plus the analysis endpoint."""

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.responses import FileResponse
from pydantic import ValidationError

from app.analyzer import analyze
from app.auth import resolve_tenant
from app.models import (
    AnalysisResult,
    BulkItemResult,
    BulkResult,
    Rule,
    RuleCreate,
)
from app.repository import repository

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="RuleGuard",
    version="0.1.0",
    description="Firewall policy analysis: shadowed, redundant and overly permissive rules.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/v1/rules", response_model=Rule, status_code=status.HTTP_201_CREATED)
def create_rule(payload: RuleCreate, tenant_id: str = Depends(resolve_tenant)) -> Rule:
    return repository.add(tenant_id, payload)


@app.get("/api/v1/rules", response_model=list[Rule])
def list_rules(
    enabled: bool | None = None,
    tenant_id: str = Depends(resolve_tenant),
) -> list[Rule]:
    return repository.list(tenant_id, enabled=enabled)


@app.get("/api/v1/rules/{rule_id}", response_model=Rule)
def get_rule(rule_id: str, tenant_id: str = Depends(resolve_tenant)) -> Rule:
    rule = repository.get(tenant_id, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@app.put("/api/v1/rules/{rule_id}", response_model=Rule)
def update_rule(
    rule_id: str,
    payload: RuleCreate,
    tenant_id: str = Depends(resolve_tenant),
) -> Rule:
    rule = repository.replace(tenant_id, rule_id, payload)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@app.delete("/api/v1/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: str, tenant_id: str = Depends(resolve_tenant)) -> Response:
    if not repository.delete(tenant_id, rule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/api/v1/rules/bulk", response_model=BulkResult)
def create_rules_bulk(
    payloads: list[dict],
    tenant_id: str = Depends(resolve_tenant),
) -> BulkResult:
    """Accept a list of rules and report success or failure for each one.

    A bad item does not abort the batch. Callers get an index-aligned report
    so they can fix and resubmit only the items that failed.
    """
    results: list[BulkItemResult] = []
    created = 0
    failed = 0

    for index, raw in enumerate(payloads):
        try:
            payload = RuleCreate.model_validate(raw)
        except ValidationError as exc:
            failed += 1
            results.append(BulkItemResult(index=index, success=False, error=str(exc)))
            continue
        rule = repository.add(tenant_id, payload)
        created += 1
        results.append(BulkItemResult(index=index, success=True, rule=rule))

    return BulkResult(created=created, failed=failed, results=results)


@app.get("/api/v1/analysis", response_model=AnalysisResult)
def run_analysis(tenant_id: str = Depends(resolve_tenant)) -> AnalysisResult:
    rules = repository.list(tenant_id)
    return AnalysisResult(
        tenant_id=tenant_id,
        rule_count=len(rules),
        findings=analyze(rules),
    )
