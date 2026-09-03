"""API key to tenant resolution.

Static key map. There is no user model, no registration and no password flow;
the only thing this layer exists to prove is that a caller can never reach
another tenant's data.
"""

from fastapi import Header, HTTPException, status

API_KEYS = {
    "key-acme-001": "tenant-acme",
    "key-globex-002": "tenant-globex",
    "key-initech-003": "tenant-initech",
}


def resolve_tenant(x_api_key: str | None = Header(default=None)) -> str:
    """FastAPI dependency returning the tenant that owns the request.

    A missing key and an unknown key both give 401. We do not distinguish
    between them in the response, since telling a caller that a key is
    well-formed but unrecognised is free information for an attacker.
    """
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    tenant = API_KEYS.get(x_api_key)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return tenant
