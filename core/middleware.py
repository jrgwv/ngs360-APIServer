"""
Request context and access logging.

Phase 0 of the RBAC rollout (docs/RBAC.md) needs an inventory of who calls the
routes that currently have no authentication, before any of them start returning
401. There was no request logging at all -- only CORSMiddleware was registered --
so there was no way to answer "which open routes receive anonymous traffic, from
which clients and source addresses".

This middleware emits one structured line per request carrying the request id,
the claimed principal, how it authenticated, the route, the status and the
duration.

Deliberately performs NO database queries. Identity is taken from the credential
itself: a bearer JWT is decoded locally for its `sub` claim, and an API key
contributes only its non-secret prefix. Adding a lookup here would double the
authentication queries on every authenticated request, and this phase changes no
behaviour -- it only observes.

Consequently the principal recorded is CLAIMED, not validated: a request bearing
an expired or revoked token still reports its subject. For inventory purposes
that is the more useful reading, since a caller presenting a stale token is
exactly the kind of consumer that needs finding before endpoints close. The
`auth_valid` field distinguishes the two.
"""

import logging
import time
import uuid
from typing import Any

from fastapi import Request, Response
from jwt import PyJWTError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

import core.logger  # noqa: F401  -- importing installs the root log handler
from core.security import decode_token

logger = logging.getLogger(__name__)

# Header a caller may set to correlate its own logs with ours. Echoed back on the
# response, and generated when absent.
REQUEST_ID_HEADER = "X-Request-ID"

# Optional caller-supplied client name, so MCP/ETL/WES traffic is attributable
# even when their user agents are indistinguishable httpx/requests defaults.
CLIENT_APP_HEADER = "X-Client-Application"

API_KEY_PREFIX = "ngs360_"

# Paths excluded from access logging: the load balancer polls the health check
# every few seconds and would otherwise dominate the logs.
_UNLOGGED_PATHS = frozenset({"/api/health"})


def _resolve_principal(request: Request) -> dict[str, Any]:
    """
    Identify the caller from its credential, without any database access.

    Returns the fields describing the principal; never raises.
    """
    header = request.headers.get("authorization") or ""
    scheme, _, credential = header.partition(" ")

    if not credential or scheme.lower() != "bearer":
        return {"principal": None, "auth_method": "none", "auth_valid": None}

    if credential.startswith(API_KEY_PREFIX):
        # Log only the non-secret prefix -- never the key itself, which is a
        # live credential. 8 chars past "ngs360_" is enough to tell keys apart
        # while remaining useless to an attacker.
        marker = credential[len(API_KEY_PREFIX):][:8]
        return {
            "principal": f"{API_KEY_PREFIX}{marker}...",
            "auth_method": "api_key",
            # Validity needs a DB lookup, which this middleware deliberately
            # avoids; the route's own dependency decides.
            "auth_valid": None,
        }

    try:
        payload = decode_token(credential)
    except (PyJWTError, ValueError):
        # Malformed, expired or wrongly-signed: still worth recording that
        # someone tried, and with what kind of credential.
        return {"principal": None, "auth_method": "jwt", "auth_valid": False}

    return {
        "principal": payload.get("sub"),
        "auth_method": "jwt",
        "auth_valid": True,
    }


# Maps id(APIRoute) -> fully-qualified path template. Built once on first use.
#
# Needed because this FastAPI version does not flatten included routers into the
# app: app.routes holds _IncludedRouter wrappers, and routing puts the *inner*
# route in scope["route"]. That route's .path is router-relative -- "/settings/{key}"
# rather than "/api/v1/settings/{key}" -- and neither root_path nor app_root_path
# carries the "/api/v1" prefix, so the full template cannot be recovered from the
# request alone. The wrapper's effective_route_contexts() pairs each inner route
# with its resolved path, which is what this map records.
#
# Keyed on identity rather than on the relative path, because relative paths are
# not unique: /search exists on the projects, runs, samples and qcmetrics routers.
_ROUTE_PATHS: dict[int, str] = {}


def _build_route_path_map(app: Any) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for route in getattr(app, "routes", []):
        # Routes registered directly on the app already carry their full path.
        path = getattr(route, "path", None)
        if isinstance(path, str):
            mapping[id(route)] = path

        # Routers included with a prefix keep their routes nested; the effective
        # context carries the fully-qualified path.
        contexts = getattr(route, "effective_route_contexts", None)
        if not callable(contexts):
            continue
        try:
            for ctx in contexts():
                inner = getattr(ctx, "original_route", None)
                full = getattr(ctx, "path", None)
                if inner is not None and isinstance(full, str):
                    mapping[id(inner)] = full
        except Exception:  # pragma: no cover - defensive, never break a request
            logger.debug("could not resolve routes for %r", route, exc_info=True)
    return mapping


def _route_name(request: Request) -> str | None:
    """
    The matched route's fully-qualified path template
    (e.g. "/api/v1/projects/{project_id}").

    Aggregating on the template rather than the concrete path is what makes the
    inventory usable -- otherwise every project id is its own bucket.
    """
    route = request.scope.get("route")
    if route is None:
        # No route matched (404), or routing has not run yet.
        return None

    global _ROUTE_PATHS
    if id(route) not in _ROUTE_PATHS:
        _ROUTE_PATHS = _build_route_path_map(request.app)

    # Fall back to the relative path rather than losing the field entirely.
    return _ROUTE_PATHS.get(id(route)) or getattr(route, "path", None)


def _authz_summary(request: Request) -> dict[str, Any]:
    """
    Flatten this request's permission checks onto the access-log line.

    Kept flat rather than nested so CloudWatch Logs Insights can filter on
    `rbac_decision` directly; Insights cannot filter inside an array.

    A route can carry more than one check. The worst decision wins, so one line
    answers "was anything refused here" without needing the individual records
    -- deny beats would_deny beats allow. Requests that ran no check at all
    contribute nothing, keeping the field absent rather than misleadingly
    "allow".
    """
    decisions = getattr(request.state, "rbac_decisions", None)
    if not decisions:
        return {}

    ranked = {"deny": 3, "would_deny": 2, "allow": 1, "skipped": 0}
    worst = max(decisions, key=lambda d: ranked.get(d["rbac_decision"], 0))
    return {
        "rbac_mode": worst["rbac_mode"],
        "rbac_decision": worst["rbac_decision"],
        "required_permission": worst["required_permission"],
        "scope": worst["scope"],
        "rbac_checks": len(decisions),
        # Only present when the check recorded one; absent rather than null so
        # `filter ispresent(rbac_subject)` selects exactly those requests.
        **({"rbac_subject": worst["rbac_subject"]}
           if "rbac_subject" in worst else {}),
    }


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a request id, then log one line per request."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        request.state.request_id = request_id

        principal = _resolve_principal(request)
        request.state.principal = principal["principal"]
        request.state.auth_method = principal["auth_method"]

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Log the failure with full context, then re-raise so FastAPI's
            # exception handling is unchanged.
            logger.exception(
                "request failed",
                extra={
                    "event": "http.request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "route_name": _route_name(request),
                    "status": 500,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "client_ip": _client_ip(request),
                    "user_agent": request.headers.get("user-agent"),
                    "client_app": request.headers.get(CLIENT_APP_HEADER),
                    **principal,
                },
            )
            raise

        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        response.headers[REQUEST_ID_HEADER] = request_id

        if request.url.path not in _UNLOGGED_PATHS:
            logger.info(
                "%s %s -> %s",
                request.method,
                request.url.path,
                response.status_code,
                extra={
                    "event": "http.request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "route_name": _route_name(request),
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "client_ip": _client_ip(request),
                    "user_agent": request.headers.get("user-agent"),
                    "client_app": request.headers.get(CLIENT_APP_HEADER),
                    **principal,
                    **_authz_summary(request),
                },
            )

        return response


def _client_ip(request: Request) -> str | None:
    """
    Originating address.

    The app sits behind nginx and an ALB, so request.client.host is the proxy.
    The left-most X-Forwarded-For entry is the caller as seen by the ALB.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
