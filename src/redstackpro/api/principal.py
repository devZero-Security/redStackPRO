"""Identity and error shape.

A Principal is a union of a human and an API key from the first release, because
the agent harness is a key holder rather than a user and shaping the principal as
a user row would mean bolting agents on badly. See 0009.

For the POC the resolver returns a hardcoded local principal. Swapping in OIDC or
reverse proxy header trust is a change to `resolve` and nothing else.
"""

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

LOCAL_ORG_ID = "00000000000000000000000000000001"
LOCAL_USER_ID = "00000000000000000000000000000002"


@dataclass(frozen=True)
class Principal:
    id: str
    org_id: str
    kind: str          # human or api_key
    role: str          # admin or member
    label: str = ""

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_agent(self):
        return self.kind == "api_key"


LOCAL_PRINCIPAL = Principal(
    id=LOCAL_USER_ID,
    org_id=LOCAL_ORG_ID,
    kind="human",
    role="admin",
    label="local",
)


def resolve(request: Request) -> Principal:
    """The POC trusts the local principal. The eventual answer is OIDC or a
    validated identity from a reverse proxy, never a local password table."""
    return getattr(request.app.state, "principal", LOCAL_PRINCIPAL)


CurrentPrincipal = Depends(resolve)


class ApiError(HTTPException):
    """Structured errors, not status codes alone. See architecture.md.

    The body carries a stable machine readable code, prose for a reader, and a
    details object. The agent harness reads code and details; a person reads the
    message.
    """

    def __init__(self, status_code, code, message, **details):
        super().__init__(status_code=status_code, detail={
            "code": code,
            "message": message,
            "details": details,
        })


def not_found(what, ident):
    return ApiError(404, "not_found", "No %s with id %s." % (what, ident),
                    resource=what, id=ident)


def forbidden(message, **details):
    return ApiError(403, "forbidden", message, **details)


def conflict(message, **details):
    return ApiError(409, "conflict", message, **details)


def invalid(message, **details):
    return ApiError(422, "invalid_request", message, **details)
