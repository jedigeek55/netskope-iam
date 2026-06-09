"""
SCIM 2.0 server — exposes /scim/v2/ so any SCIM-compatible SP (e.g. Netskope)
can provision users and groups from this IAM server.

Auth: static Bearer token configured via SCIM_BEARER_TOKEN env var.
"""
import json
import re
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session, selectinload

from ..config import settings
from ..database import get_db
from ..models.group import Group
from ..models.user import User

router = APIRouter(prefix="/scim/v2", tags=["scim-server"])

# ── SCIM schema URNs ──────────────────────────────────────────────────────────

URN_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
URN_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
URN_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
URN_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
URN_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
URN_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

SCIM_CT = "application/scim+json"

_MEMBER_FILTER_RE = re.compile(r'members\[value\s+eq\s+["\']([^"\']+)["\']\]')
_ATTR_EQ_RE = re.compile(r'^(\w+)\s+eq\s+["\'](.+)["\']$')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _j(data: dict, status: int = 200) -> Response:
    return Response(content=json.dumps(data), status_code=status, media_type=SCIM_CT)


def _err(status: int, detail: str) -> Response:
    return _j({"schemas": [URN_ERROR], "status": str(status), "detail": detail}, status)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _base(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _user_scim(user: User, base: str) -> dict:
    return {
        "schemas": [URN_USER],
        "id": str(user.id),
        "externalId": user.external_id,
        "userName": user.username,
        "name": {
            "formatted": user.display_name,
            "givenName": user.given_name,
            "familyName": user.family_name,
        },
        "displayName": user.display_name,
        "emails": [{"value": user.email, "primary": True, "type": "work"}],
        "active": user.is_active,
        "meta": {
            "resourceType": "User",
            "created": _fmt(user.created_at),
            "lastModified": _fmt(user.updated_at),
            "location": f"{base}/scim/v2/Users/{user.id}",
            "version": f'W/"{int(user.updated_at.timestamp())}"',
        },
    }


def _group_scim(group: Group, base: str) -> dict:
    return {
        "schemas": [URN_GROUP],
        "id": str(group.id),
        "externalId": group.external_id,
        "displayName": group.display_name,
        "members": [
            {
                "value": str(m.id),
                "$ref": f"{base}/scim/v2/Users/{m.id}",
                "display": m.display_name or m.email,
            }
            for m in group.members
        ],
        "meta": {
            "resourceType": "Group",
            "created": _fmt(group.created_at),
            "lastModified": _fmt(group.updated_at),
            "location": f"{base}/scim/v2/Groups/{group.id}",
        },
    }


def _list(resources: list, total: int, start: int) -> dict:
    return {
        "schemas": [URN_LIST],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def _parse_filter(f: str) -> Optional[tuple[str, str]]:
    """Parse 'attr eq "value"' → (attr, value). Returns None on no match."""
    m = _ATTR_EQ_RE.match(f.strip())
    return (m.group(1), m.group(2)) if m else None


# ── Auth ──────────────────────────────────────────────────────────────────────

def scim_auth(authorization: str = Header(default="")) -> None:
    token = settings.scim_bearer_token
    if not token:
        raise HTTPException(status_code=503, detail="SCIM_BEARER_TOKEN not configured on this server")
    if not authorization.startswith("Bearer ") or authorization[7:] != token:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing SCIM bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Pydantic models for request bodies ───────────────────────────────────────

class PatchOp(BaseModel):
    op: str
    path: Optional[str] = None
    value: Optional[Any] = None


class PatchBody(BaseModel):
    schemas: list[str]
    Operations: list[PatchOp]


# ── Service Provider Config & Schemas ─────────────────────────────────────────

@router.get("/ServiceProviderConfig", include_in_schema=False)
def service_provider_config(request: Request, _: None = Depends(scim_auth)):
    return _j({
        "schemas": [URN_SPC],
        "documentationUri": f"{_base(request)}/api/docs",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 1000},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Bearer token configured via SCIM_BEARER_TOKEN",
            "primary": True,
        }],
        "meta": {"resourceType": "ServiceProviderConfig", "location": f"{_base(request)}/scim/v2/ServiceProviderConfig"},
    })


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/Users")
def list_users(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
    startIndex: int = 1,
    count: int = 100,
    filter: str = "",
):
    base = _base(request)
    q = db.query(User)

    if filter:
        parsed = _parse_filter(filter)
        if parsed:
            attr, val = parsed
            if attr == "userName":
                q = q.filter(User.username == val)
            elif attr == "externalId":
                q = q.filter(User.external_id == val)
            elif attr == "id":
                try:
                    q = q.filter(User.id == uuid.UUID(val))
                except ValueError:
                    return _j(_list([], 0, 1))

    total = q.count()
    users = q.order_by(User.email).offset(startIndex - 1).limit(count).all()
    return _j(_list([_user_scim(u, base) for u in users], total, startIndex))


@router.post("/Users")
def create_user(
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
):
    base = _base(request)
    username = body.get("userName", "")
    if not username:
        return _err(400, "userName is required")

    if db.query(User).filter(User.username == username).first():
        return _err(409, f"User {username} already exists")

    name = body.get("name", {})
    emails = body.get("emails", [])
    email = next((e["value"] for e in emails if e.get("primary")), username)
    given = name.get("givenName") or body.get("displayName", "").split(" ")[0] or None
    family = name.get("familyName") or None
    display = body.get("displayName") or f"{given or ''} {family or ''}".strip() or username

    user = User(
        username=username,
        email=email,
        given_name=given,
        family_name=family,
        display_name=display,
        is_active=body.get("active", True),
        external_id=body.get("externalId"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _j(_user_scim(user, base), 201)


@router.get("/Users/{user_id}")
def get_user(user_id: str, request: Request, db: Session = Depends(get_db), _: None = Depends(scim_auth)):
    try:
        user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    except ValueError:
        return _err(400, "Invalid user ID")
    if not user:
        return _err(404, f"User {user_id} not found")
    return _j(_user_scim(user, _base(request)))


@router.put("/Users/{user_id}")
def replace_user(
    user_id: str,
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
):
    try:
        user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    except ValueError:
        return _err(400, "Invalid user ID")
    if not user:
        return _err(404, f"User {user_id} not found")

    name = body.get("name", {})
    emails = body.get("emails", [])
    username = body.get("userName", user.username)
    email = next((e["value"] for e in emails if e.get("primary")), username)

    user.username = username
    user.email = email
    user.given_name = name.get("givenName")
    user.family_name = name.get("familyName")
    user.display_name = body.get("displayName") or f"{name.get('givenName','') or ''} {name.get('familyName','') or ''}".strip() or username
    user.is_active = body.get("active", True)
    user.external_id = body.get("externalId", user.external_id)
    db.commit()
    db.refresh(user)
    return _j(_user_scim(user, _base(request)))


@router.patch("/Users/{user_id}")
def patch_user(
    user_id: str,
    request: Request,
    body: PatchBody,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
):
    try:
        user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    except ValueError:
        return _err(400, "Invalid user ID")
    if not user:
        return _err(404, f"User {user_id} not found")

    for op in body.Operations:
        op_name = op.op.lower()
        path = (op.path or "").lower()
        val = op.value

        if op_name in ("replace", "add"):
            if path == "active":
                user.is_active = bool(val)
            elif path == "username":
                user.username = val
                user.email = val
            elif path == "name.givenname":
                user.given_name = val
            elif path == "name.familyname":
                user.family_name = val
            elif path == "displayname":
                user.display_name = val
            elif path == "externalid":
                user.external_id = val
            elif not path and isinstance(val, dict):
                # Replace without path — val is an attribute map
                if "active" in val:
                    user.is_active = bool(val["active"])
                if "userName" in val:
                    user.username = val["userName"]
                    user.email = val["userName"]
                if "displayName" in val:
                    user.display_name = val["displayName"]
                if "name" in val:
                    n = val["name"]
                    user.given_name = n.get("givenName", user.given_name)
                    user.family_name = n.get("familyName", user.family_name)
                if "emails" in val:
                    primary = next((e["value"] for e in val["emails"] if e.get("primary")), None)
                    if primary:
                        user.email = primary

    user.display_name = user.display_name or f"{user.given_name or ''} {user.family_name or ''}".strip() or user.email
    db.commit()
    db.refresh(user)
    return _j(_user_scim(user, _base(request)))


@router.delete("/Users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), _: None = Depends(scim_auth)):
    try:
        user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    except ValueError:
        return _err(400, "Invalid user ID")
    if not user:
        return _err(404, f"User {user_id} not found")
    db.delete(user)
    db.commit()
    return Response(status_code=204)


# ── Groups ────────────────────────────────────────────────────────────────────

@router.get("/Groups")
def list_groups(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
    startIndex: int = 1,
    count: int = 100,
    filter: str = "",
):
    base = _base(request)
    q = db.query(Group).options(selectinload(Group.members))

    if filter:
        parsed = _parse_filter(filter)
        if parsed:
            attr, val = parsed
            if attr == "displayName":
                q = q.filter(Group.display_name == val)
            elif attr == "externalId":
                q = q.filter(Group.external_id == val)

    total = q.count()
    groups = q.order_by(Group.display_name).offset(startIndex - 1).limit(count).all()
    return _j(_list([_group_scim(g, base) for g in groups], total, startIndex))


@router.post("/Groups")
def create_group(
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
):
    base = _base(request)
    name = body.get("displayName", "")
    if not name:
        return _err(400, "displayName is required")
    if db.query(Group).filter(Group.display_name == name).first():
        return _err(409, f"Group '{name}' already exists")

    group = Group(
        display_name=name,
        external_id=body.get("externalId"),
    )
    db.add(group)
    db.flush()  # get id before adding members

    for m in body.get("members", []):
        mid = m.get("value", "")
        try:
            user = db.query(User).filter(User.id == uuid.UUID(mid)).first()
            if user:
                group.members.append(user)
        except ValueError:
            pass

    db.commit()
    db.refresh(group)
    return _j(_group_scim(group, base), 201)


@router.get("/Groups/{group_id}")
def get_group(group_id: str, request: Request, db: Session = Depends(get_db), _: None = Depends(scim_auth)):
    try:
        group = db.query(Group).options(selectinload(Group.members)).filter(
            Group.id == uuid.UUID(group_id)
        ).first()
    except ValueError:
        return _err(400, "Invalid group ID")
    if not group:
        return _err(404, f"Group {group_id} not found")
    return _j(_group_scim(group, _base(request)))


@router.put("/Groups/{group_id}")
def replace_group(
    group_id: str,
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
):
    try:
        group = db.query(Group).options(selectinload(Group.members)).filter(
            Group.id == uuid.UUID(group_id)
        ).first()
    except ValueError:
        return _err(400, "Invalid group ID")
    if not group:
        return _err(404, f"Group {group_id} not found")

    group.display_name = body.get("displayName", group.display_name)
    group.external_id = body.get("externalId", group.external_id)

    new_members = []
    for m in body.get("members", []):
        mid = m.get("value", "")
        try:
            user = db.query(User).filter(User.id == uuid.UUID(mid)).first()
            if user:
                new_members.append(user)
        except ValueError:
            pass
    group.members = new_members

    db.commit()
    db.refresh(group)
    return _j(_group_scim(group, _base(request)))


@router.patch("/Groups/{group_id}")
def patch_group(
    group_id: str,
    request: Request,
    body: PatchBody,
    db: Session = Depends(get_db),
    _: None = Depends(scim_auth),
):
    try:
        group = db.query(Group).options(selectinload(Group.members)).filter(
            Group.id == uuid.UUID(group_id)
        ).first()
    except ValueError:
        return _err(400, "Invalid group ID")
    if not group:
        return _err(404, f"Group {group_id} not found")

    for op in body.Operations:
        op_name = op.op.lower()
        path = op.path or ""
        val = op.value

        if op_name == "add" and path.lower() == "members":
            for m in (val if isinstance(val, list) else []):
                mid = m.get("value", "")
                try:
                    user = db.query(User).filter(User.id == uuid.UUID(mid)).first()
                    if user and user not in group.members:
                        group.members.append(user)
                except ValueError:
                    pass

        elif op_name == "remove":
            flt = _MEMBER_FILTER_RE.match(path)
            if flt:
                # remove specific member: members[value eq "user-id"]
                try:
                    uid = uuid.UUID(flt.group(1))
                    group.members = [m for m in group.members if m.id != uid]
                except ValueError:
                    pass
            elif path.lower() == "members":
                group.members = []

        elif op_name == "replace":
            if path.lower() == "displayname":
                group.display_name = val
            elif path.lower() == "members":
                new_members = []
                for m in (val if isinstance(val, list) else []):
                    mid = m.get("value", "")
                    try:
                        user = db.query(User).filter(User.id == uuid.UUID(mid)).first()
                        if user:
                            new_members.append(user)
                    except ValueError:
                        pass
                group.members = new_members
            elif not path and isinstance(val, dict):
                if "displayName" in val:
                    group.display_name = val["displayName"]

    db.commit()
    db.refresh(group)
    return _j(_group_scim(group, _base(request)))


@router.delete("/Groups/{group_id}")
def delete_group(group_id: str, db: Session = Depends(get_db), _: None = Depends(scim_auth)):
    try:
        group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
    except ValueError:
        return _err(400, "Invalid group ID")
    if not group:
        return _err(404, f"Group {group_id} not found")
    db.delete(group)
    db.commit()
    return Response(status_code=204)
