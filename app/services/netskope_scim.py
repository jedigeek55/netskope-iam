"""
SCIM client for the Netskope tenant.

Netskope quirks (from API docs):
- Auth header: Netskope-Api-Token (not Authorization: Bearer)
- Base URL: https://<tenant>/api/v2/scim/
- Pagination: skip + limit  (NOT SCIM-standard startIndex/count)
- Must resolve email → Netskope SCIM UUID before PUT/PATCH/DELETE
"""
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from ..config import settings
from ..models.group import Group
from ..models.netskope_config import NetskopeConfig
from ..models.user import User


def get_netskope_config(db: Optional[Session]) -> Optional[NetskopeConfig]:
    """Return the saved Netskope connection settings row, if one has been configured via the UI."""
    if db is None:
        return None
    return db.query(NetskopeConfig).filter(NetskopeConfig.id == 1).first()


class NetskopeScimClient:
    def __init__(self, db: Optional[Session] = None) -> None:
        cfg = get_netskope_config(db)
        if cfg and cfg.tenant:
            self.tenant = cfg.tenant
            self.token = cfg.scim_token or ""
            self.verify = cfg.verify_ssl
        else:
            self.tenant = settings.netskope_tenant
            self.token = settings.netskope_scim_token
            self.verify = settings.netskope_verify_ssl
        self.base = f"https://{self.tenant}/api/v2/scim"
        self.headers = {
            "Netskope-Api-Token": self.token,
            "Content-Type": "application/scim+json;charset=utf-8",
            "Accept": "application/scim+json",
        }

    def is_configured(self) -> bool:
        return bool(self.tenant and self.token)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = httpx.get(
            f"{self.base}/{path}",
            headers=self.headers,
            params=params or {},
            timeout=20,
            verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict) -> dict:
        resp = httpx.post(
            f"{self.base}/{path}",
            headers=self.headers,
            json=payload,
            timeout=20,
            verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, payload: dict) -> None:
        resp = httpx.patch(
            f"{self.base}/{path}",
            headers=self.headers,
            json=payload,
            timeout=20,
            verify=self.verify,
        )
        resp.raise_for_status()

    def _paginate(self, resource: str) -> list[dict]:
        """Page through all resources using Netskope's skip/limit params."""
        results: list[dict] = []
        skip = 0
        limit = 100
        while True:
            data = self._get(resource, {"limit": limit, "skip": skip})
            page = data.get("Resources", [])
            results.extend(page)
            if len(page) < limit:
                break
            skip += limit
        return results

    # ── Public API ────────────────────────────────────────────────────────────

    def test_connection(self) -> tuple[bool, str]:
        if not self.is_configured():
            return False, "NETSKOPE_TENANT and NETSKOPE_SCIM_TOKEN are not set"
        try:
            self._get("Users", {"limit": 1})
            return True, f"Connected to {self.tenant}"
        except httpx.HTTPStatusError as e:
            return False, f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        except Exception as e:
            return False, str(e)

    def get_users(self) -> list[dict]:
        return self._paginate("Users")

    def get_groups(self) -> list[dict]:
        return self._paginate("Groups")

    def find_user_by_email(self, email: str) -> Optional[dict]:
        try:
            data = self._get("Users", {"filter": f'userName eq "{email}"'})
            resources = data.get("Resources", [])
            return resources[0] if resources else None
        except Exception:
            return None

    def find_group_by_name(self, name: str) -> Optional[dict]:
        try:
            data = self._get("Groups", {"filter": f'displayName eq "{name}"'})
            resources = data.get("Resources", [])
            return resources[0] if resources else None
        except Exception:
            return None

    def create_user(self, user: User) -> dict:
        return self._post("Users", {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": user.email,
            "name": {
                "givenName": user.given_name or "",
                "familyName": user.family_name or "",
            },
            "emails": [{"value": user.email, "primary": True, "type": "work"}],
            "active": user.is_active,
            "externalId": str(user.id),
            "meta": {"resourceType": "User"},
        })

    def create_group(self, group: Group) -> dict:
        return self._post("Groups", {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": group.display_name,
            "externalId": str(group.id),
            "members": [],
            "meta": {"resourceType": "Group"},
        })

    def add_member_to_group(self, netskope_group_id: str, netskope_user_id: str) -> None:
        self._patch(f"Groups/{netskope_group_id}", {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "add",
                "path": "members",
                "value": [{"value": netskope_user_id}],
            }],
        })

    def remove_member_from_group(self, netskope_group_id: str, netskope_user_id: str) -> None:
        self._patch(f"Groups/{netskope_group_id}", {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "remove",
                "path": f'members[value eq "{netskope_user_id}"]',
            }],
        })


# ── Sync operations (called from UI routes) ───────────────────────────────────

def sync_import(db) -> dict:
    """
    Pull users and groups from Netskope into local DB.
    - Creates local users/groups that don't exist yet.
    - Sets scim_id on existing records that are missing it.
    """
    client = NetskopeScimClient(db)
    results = {"users": {}, "groups": {}}

    # ── Users ──────────────────────────────────────────────────────────────
    netskope_users = client.get_users()
    u_created = u_linked = u_skipped = 0
    for nu in netskope_users:
        email = nu.get("userName", "").strip()
        if not email:
            continue
        scim_id = nu.get("id", "")
        local = db.query(User).filter(User.email == email).first()
        if local:
            if not local.scim_id and scim_id:
                local.scim_id = scim_id
                u_linked += 1
            else:
                u_skipped += 1
        else:
            name = nu.get("name", {})
            given = name.get("givenName") or None
            family = name.get("familyName") or None
            display = nu.get("displayName") or f"{given or ''} {family or ''}".strip() or email
            db.add(User(
                username=email,
                email=email,
                given_name=given,
                family_name=family,
                display_name=display,
                is_active=nu.get("active", True),
                scim_id=scim_id,
                external_id=nu.get("externalId"),
            ))
            u_created += 1
    db.commit()
    results["users"] = {"created": u_created, "linked": u_linked, "skipped": u_skipped}

    # ── Groups ─────────────────────────────────────────────────────────────
    netskope_groups = client.get_groups()
    g_created = g_linked = g_skipped = 0
    for ng in netskope_groups:
        name = ng.get("displayName", "").strip()
        if not name:
            continue
        scim_id = ng.get("id", "")
        local = db.query(Group).filter(Group.display_name == name).first()
        if local:
            if not local.scim_id and scim_id:
                local.scim_id = scim_id
                g_linked += 1
            else:
                g_skipped += 1
        else:
            db.add(Group(
                display_name=name,
                scim_id=scim_id,
                external_id=ng.get("externalId"),
            ))
            g_created += 1
    db.commit()
    results["groups"] = {"created": g_created, "linked": g_linked, "skipped": g_skipped}

    return results


def sync_push(db) -> dict:
    """
    Push local users/groups that don't have a scim_id to Netskope.
    - If the user/group already exists in Netskope (matched by email/name), links the ID.
    - Otherwise creates a new record in Netskope.
    """
    client = NetskopeScimClient(db)
    results = {"users": {}, "groups": {}}
    errors: list[str] = []

    # ── Users ──────────────────────────────────────────────────────────────
    unsynced_users = db.query(User).filter(User.scim_id == None).all()  # noqa: E711
    u_created = u_matched = 0
    for user in unsynced_users:
        try:
            existing = client.find_user_by_email(user.email)
            if existing:
                user.scim_id = existing["id"]
                u_matched += 1
            else:
                result = client.create_user(user)
                user.scim_id = result.get("id", "")
                u_created += 1
        except Exception as e:
            errors.append(f"User {user.email}: {e}")
    db.commit()
    results["users"] = {"created": u_created, "matched": u_matched}

    # ── Groups ─────────────────────────────────────────────────────────────
    unsynced_groups = db.query(Group).filter(Group.scim_id == None).all()  # noqa: E711
    g_created = g_matched = 0
    for group in unsynced_groups:
        try:
            existing = client.find_group_by_name(group.display_name)
            if existing:
                group.scim_id = existing["id"]
                g_matched += 1
            else:
                result = client.create_group(group)
                group.scim_id = result.get("id", "")
                g_created += 1
        except Exception as e:
            errors.append(f"Group {group.display_name}: {e}")
    db.commit()
    results["groups"] = {"created": g_created, "matched": g_matched}

    results["errors"] = errors
    return results
