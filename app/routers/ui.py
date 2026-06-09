import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, selectinload

from ..config import settings
from ..database import get_db
from ..models.group import Group
from ..models.user import User
from ..services.auth import create_access_token, decode_access_token, hash_password, verify_password
from ..services.netskope_scim import NetskopeScimClient, sync_import, sync_push

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory="app/templates")


def _get_current_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    try:
        user = db.query(User).filter(User.id == uuid.UUID(payload["sub"])).first()
    except (ValueError, KeyError):
        return None
    return user if user and user.is_active else None


def _require(request: Request, db: Session):
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse("/ui/login", status_code=302)
    return user


# ── Auth ─────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@router.post("/login")
def login(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
):
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        return RedirectResponse("/ui/login?error=Invalid+email+or+password", status_code=302)
    if not user.is_admin:
        return RedirectResponse("/ui/login?error=Admin+access+required", status_code=302)
    token = create_access_token({"sub": str(user.id)})
    response = RedirectResponse("/ui/dashboard", status_code=302)
    response.set_cookie("access_token", token, httponly=True, samesite="lax", max_age=3600)
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse("/ui/login", status_code=302)
    response.delete_cookie("access_token")
    return response


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": auth,
        "active": "dashboard",
        "user_count": db.query(User).count(),
        "active_user_count": db.query(User).filter(User.is_active == True).count(),
        "group_count": db.query(Group).count(),
    })


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/users", response_class=HTMLResponse)
def users_list(request: Request, db: Session = Depends(get_db), success: str = "", error: str = ""):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    users = db.query(User).order_by(User.email).all()
    return templates.TemplateResponse("users.html", {
        "request": request, "current_user": auth, "active": "users",
        "users": users, "success": success, "error": error,
    })


@router.get("/users/new", response_class=HTMLResponse)
def new_user_form(request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    return templates.TemplateResponse("user_form.html", {
        "request": request, "current_user": auth, "active": "users",
        "editing": None, "action": "/ui/users/new", "error": "",
    })


@router.post("/users/new")
def create_user(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    given_name: str = Form(""),
    family_name: str = Form(""),
    password: str = Form(...),
    is_active: Optional[str] = Form(None),
    is_admin: Optional[str] = Form(None),
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("user_form.html", {
            "request": request, "current_user": auth, "active": "users",
            "editing": None, "action": "/ui/users/new",
            "error": f"A user with email {email} already exists.",
            "form": {"email": email, "given_name": given_name, "family_name": family_name},
        })
    display = f"{given_name} {family_name}".strip() or email
    user = User(
        username=email, email=email,
        given_name=given_name or None,
        family_name=family_name or None,
        display_name=display,
        hashed_password=hash_password(password),
        is_active=is_active == "on",
        is_admin=is_admin == "on",
    )
    db.add(user)
    db.commit()
    return RedirectResponse(f"/ui/users?success=User+{email}+created", status_code=302)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
def edit_user_form(user_id: str, request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        return RedirectResponse("/ui/users?error=User+not+found", status_code=302)
    return templates.TemplateResponse("user_form.html", {
        "request": request, "current_user": auth, "active": "users",
        "editing": user, "action": f"/ui/users/{user_id}/edit", "error": "",
    })


@router.post("/users/{user_id}/edit")
def update_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    given_name: str = Form(""),
    family_name: str = Form(""),
    password: str = Form(""),
    is_active: Optional[str] = Form(None),
    is_admin: Optional[str] = Form(None),
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        return RedirectResponse("/ui/users?error=User+not+found", status_code=302)
    user.email = email
    user.username = email
    user.given_name = given_name or None
    user.family_name = family_name or None
    user.display_name = f"{given_name} {family_name}".strip() or email
    user.is_active = is_active == "on"
    user.is_admin = is_admin == "on"
    if password:
        user.hashed_password = hash_password(password)
    db.commit()
    return RedirectResponse(f"/ui/users?success=User+{email}+updated", status_code=302)


@router.post("/users/{user_id}/delete")
def delete_user(user_id: str, request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        return RedirectResponse("/ui/users?error=User+not+found", status_code=302)
    email = user.email
    db.delete(user)
    db.commit()
    return RedirectResponse(f"/ui/users?success=User+{email}+deleted", status_code=302)


# ── Groups ────────────────────────────────────────────────────────────────────

@router.get("/groups", response_class=HTMLResponse)
def groups_list(request: Request, db: Session = Depends(get_db), success: str = "", error: str = ""):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    groups = db.query(Group).options(selectinload(Group.members)).order_by(Group.display_name).all()
    return templates.TemplateResponse("groups.html", {
        "request": request, "current_user": auth, "active": "groups",
        "groups": groups, "success": success, "error": error,
    })


@router.get("/groups/new", response_class=HTMLResponse)
def new_group_form(request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    return templates.TemplateResponse("group_form.html", {
        "request": request, "current_user": auth, "active": "groups",
        "editing": None, "action": "/ui/groups/new", "error": "",
    })


@router.post("/groups/new")
def create_group(
    request: Request,
    db: Session = Depends(get_db),
    display_name: str = Form(...),
    description: str = Form(""),
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    if db.query(Group).filter(Group.display_name == display_name).first():
        return templates.TemplateResponse("group_form.html", {
            "request": request, "current_user": auth, "active": "groups",
            "editing": None, "action": "/ui/groups/new",
            "error": f"Group '{display_name}' already exists.",
            "form": {"display_name": display_name, "description": description},
        })
    db.add(Group(display_name=display_name, description=description or None))
    db.commit()
    return RedirectResponse(f"/ui/groups?success=Group+created", status_code=302)


@router.get("/groups/{group_id}/edit", response_class=HTMLResponse)
def edit_group_form(group_id: str, request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
    if not group:
        return RedirectResponse("/ui/groups?error=Group+not+found", status_code=302)
    return templates.TemplateResponse("group_form.html", {
        "request": request, "current_user": auth, "active": "groups",
        "editing": group, "action": f"/ui/groups/{group_id}/edit", "error": "",
    })


@router.post("/groups/{group_id}/edit")
def update_group(
    group_id: str,
    request: Request,
    db: Session = Depends(get_db),
    display_name: str = Form(...),
    description: str = Form(""),
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
    if not group:
        return RedirectResponse("/ui/groups?error=Group+not+found", status_code=302)
    group.display_name = display_name
    group.description = description or None
    db.commit()
    return RedirectResponse("/ui/groups?success=Group+updated", status_code=302)


@router.post("/groups/{group_id}/delete")
def delete_group(group_id: str, request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
    if not group:
        return RedirectResponse("/ui/groups?error=Group+not+found", status_code=302)
    name = group.display_name
    db.delete(group)
    db.commit()
    return RedirectResponse(f"/ui/groups?success=Group+{name}+deleted", status_code=302)


@router.get("/groups/{group_id}/members", response_class=HTMLResponse)
def group_members_page(
    group_id: str, request: Request, db: Session = Depends(get_db), success: str = ""
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    group = db.query(Group).options(selectinload(Group.members)).filter(
        Group.id == uuid.UUID(group_id)
    ).first()
    if not group:
        return RedirectResponse("/ui/groups?error=Group+not+found", status_code=302)
    member_ids = {m.id for m in group.members}
    available = db.query(User).filter(User.id.notin_(member_ids)).order_by(User.email).all()
    return templates.TemplateResponse("group_members.html", {
        "request": request, "current_user": auth, "active": "groups",
        "group": group, "available_users": available, "success": success,
    })


@router.post("/groups/{group_id}/members/add")
def add_member(
    group_id: str, request: Request, db: Session = Depends(get_db), user_id: str = Form(...)
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    group = db.query(Group).options(selectinload(Group.members)).filter(
        Group.id == uuid.UUID(group_id)
    ).first()
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if group and user and user not in group.members:
        group.members.append(user)
        db.commit()
    return RedirectResponse(f"/ui/groups/{group_id}/members?success=Member+added", status_code=302)


@router.post("/groups/{group_id}/members/remove")
def remove_member(
    group_id: str, request: Request, db: Session = Depends(get_db), user_id: str = Form(...)
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    group = db.query(Group).options(selectinload(Group.members)).filter(
        Group.id == uuid.UUID(group_id)
    ).first()
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if group and user and user in group.members:
        group.members.remove(user)
        db.commit()
    return RedirectResponse(f"/ui/groups/{group_id}/members?success=Member+removed", status_code=302)


# ── Netskope Sync ─────────────────────────────────────────────────────────────

@router.get("/sync", response_class=HTMLResponse)
def sync_page(
    request: Request,
    db: Session = Depends(get_db),
    connection: str = "",
    connection_msg: str = "",
    sync_result: str = "",
    sync_error: str = "",
):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth

    client = NetskopeScimClient()
    configured = client.is_configured()
    synced_users = db.query(User).filter(User.scim_id != None).count()  # noqa: E711
    synced_groups = db.query(Group).filter(Group.scim_id != None).count()  # noqa: E711

    return templates.TemplateResponse("sync.html", {
        "request": request,
        "current_user": auth,
        "active": "sync",
        "configured": configured,
        "netskope_tenant": settings.netskope_tenant,
        "scim_server_token_set": bool(settings.scim_bearer_token),
        "total_users": db.query(User).count(),
        "total_groups": db.query(Group).count(),
        "synced_users": synced_users,
        "synced_groups": synced_groups,
        "connection": connection,
        "connection_msg": connection_msg,
        "sync_result": sync_result,
        "sync_error": sync_error,
    })


@router.post("/sync/test")
def test_connection(request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    ok, msg = NetskopeScimClient().test_connection()
    status = "ok" if ok else "failed"
    return RedirectResponse(
        f"/ui/sync?connection={status}&connection_msg={msg.replace(' ', '+')}",
        status_code=302,
    )


@router.post("/sync/import")
def import_from_netskope(request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    try:
        r = sync_import(db)
        u = r["users"]
        g = r["groups"]
        msg = (
            f"Users: {u['created']} created, {u['linked']} linked, {u['skipped']} skipped. "
            f"Groups: {g['created']} created, {g['linked']} linked, {g['skipped']} skipped."
        )
        return RedirectResponse(f"/ui/sync?sync_result={msg.replace(' ', '+')}", status_code=302)
    except Exception as e:
        return RedirectResponse(f"/ui/sync?sync_error={str(e)[:200].replace(' ', '+')}", status_code=302)


@router.post("/sync/push")
def push_to_netskope(request: Request, db: Session = Depends(get_db)):
    auth = _require(request, db)
    if isinstance(auth, RedirectResponse):
        return auth
    try:
        r = sync_push(db)
        u = r["users"]
        g = r["groups"]
        errors = r.get("errors", [])
        msg = (
            f"Users: {u['created']} created, {u['matched']} matched in Netskope. "
            f"Groups: {g['created']} created, {g['matched']} matched."
        )
        if errors:
            msg += f" Errors: {'; '.join(errors[:3])}"
        return RedirectResponse(f"/ui/sync?sync_result={msg.replace(' ', '+')}", status_code=302)
    except Exception as e:
        return RedirectResponse(f"/ui/sync?sync_error={str(e)[:200].replace(' ', '+')}", status_code=302)
