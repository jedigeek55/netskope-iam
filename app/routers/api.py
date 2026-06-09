import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..models.group import Group
from ..models.user import User
from ..services.auth import decode_access_token, hash_password

router = APIRouter(prefix="/api", tags=["api"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    password: str
    is_active: bool = True
    is_admin: bool = False


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    username: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    display_name: Optional[str] = None
    is_active: bool
    is_admin: bool
    scim_id: Optional[str] = None


class GroupCreate(BaseModel):
    display_name: str
    description: Optional[str] = None


class GroupUpdate(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None


class GroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    display_name: str
    description: Optional[str] = None
    scim_id: Optional[str] = None
    member_count: int = 0


# ── Auth dependency ───────────────────────────────────────────────────────────

def _api_auth(authorization: str = Header(default=""), db: Session = Depends(get_db)) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    payload = decode_access_token(authorization[7:])
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        user = db.query(User).filter(User.id == uuid.UUID(payload["sub"])).first()
    except (ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid token")
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── User endpoints ────────────────────────────────────────────────────────────

@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    return db.query(User).order_by(User.email).all()


@router.post("/users", response_model=UserResponse, status_code=201)
def create_user(data: UserCreate, db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=409, detail="User already exists")
    display = f"{data.given_name or ''} {data.family_name or ''}".strip() or data.email
    user = User(
        username=data.email, email=data.email,
        given_name=data.given_name, family_name=data.family_name,
        display_name=display,
        hashed_password=hash_password(data.password),
        is_active=data.is_active, is_admin=data.is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str, data: UserUpdate, db: Session = Depends(get_db), _: User = Depends(_api_auth)
):
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if data.email is not None:
        user.email = data.email
        user.username = data.email
    if data.given_name is not None:
        user.given_name = data.given_name
    if data.family_name is not None:
        user.family_name = data.family_name
    if data.is_active is not None:
        user.is_active = data.is_active
    if data.is_admin is not None:
        user.is_admin = data.is_admin
    if data.password:
        user.hashed_password = hash_password(data.password)
    user.display_name = f"{user.given_name or ''} {user.family_name or ''}".strip() or user.email
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: str, db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()


# ── Group endpoints ───────────────────────────────────────────────────────────

@router.get("/groups", response_model=list[GroupResponse])
def list_groups(db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    groups = db.query(Group).options(selectinload(Group.members)).order_by(Group.display_name).all()
    return [
        GroupResponse(
            id=g.id, display_name=g.display_name, description=g.description,
            scim_id=g.scim_id, member_count=g.member_count,
        )
        for g in groups
    ]


@router.post("/groups", response_model=GroupResponse, status_code=201)
def create_group(data: GroupCreate, db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    if db.query(Group).filter(Group.display_name == data.display_name).first():
        raise HTTPException(status_code=409, detail="Group already exists")
    group = Group(display_name=data.display_name, description=data.description)
    db.add(group)
    db.commit()
    db.refresh(group)
    return GroupResponse(id=group.id, display_name=group.display_name, description=group.description)


@router.get("/groups/{group_id}", response_model=GroupResponse)
def get_group(group_id: str, db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    group = db.query(Group).options(selectinload(Group.members)).filter(
        Group.id == uuid.UUID(group_id)
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return GroupResponse(
        id=group.id, display_name=group.display_name, description=group.description,
        scim_id=group.scim_id, member_count=group.member_count,
    )


@router.put("/groups/{group_id}", response_model=GroupResponse)
def update_group(
    group_id: str, data: GroupUpdate, db: Session = Depends(get_db), _: User = Depends(_api_auth)
):
    group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if data.display_name is not None:
        group.display_name = data.display_name
    if data.description is not None:
        group.description = data.description
    db.commit()
    db.refresh(group)
    return GroupResponse(id=group.id, display_name=group.display_name, description=group.description)


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(group_id: str, db: Session = Depends(get_db), _: User = Depends(_api_auth)):
    group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    db.delete(group)
    db.commit()
