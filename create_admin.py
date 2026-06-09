#!/usr/bin/env python3
"""Create an initial admin user. Run once after first deploy."""
import sys

from app.database import SessionLocal, engine, Base
from app.models import user, group  # noqa: F401
from app.models.user import User
from app.services.auth import hash_password

Base.metadata.create_all(bind=engine)


def create_admin(email: str, password: str, given_name: str = "Admin", family_name: str = "User") -> None:
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == email).first():
            print(f"User {email} already exists.")
            return
        admin = User(
            username=email,
            email=email,
            given_name=given_name,
            family_name=family_name,
            display_name=f"{given_name} {family_name}".strip(),
            hashed_password=hash_password(password),
            is_active=True,
            is_admin=True,
        )
        db.add(admin)
        db.commit()
        print(f"Admin user '{email}' created successfully.")
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_admin.py <email> <password> [given_name] [family_name]")
        sys.exit(1)
    create_admin(
        sys.argv[1],
        sys.argv[2],
        sys.argv[3] if len(sys.argv) > 3 else "Admin",
        sys.argv[4] if len(sys.argv) > 4 else "User",
    )
