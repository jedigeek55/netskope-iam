# Netskope IAM Server

Self-hosted Identity Provider with SCIM 2.0 provisioning and SAML 2.0 SSO for Netskope tenants.

## Phase Status

| Phase | Feature | Status |
|---|---|---|
| 1 | User & group management + web UI | ✅ Complete |
| 2 | SCIM 2.0 client/server (Netskope sync) | Planned |
| 3 | SAML 2.0 IdP + SSO | Planned |
| 4 | AWS deployment + production hardening | Planned |

## Quick Start (Local Dev)

**Prerequisites:** Docker, Python 3.12+

### 1. Start the database

```bash
docker-compose up db -d
```

### 2. Set up environment

```bash
cp .env.example .env
# Edit .env and set a strong SECRET_KEY
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create the initial admin user

```bash
python create_admin.py admin@example.com yourpassword Scott Admin
```

### 5. Run the server

```bash
uvicorn app.main:app --reload
```

Visit **http://localhost:8000** and log in with your admin credentials.

## Running with Docker Compose

```bash
cp .env.example .env
docker-compose up --build
python create_admin.py admin@example.com yourpassword
```

## Database Migrations

Alembic is configured for production migrations. For local dev, `create_all` runs automatically on startup.

```bash
# Apply migrations
alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "description"
```

## REST API

Interactive API docs available at **http://localhost:8000/api/docs** (requires Bearer token from login).

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/users` | List all users |
| POST | `/api/users` | Create user |
| GET/PUT/DELETE | `/api/users/{id}` | Read/update/delete user |
| GET | `/api/groups` | List all groups |
| POST | `/api/groups` | Create group |
| GET/PUT/DELETE | `/api/groups/{id}` | Read/update/delete group |

## Project Structure

```
app/
├── main.py           # FastAPI app entry point
├── config.py         # Settings (env vars)
├── database.py       # SQLAlchemy engine + session
├── models/           # ORM models (User, Group)
├── routers/
│   ├── ui.py         # Web interface routes
│   └── api.py        # REST API routes
├── services/
│   └── auth.py       # Password hashing, JWT
└── templates/        # Jinja2 HTML templates
alembic/              # Database migrations
create_admin.py       # Bootstrap admin user
docker-compose.yml    # Local dev environment
```
