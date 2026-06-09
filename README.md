# Netskope IAM Server

Self-hosted Identity Provider with SCIM 2.0 provisioning and SAML 2.0 SSO for Netskope tenants.

## Phase Status

| Phase | Feature | Status |
|---|---|---|
| 1 | User & group management + web UI | ✅ Complete |
| 2 | SCIM 2.0 client/server (Netskope sync) | ✅ Complete |
| 3 | SAML 2.0 IdP + SSO + Service Provider management | ✅ Complete |
| 4 | AWS deployment + production hardening | ✅ Complete |

---

## Quick Start (Local Dev)

**Prerequisites:** Docker, Python 3.12+

### 1. Start the database

```bash
docker-compose up db -d
```

### 2. Set up environment

```bash
cp .env.example .env
# Edit .env — set SECRET_KEY, SCIM_BEARER_TOKEN, and Netskope credentials
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

Visit **http://localhost:8000** — log in with your admin credentials.

---

## AWS Deployment (Phase 4)

Deploys a single EC2 instance in the **Jedigeek5 Test VPC** (us-east-1) running:
- **uvicorn** behind **nginx** (TLS 1.2/1.3)
- **PostgreSQL 15** on the same instance
- **Let's Encrypt** SSL for `iam.jedigeek5.net`
- **CloudWatch agent** forwarding logs to `/netskope-iam/*` log groups
- Secrets in **AWS SSM Parameter Store** — never on disk in plaintext (the `.env` file is written at boot from SSM and is chmod 600)

### Prerequisites

- AWS CLI configured (`aws sts get-caller-identity` works)
- If behind Netskope SSL inspection: `export AWS_CA_BUNDLE=C:/ProgramData/Netskope/stagent/data/nscacert.pem`

### Step 1 — Create SSM parameters

Run this **once** to store all secrets:

```bash
bash deploy/create-ssm-params.sh --region us-east-1
```

You will be prompted for:

| Parameter | Description |
|---|---|
| `secret-key` | JWT signing secret (32+ random bytes) |
| `db-password` | PostgreSQL password for the `iam` user |
| `scim-bearer-token` | Token Netskope sends to `/scim/v2/` |
| `netskope-tenant` | Your tenant hostname, e.g. `ns-3337.us-sv5.npa.goskope.com` |
| `netskope-scim-token` | Token from Netskope Admin > Settings > Tools > SCIM Integration |
| `admin-email` | Initial admin account email |
| `admin-password` | Initial admin account password |

### Step 2 — Deploy the CloudFormation stack

```bash
aws cloudformation deploy \
  --template-file deploy/netskope-iam.yaml \
  --stack-name netskope-iam \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

Stack creates: EC2 instance (t3.small, AL2023, 20 GB gp3), Elastic IP, security group, IAM role, and CloudWatch log groups.

### Step 3 — Configure DNS

Get the Elastic IP from the stack outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name netskope-iam \
  --query "Stacks[0].Outputs" \
  --output table \
  --region us-east-1
```

Create a DNS **A record**:
```
iam.jedigeek5.net → <PublicIP from outputs>
```

### Step 4 — Monitor bootstrap

The EC2 UserData clones the repo and runs `deploy/setup.sh` (~5–10 min). Watch it via SSM:

```bash
# Open a shell (no SSH key needed)
aws ssm start-session --target <InstanceId> --region us-east-1

# Tail the setup log
tail -f /var/log/iam-setup.log
```

When complete the log ends with `=== Bootstrap complete ===`.

### Step 5 — Verify

- **IAM admin UI:** `https://iam.jedigeek5.net` — log in with admin credentials from SSM
- **SAML metadata:** `https://iam.jedigeek5.net/saml/metadata`
- **SCIM endpoint:** `https://iam.jedigeek5.net/scim/v2/Users`
- **API docs:** `https://iam.jedigeek5.net/api/docs`

### Re-running SSL if DNS wasn't ready

If certbot failed during bootstrap (DNS not yet propagated):

```bash
sudo IAM_DOMAIN=iam.jedigeek5.net bash /opt/netskope-iam/deploy/setup.sh --ssl-only
```

### Useful ops commands

```bash
# Service status
sudo systemctl status netskope-iam

# Restart app
sudo systemctl restart netskope-iam

# Tail app logs
sudo tail -f /var/log/netskope-iam/uvicorn.log

# Reload nginx after config change
sudo nginx -t && sudo nginx -s reload

# Apply new migrations after a git pull
cd /opt/netskope-iam
sudo -u iam ./venv/bin/alembic upgrade head
sudo systemctl restart netskope-iam
```

---

## Registering Netskope as a SAML SP

1. Log in to the IAM admin UI and go to **Service Providers → Register SP**
2. Enter:
   - **Entity ID:** your Netskope tenant SAML entity ID
   - **ACS URL:** your Netskope tenant SAML ACS URL
3. Download the **IdP Metadata XML** from `https://iam.jedigeek5.net/saml/metadata`
4. In the Netskope admin console, configure the IdP using the downloaded metadata

Detailed IdP values are on the **IdP Info** page in the admin UI.

---

## SCIM Sync with Netskope

On the **Netskope Sync** page you can:
- **Import** — pull existing users/groups from the Netskope tenant into the IAM server
- **Push** — provision users/groups from the IAM server to the Netskope tenant

The IAM server also exposes a SCIM 2.0 server at `/scim/v2/` — configure Netskope to call it using the `SCIM_BEARER_TOKEN` from SSM.

---

## Database Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "your description"
```

---

## Project Structure

```
app/
├── main.py                   # FastAPI app entry point
├── config.py                 # Settings (pydantic-settings, reads .env)
├── database.py               # SQLAlchemy engine + session
├── models/                   # ORM models: User, Group, ServiceProvider
├── routers/
│   ├── ui.py                 # Web UI routes
│   ├── api.py                # REST API (/api/*)
│   ├── scim.py               # SCIM 2.0 server (/scim/v2/*)
│   └── saml.py               # SAML 2.0 IdP (/saml/*)
├── services/
│   ├── auth.py               # Password hashing, JWT (access + SSO tokens)
│   ├── saml_idp.py           # Key gen, metadata, assertion building + signing
│   └── netskope_scim.py      # SCIM client for Netskope tenant
└── templates/                # Jinja2 HTML templates (Bootstrap 5)
alembic/                      # Database migrations
deploy/
├── netskope-iam.yaml         # CloudFormation template (EC2 + EIP + IAM + SG)
├── setup.sh                  # EC2 bootstrap script (called from UserData)
├── netskope-iam.service      # systemd unit for uvicorn
├── cloudwatch-agent.json     # CloudWatch agent log config
└── create-ssm-params.sh      # One-time SSM parameter setup helper
create_admin.py               # Bootstrap admin user (local dev)
docker-compose.yml            # Local dev environment
```
