#!/bin/bash
# Netskope IAM Server — EC2 bootstrap script
#
# Called by CloudFormation UserData after cloning the GitHub repo to /opt/netskope-iam.
# Reads all secrets from SSM Parameter Store at /netskope-iam/*.
# Installs: PostgreSQL 15, Python 3.12 venv, nginx, CloudWatch agent.
# Server is HTTP-only, reachable only from the private subnet (10.10.2.0/24).
#
# Usage (normally called from UserData):
#   export IAM_DOMAIN=iam.jedigeek5.net
#   bash /opt/netskope-iam/deploy/setup.sh

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────
IAM_DIR=/opt/netskope-iam
IAM_USER=iam
DB_NAME=netskope_iam
DB_USER=iam
LOG_DIR=/var/log/netskope-iam
DOMAIN="${IAM_DOMAIN:-iam.jedigeek5.net}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

log "=== Netskope IAM Server Bootstrap ==="
log "Domain:   $DOMAIN"
log "IAM dir:  $IAM_DIR"

# ── Detect region from IMDS (IMDSv2 required on AL2023) ───────────────────
IMDS_TOKEN=$(curl -sfX PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
REGION=$(curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  "http://169.254.169.254/latest/meta-data/placement/region")
log "Region: $REGION"

# ── Helper: fetch SSM SecureString ────────────────────────────────────────
ssm_get() {
  aws ssm get-parameter --region "$REGION" \
    --name "/netskope-iam/$1" --with-decryption \
    --query Parameter.Value --output text \
  || die "SSM parameter /netskope-iam/$1 not found — run deploy/create-ssm-params.sh first"
}

# ── 1. System packages ─────────────────────────────────────────────────────
log "Step 1/11 — Installing system packages..."
dnf update -y

dnf install -y \
  python3.12 python3.12-pip python3.12-devel \
  postgresql15 postgresql15-server \
  nginx \
  libxml2-devel libxslt-devel libffi-devel openssl-devel gcc \
  amazon-cloudwatch-agent \
  augeas-libs

# ── 2. PostgreSQL init ─────────────────────────────────────────────────────
log "Step 2/12 — Initialising PostgreSQL 15..."
if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
  postgresql-setup --initdb
  # Add scram-sha-256 rule for our DB/user before the catch-all line
  sed -i '/^host[[:space:]]\+all[[:space:]]\+all[[:space:]]\+127\.0\.0\.1\/32/i host    '"$DB_NAME"'    '"$DB_USER"'    127.0.0.1/32    scram-sha-256' \
    /var/lib/pgsql/data/pg_hba.conf
  log "  PostgreSQL initialized."
else
  log "  Already initialized, skipping."
fi
systemctl enable --now postgresql

# ── 3. Fetch secrets from SSM Parameter Store ──────────────────────────────
log "Step 3/11 — Reading secrets from SSM /netskope-iam/..."
SECRET_KEY=$(ssm_get secret-key)
DB_PASSWORD=$(ssm_get db-password)
SCIM_BEARER_TOKEN=$(ssm_get scim-bearer-token)
NETSKOPE_TENANT=$(ssm_get netskope-tenant)
NETSKOPE_SCIM_TOKEN=$(ssm_get netskope-scim-token)
ADMIN_EMAIL=$(ssm_get admin-email)
ADMIN_PASSWORD=$(ssm_get admin-password)

# ── 4. OS user and directories ─────────────────────────────────────────────
log "Step 4/11 — Creating iam OS user and directories..."
id -u "$IAM_USER" &>/dev/null || \
  useradd -r -d "$IAM_DIR" -s /sbin/nologin "$IAM_USER"

mkdir -p "$LOG_DIR" "$IAM_DIR/keys" "$IAM_DIR/static"
chown -R "$IAM_USER:$IAM_USER" "$IAM_DIR" "$LOG_DIR"
chmod 750 "$IAM_DIR/keys"

# ── 5. Python virtualenv ───────────────────────────────────────────────────
log "Step 5/11 — Installing Python 3.12 venv and dependencies..."
python3.12 -m venv "$IAM_DIR/venv"
"$IAM_DIR/venv/bin/pip" install --quiet --upgrade pip
"$IAM_DIR/venv/bin/pip" install --quiet -r "$IAM_DIR/requirements.txt"
chown -R "$IAM_USER:$IAM_USER" "$IAM_DIR/venv"

# ── 6. PostgreSQL database and user ───────────────────────────────────────
log "Step 6/11 — Creating database '$DB_NAME' and user '$DB_USER'..."
sudo -u postgres psql -c \
  "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null || \
  log "  (user already exists, skipping)"

sudo -u postgres psql -c \
  "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null || \
  log "  (database already exists, skipping)"

sudo -u postgres psql -c \
  "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# ── 7. .env file ───────────────────────────────────────────────────────────
log "Step 7/11 — Writing .env..."
cat > "$IAM_DIR/.env" <<ENV
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1/$DB_NAME
SECRET_KEY=$SECRET_KEY
ACCESS_TOKEN_EXPIRE_MINUTES=60
SCIM_BEARER_TOKEN=$SCIM_BEARER_TOKEN
NETSKOPE_TENANT=$NETSKOPE_TENANT
NETSKOPE_SCIM_TOKEN=$NETSKOPE_SCIM_TOKEN
NETSKOPE_VERIFY_SSL=true
IDP_ENTITY_ID=http://$DOMAIN
IDP_BASE_URL=http://$DOMAIN
SAML_KEY_FILE=$IAM_DIR/keys/saml_idp.key
SAML_CERT_FILE=$IAM_DIR/keys/saml_idp.crt
SSO_SESSION_EXPIRE_HOURS=8
ENV
chmod 600 "$IAM_DIR/.env"
chown "$IAM_USER:$IAM_USER" "$IAM_DIR/.env"

# ── 8. Alembic migrations ──────────────────────────────────────────────────
log "Step 8/11 — Running Alembic migrations..."
cd "$IAM_DIR"
sudo -u "$IAM_USER" "$IAM_DIR/venv/bin/alembic" upgrade head

# ── 9. Create admin user ───────────────────────────────────────────────────
log "Step 9/11 — Creating admin user ($ADMIN_EMAIL)..."
cd "$IAM_DIR"
sudo -u "$IAM_USER" "$IAM_DIR/venv/bin/python" create_admin.py \
  "$ADMIN_EMAIL" "$ADMIN_PASSWORD" Admin User 2>/dev/null || \
  log "  (admin user may already exist, skipping)"

# ── 10. systemd service ────────────────────────────────────────────────────
log "Step 10/11 — Installing systemd service..."
cp "$IAM_DIR/deploy/netskope-iam.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable netskope-iam

# ── 11. nginx ───────────────────────────────────────────────────────────────
log "Step 11/11 — Configuring nginx..."

cat > /etc/nginx/conf.d/netskope-iam.conf <<NGINX
server {
    listen 80;
    server_name $DOMAIN;

    client_max_body_size 10m;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
    }
}
NGINX

nginx -t
systemctl enable --now nginx
nginx -s reload

# ── CloudWatch agent ───────────────────────────────────────────────────────
log "Starting CloudWatch agent..."
cp "$IAM_DIR/deploy/cloudwatch-agent.json" \
  /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# ── Start IAM server ───────────────────────────────────────────────────────
log "Starting netskope-iam service..."
systemctl start netskope-iam

log ""
log "=== Bootstrap complete ==="
log "IAM server: http://$DOMAIN (reachable from 10.10.2.0/24 only)"
log "Admin login: $ADMIN_EMAIL"
