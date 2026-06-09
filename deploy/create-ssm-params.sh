#!/bin/bash
# Netskope IAM Server — SSM Parameter Store setup
#
# Run this ONCE before deploying the CloudFormation stack.
# Creates all required secrets at /netskope-iam/* as SecureString parameters.
#
# Prerequisites:
#   - AWS CLI configured with credentials that have ssm:PutParameter permission
#   - AWS_CA_BUNDLE set if behind Netskope SSL inspection:
#       export AWS_CA_BUNDLE=C:/ProgramData/Netskope/stagent/data/nscacert.pem
#
# Usage:
#   bash deploy/create-ssm-params.sh [--region us-east-1]

set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
PREFIX="/netskope-iam"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region) REGION="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "=== Netskope IAM Server — SSM Parameter Setup ==="
echo "Region : $REGION"
echo "Prefix : $PREFIX"
echo ""
echo "All values stored as SecureString (KMS-encrypted)."
echo "Press Ctrl+C to abort."
echo ""

# Helper: prompt for a value and put it in SSM
put_param() {
  local name="$1"
  local description="$2"
  local default_val="${3:-}"
  local secret="${4:-true}"
  local val

  echo "──────────────────────────────────────────────"
  echo "Parameter : $PREFIX/$name"
  echo "Info      : $description"

  if [ "$secret" = "false" ]; then
    read -rp "Value${default_val:+ [$default_val]}: " val
    val="${val:-$default_val}"
  else
    if [ -n "$default_val" ]; then
      read -rsp "Value (hidden)${default_val:+ [press Enter to use default]}: " val
      echo ""
      val="${val:-$default_val}"
    else
      read -rsp "Value (hidden): " val
      echo ""
    fi
  fi

  [ -z "$val" ] && { echo "  Skipped (empty value)."; return; }

  aws ssm put-parameter \
    --region "$REGION" \
    --name "$PREFIX/$name" \
    --type SecureString \
    --value "$val" \
    --description "$description" \
    --overwrite \
    --output text \
    --query "Version" | xargs -I{} echo "  Saved (version {})."
}

# Generate suggested values
SUGGESTED_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || echo "")
SUGGESTED_SCIM_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || echo "")

echo "Suggested SECRET_KEY  : $SUGGESTED_SECRET_KEY"
echo "Suggested SCIM_TOKEN  : $SUGGESTED_SCIM_TOKEN"
echo "(Copy these now if you want to use them below.)"
echo ""

put_param "secret-key" \
  "JWT signing secret — 32+ random bytes (use the suggested value above)" \
  "$SUGGESTED_SECRET_KEY"

put_param "db-password" \
  "PostgreSQL password for the 'iam' database user"

put_param "scim-bearer-token" \
  "Bearer token Netskope sends when calling /scim/v2/ (use the suggested value above)" \
  "$SUGGESTED_SCIM_TOKEN"

put_param "netskope-tenant" \
  "Netskope tenant hostname, e.g. ns-3337.us-sv5.npa.goskope.com" \
  "ns-3337.us-sv5.npa.goskope.com" \
  "false"

put_param "netskope-scim-token" \
  "Netskope SCIM API token (Netskope Admin > Settings > Tools > SCIM Integration > Add Token)"

put_param "admin-email" \
  "Initial admin user email address" \
  "admin@jedigeek5.net" \
  "false"

put_param "admin-password" \
  "Initial admin user password (change after first login)"

echo ""
echo "=== All parameters saved. ==="
echo ""
echo "To verify:"
echo "  aws ssm get-parameters-by-path \\"
echo "    --path $PREFIX --with-decryption \\"
echo "    --region $REGION \\"
echo "    --query 'Parameters[*].{Name:Name,Value:Value}' \\"
echo "    --output table"
echo ""
echo "Next step: deploy the CloudFormation stack:"
echo "  aws cloudformation deploy \\"
echo "    --template-file deploy/netskope-iam.yaml \\"
echo "    --stack-name netskope-iam \\"
echo "    --capabilities CAPABILITY_IAM \\"
echo "    --region $REGION"
