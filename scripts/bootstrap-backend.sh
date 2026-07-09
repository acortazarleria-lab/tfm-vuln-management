#!/usr/bin/env bash
# ============================================================
# bootstrap-backend.sh
# Crea los recursos de backend ANTES de terraform init
# Prerequisito: AWS CLI configurado con permisos suficientes
#
# Uso:
#   ./bootstrap-backend.sh prod
#   ./bootstrap-backend.sh dev
# ============================================================
set -euo pipefail

REGION="eu-west-1"
PROJECT="vuln-mgmt"
ENVIRONMENT="${1:-prod}"
BUCKET="${PROJECT}-tfstate-${ENVIRONMENT}"
TABLE="${PROJECT}-tfstate-lock"
ALIAS="alias/terraform-state"

if [[ "$ENVIRONMENT" != "prod" && "$ENVIRONMENT" != "dev" ]]; then
  echo "ERROR: entorno debe ser 'prod' o 'dev'"
  exit 1
fi

echo "→ Creando CMK para cifrar el estado Terraform (si no existe)..."
if ! aws kms describe-key --key-id "$ALIAS" --region "$REGION" &>/dev/null; then
  KEY_ID=$(aws kms create-key \
    --region "$REGION" \
    --description "CMK para cifrar terraform state - ${PROJECT}" \
    --query 'KeyMetadata.KeyId' --output text)

  aws kms create-alias \
    --region "$REGION" \
    --alias-name "$ALIAS" \
    --target-key-id "$KEY_ID"

  aws kms enable-key-rotation \
    --region "$REGION" \
    --key-id "$KEY_ID"

  echo "  CMK creada: $KEY_ID"
else
  echo "  CMK ya existe, reutilizando."
fi

echo "→ Creando bucket S3 para tfstate ($ENVIRONMENT)..."
if ! aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null; then
  aws s3api create-bucket \
    --bucket "$BUCKET" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION"

  aws s3api put-bucket-versioning \
    --bucket "$BUCKET" \
    --versioning-configuration Status=Enabled

  aws s3api put-bucket-encryption \
    --bucket "$BUCKET" \
    --server-side-encryption-configuration '{
      "Rules": [{
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "aws:kms",
          "KMSMasterKeyID": "'"$ALIAS"'"
        }
      }]
    }'

  aws s3api put-public-access-block \
    --bucket "$BUCKET" \
    --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

  echo "  Bucket creado: $BUCKET"
else
  echo "  Bucket ya existe, reutilizando: $BUCKET"
fi

echo "→ Creando tabla DynamoDB para locking (compartida entre entornos)..."
if ! aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" &>/dev/null; then
  aws dynamodb create-table \
    --table-name "$TABLE" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region "$REGION"

  echo "  Tabla creada: $TABLE"
else
  echo "  Tabla ya existe, reutilizando: $TABLE"
fi

echo ""
echo "✓ Backend listo para entorno '$ENVIRONMENT'."
echo "  cd environments/$ENVIRONMENT && terraform init"
