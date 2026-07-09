#!/usr/bin/env bash
# ============================================================
# localstack/setup-and-plan.sh
# Instala terraform + levanta LocalStack + ejecuta terraform plan
# Sin cuenta AWS. Requisitos: Docker Desktop instalado y corriendo.
#
# Uso:
#   chmod +x localstack/setup-and-plan.sh
#   ./localstack/setup-and-plan.sh
#
# Tiempo estimado: ~5 minutos (primera ejecución descarga imágenes)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TF_VERSION="1.7.5"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
[ "$ARCH" = "x86_64" ] && ARCH="amd64"
[ "$ARCH" = "arm64" ]  && ARCH="arm64"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "\n${YELLOW}──────────────────────────────────────${NC}"; echo -e "${YELLOW}▶ $1${NC}"; }

# ── 0. Prereqs ─────────────────────────────────────────────
step "Verificando prerequisitos"

if ! command -v docker &>/dev/null; then
  err "Docker no encontrado. Instala Docker Desktop: https://docs.docker.com/get-docker/"
fi
docker info &>/dev/null || err "Docker no está corriendo. Arranca Docker Desktop primero."
ok "Docker disponible"

if ! command -v python3 &>/dev/null; then
  err "Python 3 no encontrado"
fi
ok "Python 3 disponible: $(python3 --version)"

# ── 1. Instalar Terraform localmente ──────────────────────
step "Instalando Terraform $TF_VERSION"

TF_BIN="$SCRIPT_DIR/bin/terraform"
mkdir -p "$SCRIPT_DIR/bin"

if [ -f "$TF_BIN" ] && "$TF_BIN" version 2>/dev/null | grep -q "$TF_VERSION"; then
  ok "Terraform $TF_VERSION ya instalado en $TF_BIN"
else
  TF_URL="https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_${OS}_${ARCH}.zip"
  echo "Descargando $TF_URL ..."
  curl -fsSL "$TF_URL" -o /tmp/terraform.zip
  unzip -o /tmp/terraform.zip -d "$SCRIPT_DIR/bin/"
  chmod +x "$TF_BIN"
  rm /tmp/terraform.zip
  ok "Terraform instalado: $("$TF_BIN" version | head -1)"
fi

export PATH="$SCRIPT_DIR/bin:$PATH"

# ── 2. Instalar LocalStack CLI ─────────────────────────────
step "Instalando LocalStack CLI"

if command -v localstack &>/dev/null && localstack --version 2>/dev/null; then
  ok "LocalStack CLI ya instalado"
else
  pip3 install localstack --quiet --break-system-packages 2>/dev/null \
    || pip3 install localstack --quiet
  ok "LocalStack CLI instalado"
fi

# ── 3. Levantar LocalStack ─────────────────────────────────
step "Levantando LocalStack (Docker)"

# Parar instancia previa si existe
docker rm -f localstack-main 2>/dev/null || true

# Servicios necesarios para el plan
SERVICES="ec2,rds,s3,kms,iam,secretsmanager,cloudwatch,wafv2,\
elbv2,lambda,sns,apigateway,config,guardduty,logs,\
scheduler,events,ssm,dynamodb"

docker run -d \
  --name localstack-main \
  --rm \
  -p 4566:4566 \
  -p 4510-4559:4510-4559 \
  -e SERVICES="$SERVICES" \
  -e DEFAULT_REGION=eu-west-1 \
  -e AWS_DEFAULT_REGION=eu-west-1 \
  -e DISABLE_CORS_CHECKS=1 \
  -e EAGER_SERVICE_LOADING=0 \
  -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN:-}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  localstack/localstack:latest

echo "Esperando a que LocalStack arranque (~20s)..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:4566/_localstack/health 2>/dev/null | grep -q '"s3": "running"'; then
    ok "LocalStack listo"
    break
  fi
  sleep 2
  echo -n "."
done
echo ""

# ── 4. Crear backend bootstrap local ──────────────────────
step "Creando backend S3 + DynamoDB en LocalStack"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=eu-west-1

AWS_CMD="aws --endpoint-url=http://localhost:4566 --region eu-west-1"

# Bucket tfstate
$AWS_CMD s3api create-bucket \
  --bucket vuln-mgmt-tfstate-dev \
  --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1 2>/dev/null || true

$AWS_CMD s3api put-bucket-versioning \
  --bucket vuln-mgmt-tfstate-dev \
  --versioning-configuration Status=Enabled 2>/dev/null || true

# Tabla DynamoDB locking
$AWS_CMD dynamodb create-table \
  --table-name vuln-mgmt-tfstate-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST 2>/dev/null || true

ok "Backend LocalStack listo"

# ── 5. Ejecutar terraform init + plan ─────────────────────
step "Ejecutando terraform init"

cd "$REPO_ROOT/environments/dev"

# Usar override de LocalStack
cp "$SCRIPT_DIR/localstack.override.tf" ./localstack.override.tf

# Init con backend LocalStack
terraform init \
  -backend-config="endpoint=http://localhost:4566" \
  -backend-config="access_key=test" \
  -backend-config="secret_key=test" \
  -backend-config="skip_credentials_validation=true" \
  -backend-config="skip_metadata_api_check=true" \
  -backend-config="force_path_style=true" \
  -reconfigure \
  -input=false

ok "terraform init completado"

step "Ejecutando terraform plan"

terraform plan \
  -var="acm_certificate_arn=arn:aws:acm:eu-west-1:000000000000:certificate/localstack-fake" \
  -var="alarm_email=test@empresa.com" \
  -var="internal_domain=empresa.internal" \
  -input=false \
  -out=tfplan.localstack \
  2>&1 | tee "$SCRIPT_DIR/plan-output.txt"

PLAN_EXIT=${PIPESTATUS[0]}

echo ""
echo "────────────────────────────────────"
if [ $PLAN_EXIT -eq 0 ]; then
  ok "terraform plan EXITOSO — sin errores de sintaxis ni estructura"
  echo ""
  grep -E "^Plan:|^No changes" "$SCRIPT_DIR/plan-output.txt" || true
elif [ $PLAN_EXIT -eq 2 ]; then
  ok "terraform plan EXITOSO con cambios pendientes (exit 2 = hay recursos a crear)"
  grep -E "^Plan:" "$SCRIPT_DIR/plan-output.txt" || true
else
  err "terraform plan FALLÓ — revisar plan-output.txt para detalles"
fi

# Limpiar override
rm -f ./localstack.override.tf

step "Limpieza"
echo "Para parar LocalStack: docker stop localstack-main"
echo "Log completo del plan: localstack/plan-output.txt"
