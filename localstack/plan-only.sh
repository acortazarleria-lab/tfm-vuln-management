#!/usr/bin/env bash
# ============================================================
# localstack/plan-only.sh
# Ejecuta terraform validate + plan SIN cuenta AWS ni Docker.
#
# Requisito único: terraform >= 1.7 instalado.
#   macOS:   brew install terraform
#   Ubuntu:  snap install terraform
#   Windows: winget install Hashicorp.Terraform
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_DIR="$REPO_ROOT/environments/dev"

# El nombre DEBE terminar en _override.tf para que Terraform
# lo fusione con el provider existente en vez de duplicarlo.
OVERRIDE_DST="$ENV_DIR/localstack_override.tf"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
step() { echo -e "\n${YELLOW}▶ $*${NC}"; }
fail() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 0. Verificar terraform ─────────────────────────────────
step "Verificando Terraform"
if ! command -v terraform &>/dev/null; then
  fail "terraform no encontrado.\n  macOS:   brew install terraform\n  Ubuntu:  snap install terraform\n  Windows: winget install Hashicorp.Terraform"
fi
TF_VER=$(terraform version -json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])" 2>/dev/null || terraform version | head -1)
ok "Terraform: $TF_VER"

# ── 1. Copiar override (nombre _override.tf = merge, no duplicado)
step "Instalando override LocalStack"
cp "$SCRIPT_DIR/localstack.override.tf" "$OVERRIDE_DST"
ok "Override copiado como localstack_override.tf (Terraform lo fusiona con el provider base)"

# Cleanup automático al salir (éxito o error)
cleanup() {
  rm -f "$OVERRIDE_DST"
  rm -f "$ENV_DIR/.terraform.lock.hcl" 2>/dev/null || true
}
trap cleanup EXIT

# ── 2. Variables de entorno ficticias ──────────────────────
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="eu-west-1"

cd "$ENV_DIR"

# ── 3. terraform init ──────────────────────────────────────
step "terraform init -backend=false"
terraform init \
  -backend=false \
  -input=false \
  -upgrade \
  2>&1 | grep -v "^Terraform has been\|^Initializing the backend\|^Initializing provider\|^- Reusing\|^- Using\|^- Installing\|^- Installed\|^Terraform has been successfully" \
  || true

ok "init completado"

# ── 4. terraform validate ──────────────────────────────────
step "terraform validate"
if terraform validate 2>&1; then
  ok "validate — sintaxis HCL correcta en todos los módulos"
else
  echo ""
  fail "validate falló — corregir errores antes de continuar"
fi

# ── 5. terraform plan ──────────────────────────────────────
step "terraform plan"
echo "  (con variables ficticias, sin llamar a AWS)"
echo ""

terraform plan \
  -var="acm_certificate_arn=arn:aws:acm:eu-west-1:000000000000:certificate/test-fake-cert" \
  -var="alarm_email=test@empresa.com" \
  -var="internal_domain=empresa.internal" \
  -input=false \
  -compact-warnings \
  -out="$SCRIPT_DIR/tfplan.out" \
  2>&1 | tee "$SCRIPT_DIR/plan-output.txt"

PLAN_EXIT=${PIPESTATUS[0]}

# ── 6. Resumen ─────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
case $PLAN_EXIT in
  0)
    ok "terraform plan EXITOSO — sin cambios pendientes"
    ;;
  2)
    PLAN_LINE=$(grep "^Plan:" "$SCRIPT_DIR/plan-output.txt" 2>/dev/null | head -1 || true)
    ok "terraform plan EXITOSO"
    [ -n "$PLAN_LINE" ] && echo "  $PLAN_LINE"
    RESOURCE_COUNT=$(grep -c "will be created" "$SCRIPT_DIR/plan-output.txt" 2>/dev/null || echo "0")
    echo "  Recursos que se crearían: $RESOURCE_COUNT"
    ;;
  *)
    echo -e "${RED}[ERROR]${NC} terraform plan FALLÓ (exit=$PLAN_EXIT)"
    echo ""
    echo "  Últimos errores:"
    grep -A5 "^│ Error" "$SCRIPT_DIR/plan-output.txt" 2>/dev/null | head -40 || true
    echo ""
    echo "  Log completo: localstack/plan-output.txt"
    exit 1
    ;;
esac
echo ""
echo "  Log completo guardado en: localstack/plan-output.txt"
echo "══════════════════════════════════════════════════════"
