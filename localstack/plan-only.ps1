# ============================================================
# localstack/plan-only.ps1
# Equivalente a plan-only.sh para usuarios de Windows
#
# Requisitos:
#   - Terraform instalado: winget install Hashicorp.Terraform
#   - O descargar manualmente de: https://developer.hashicorp.com/terraform/downloads
#
# Uso (PowerShell):
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\localstack\plan-only.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$EnvDir     = Join-Path $RepoRoot "environments\dev"
$OverrideSrc = Join-Path $ScriptDir "localstack.override.tf"
$OverrideDst = Join-Path $EnvDir "localstack.override.tf"

function Write-Step { param($msg) Write-Host "`n▶ $msg" -ForegroundColor Yellow }
function Write-Ok   { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Err  { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── Verificar terraform ────────────────────────────────────
Write-Step "Verificando Terraform"
try {
    $tfVersion = terraform version 2>&1 | Select-Object -First 1
    Write-Ok $tfVersion
} catch {
    Write-Err "terraform no encontrado. Instala con: winget install Hashicorp.Terraform"
}

# ── Variables de entorno ficticias ─────────────────────────
$env:AWS_ACCESS_KEY_ID     = "fake"
$env:AWS_SECRET_ACCESS_KEY = "fake"
$env:AWS_DEFAULT_REGION    = "eu-west-1"

# ── Copiar override ────────────────────────────────────────
Write-Step "Copiando override LocalStack"
Copy-Item $OverrideSrc $OverrideDst -Force
Write-Ok "Override copiado a $OverrideDst"

# Registrar cleanup
$cleanupBlock = {
    if (Test-Path $OverrideDst) {
        Remove-Item $OverrideDst -Force
        Write-Host "Archivo temporal limpiado." -ForegroundColor Gray
    }
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $cleanupBlock | Out-Null

try {
    Set-Location $EnvDir

    # ── terraform init ─────────────────────────────────────
    Write-Step "terraform init -backend=false"
    terraform init -backend=false -input=false
    Write-Ok "init completado"

    # ── terraform validate ─────────────────────────────────
    Write-Step "terraform validate"
    terraform validate
    Write-Ok "validate — sintaxis HCL correcta"

    # ── terraform plan ─────────────────────────────────────
    Write-Step "terraform plan"
    $PlanOutput = Join-Path $ScriptDir "plan-output.txt"

    terraform plan `
        -var="acm_certificate_arn=arn:aws:acm:eu-west-1:000000000000:certificate/test" `
        -var="alarm_email=test@empresa.com" `
        -var="internal_domain=empresa.internal" `
        -input=false `
        -compact-warnings `
        -out=(Join-Path $ScriptDir "tfplan.out") `
        2>&1 | Tee-Object -FilePath $PlanOutput

    Write-Host "`n══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Ok "terraform plan EXITOSO"
    $planLine = Get-Content $PlanOutput | Where-Object { $_ -match "^Plan:" } | Select-Object -First 1
    if ($planLine) { Write-Host "  $planLine" }
    Write-Host "  Log completo: localstack\plan-output.txt"
    Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan

} finally {
    & $cleanupBlock
}
