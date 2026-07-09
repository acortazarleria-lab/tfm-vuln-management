# ============================================================
# environments/dev/terraform.tfvars
# NO commitear secrets aquí → usar AWS Secrets Manager
# Variables sensibles (ACM ARN, email) → GitHub Actions secrets
# Este archivo es de referencia/ejemplo para uso local
#
# Diferencias respecto a prod:
#  - apagado automático 20:00-08:00 CET L-V (ver módulo defectdojo)
#  - deletion_protection desactivada (var.environment == "dev")
#  - force_destroy habilitado en buckets S3
# ============================================================

project     = "vuln-mgmt"
environment = "dev"
aws_region  = "eu-west-1"
owner       = "equipo-seguridad"
cost_center = "IT-SEC-001"

internal_domain     = "dev.empresa.internal"
acm_certificate_arn = "arn:aws:acm:eu-west-1:ACCOUNT_ID:certificate/CERT_ID_DEV"
alarm_email         = "soc@empresa.com"
