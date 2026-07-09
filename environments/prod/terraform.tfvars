# ============================================================
# environments/prod/terraform.tfvars
# NO commitear secrets aquí → usar AWS Secrets Manager
# Variables sensibles (ACM ARN, email) → GitHub Actions secrets
# Este archivo es de referencia/ejemplo para uso local
# ============================================================

project     = "vuln-mgmt"
environment = "prod"
aws_region  = "eu-west-1"
owner       = "equipo-seguridad"
cost_center = "IT-SEC-001"

internal_domain     = "empresa.internal"
acm_certificate_arn = "arn:aws:acm:eu-west-1:ACCOUNT_ID:certificate/CERT_ID"
alarm_email         = "soc@empresa.com"
