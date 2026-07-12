# ============================================================
# locals.tf
# Valores derivados: tags, nombres de recursos, CIDRs
# Centralizar aquí evita inconsistencias entre módulos
# Scope reducido: DefectDojo como core + RDS + ALB/WAF +
#                 S3 + Security + Monitoring + CI/CD
# Dependency-Track se ejecuta como step de CI/CD (no EC2)
# Wazuh fuera de scope
# ============================================================

locals {
  # Tags obligatorios en TODOS los recursos
  # ISO 27001: A.8.1.1 — inventario de activos
  common_tags = {
    Project     = var.project
    Environment = var.environment
    Owner       = var.owner
    CostCenter  = var.cost_center
    Compliance  = "ISO27001-GDPR"
    ManagedBy   = "terraform"
  }

  # Convención de naming: {project}-{recurso}-{env}
  name_prefix = "${var.project}-${var.environment}"

  # CIDRs por capa (segmentación de red)
  # ISO 27001: A.13.1.3 — segregación en redes
  cidrs = {
    vpc             = "10.0.0.0/16"
    public          = "10.0.1.0/24" # ALB interno (AZ-a)
    private_compute = "10.0.2.0/24" # EC2: DefectDojo (AZ-a)
    private_data    = "10.0.3.0/24" # RDS (AZ-a activa)
    private_lambda  = "10.0.4.0/24" # Lambdas integración + CI/CD runners
    private_data_b  = "10.0.5.0/24" # RDS subnet group standby (AZ-b, solo para cumplir req. AWS)
    public_b        = "10.0.6.0/24" # ALB subnet standby (AZ-b, solo para cumplir req. AWS)
  }

  # Horario apagado automático (CET laboral) — solo dev
  # Ahorro: ~60% horas EC2
  schedule = {
    shutdown = "cron(0 19 ? * MON-FRI *)" # 20:00 CET (19 UTC+1)
    startup  = "cron(0 7 ? * MON-FRI *)"  # 08:00 CET (07 UTC+1)
  }

  # Retención logs por capa
  retention = {
    hot_days     = 90  # CloudWatch + datos operativos
    glacier_days = 365 # S3 Glacier
    backup_days  = 30  # RDS snapshots
    sg_flow_days = 90  # VPC Flow Logs (GDPR)
  }
}
