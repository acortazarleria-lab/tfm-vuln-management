# ============================================================
# docs/iso27001-controls.tf
# Mapeo de controles ISO 27001:2022 → recursos Terraform
# Generado como código para ser auditable y versionable.
#
# NOTA: este archivo es documental. No se incluye en ningún
# `environments/*/main.tf` ni se aplica con terraform apply —
# vive en docs/ precisamente para no formar parte del grafo de
# recursos. Sirve como evidencia trazable en la defensa del TFM
# y como entrada de scripts/generate-compliance-report.py.
# ============================================================

terraform {
  required_version = ">= 1.7.0, < 2.0.0"
}

locals {
  iso27001_controls = {

    # ── Dominio 5: Políticas de seguridad ──────────────────
    "A.5.1.1" = {
      control     = "Políticas de seguridad de la información"
      implemented = true
      evidence    = ["locals.tf:common_tags", "README.md"]
      status      = "COMPLIANT"
    }

    # ── Dominio 6: Organización de la seguridad ────────────
    "A.6.1.2" = {
      control     = "Segregación de funciones"
      implemented = true
      evidence = [
        "modules/security/iam.tf:role por servicio",
        ".github/workflows/terraform-apply.yml:aprobación manual"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 8: Gestión de activos ──────────────────────
    "A.8.1.1" = {
      control     = "Inventario de activos"
      implemented = true
      evidence = [
        "environments/prod/locals.tf:common_tags (Project, Owner, CostCenter)",
        "modules/monitoring/config.tf:AWS Config recorder"
      ]
      status = "COMPLIANT"
    }

    "A.8.2.1" = {
      control     = "Clasificación de la información"
      implemented = true
      evidence = [
        "modules/storage/main.tf:tags DataClass=confidential/restricted",
        "modules/database/main.tf:tags Service=database"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 9: Control de acceso ───────────────────────
    "A.9.1.2" = {
      control     = "Acceso a redes y servicios de red"
      implemented = true
      evidence = [
        "modules/networking/vpc.tf:NACLs por subnet",
        "modules/networking/alb.tf:SGs least privilege",
        "modules/networking/alb.tf:ALB internal scheme"
      ]
      status = "COMPLIANT"
    }

    "A.9.2.3" = {
      control     = "Gestión de privilegios de acceso"
      implemented = true
      evidence = [
        "modules/security/iam.tf:ARNs explícitos en políticas",
        "modules/security/iam.tf:prefijos /project/service/* en Secrets"
      ]
      status = "COMPLIANT"
    }

    "A.9.4.1" = {
      control     = "Restricción de acceso a información"
      implemented = true
      evidence = [
        "modules/defectdojo/main.tf:IMDSv2 obligatorio",
        "modules/networking/alb.tf:drop_invalid_header_fields=true"
      ]
      status = "COMPLIANT"
    }

    "A.9.4.2" = {
      control     = "Procedimientos seguros de inicio de sesión"
      implemented = true
      evidence = [
        "modules/networking/vpc.tf:SSM Session Manager sin SSH",
        "modules/security/iam.tf:SSM permisos mínimos",
        "modules/networking/alb.tf:WAF OWASP ruleset"
      ]
      status = "COMPLIANT"
    }

    "A.9.4.3" = {
      control     = "Sistema de gestión de contraseñas"
      implemented = true
      evidence = [
        "modules/database/main.tf:random_password 32 chars",
        "modules/database/main.tf:Secrets Manager",
        "modules/defectdojo/main.tf:random_password admin"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 10: Criptografía ───────────────────────────
    "A.10.1.1" = {
      control     = "Política sobre el uso de controles criptográficos"
      implemented = true
      evidence = [
        "modules/security/kms.tf:5 CMKs independientes",
        "modules/database/main.tf:storage_encrypted=true",
        "modules/storage/main.tf:SSE-KMS todos los buckets",
        "modules/networking/alb.tf:TLS 1.3 ELBSecurityPolicy"
      ]
      status = "COMPLIANT"
    }

    "A.10.1.2" = {
      control     = "Gestión de claves criptográficas"
      implemented = true
      evidence = [
        "modules/security/kms.tf:enable_key_rotation=true",
        "modules/security/kms.tf:deletion_window=14d",
        "modules/monitoring/config.tf:CMK_BACKING_KEY_ROTATION_ENABLED"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 12: Seguridad en operaciones ───────────────
    "A.12.1.2" = {
      control     = "Gestión de cambios"
      implemented = true
      evidence = [
        "environments/prod/backend.tf:DynamoDB state locking",
        ".github/workflows/terraform-apply.yml:aprobación manual",
        ".github/workflows/terraform-plan.yml:drift detection"
      ]
      status = "COMPLIANT"
    }

    "A.12.3.1" = {
      control     = "Backup de información"
      implemented = true
      evidence = [
        "modules/database/main.tf:backup_retention_period=30",
        "modules/defectdojo/main.tf:DLM snapshots 7d",
        "modules/storage/main.tf:S3 versioning enabled"
      ]
      status = "COMPLIANT"
    }

    "A.12.4.1" = {
      control     = "Registro de eventos"
      implemented = true
      evidence = [
        "modules/monitoring/config.tf:CloudTrail multi-service",
        "modules/networking/vpc.tf:VPC Flow Logs ALL",
        "modules/monitoring/guardduty.tf:GuardDuty S3+EC2",
        "modules/monitoring/main.tf:CloudWatch Log Groups 90d"
      ]
      status = "COMPLIANT"
    }

    "A.12.4.2" = {
      control     = "Protección de la información de registro"
      implemented = true
      evidence = [
        "modules/storage/main.tf:S3 WORM Object Lock COMPLIANCE",
        "modules/monitoring/config.tf:CloudTrail log validation",
        "modules/storage/main.tf:DenyDelete bucket policy"
      ]
      status = "COMPLIANT"
    }

    "A.12.6.1" = {
      control     = "Gestión de vulnerabilidades técnicas"
      implemented = true
      evidence = [
        "modules/defectdojo/main.tf:DefectDojo 5 categorías",
        ".github/workflows/security-scan.yml:Trivy+Checkov+ZAP+Semgrep+DTrack",
        "modules/defectdojo/lambda/enrichment/handler.py:EPSS+KEV+SLA"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 13: Seguridad de comunicaciones ────────────
    "A.13.1.1" = {
      control     = "Controles de red"
      implemented = true
      evidence = [
        "modules/networking/vpc.tf:NACLs stateless defense-in-depth",
        "modules/networking/alb.tf:WAF OWASP + IP reputation",
        "modules/monitoring/config.tf:VPC_FLOW_LOGS_ENABLED rule"
      ]
      status = "COMPLIANT"
    }

    "A.13.1.3" = {
      control     = "Segregación en redes"
      implemented = true
      evidence = [
        "modules/networking/vpc.tf:4 subnets por función",
        "environments/prod/locals.tf:cidrs por capa",
        "modules/networking/alb.tf:SG reference entre capas"
      ]
      status = "COMPLIANT"
    }

    "A.13.2.1" = {
      control     = "Políticas y procedimientos de transferencia de información"
      implemented = true
      evidence = [
        "modules/networking/vpc.tf:VPC Endpoints 7 servicios",
        "modules/networking/alb.tf:TLS 1.3 en tránsito",
        "modules/database/main.tf:rds.force_ssl=1"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 14: Adquisición, desarrollo, mantenimiento ─
    "A.14.2.2" = {
      control     = "Procedimientos de control de cambios en sistemas"
      implemented = true
      evidence = [
        ".github/workflows/terraform-apply.yml:environment prod-apply",
        ".github/workflows/terraform-validate.yml:PR checks",
        "environments/prod/backend.tf:estado versionado"
      ]
      status = "COMPLIANT"
    }

    "A.14.2.5" = {
      control     = "Principios de ingeniería de sistemas seguros"
      implemented = true
      evidence = [
        "modules/database/main.tf:parameter group hardened",
        "modules/defectdojo/templates/defectdojo-install.sh.tpl:sysctl hardening",
        "modules/networking/alb.tf:drop_invalid_header_fields"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 16: Gestión de incidentes ──────────────────
    "A.16.1.1" = {
      control     = "Responsabilidades y procedimientos de gestión de incidentes"
      implemented = true
      evidence = [
        "modules/monitoring/guardduty.tf:EventBridge → SNS",
        "modules/defectdojo/lambda/webhook/handler.py:alertas críticas",
        "modules/security/iam.tf:SNS topic cifrado KMS"
      ]
      status = "COMPLIANT"
    }

    "A.16.1.2" = {
      control     = "Notificación de eventos de seguridad"
      implemented = true
      evidence = [
        "modules/monitoring/main.tf:12 alarmas CloudWatch → SNS",
        "modules/defectdojo/lambda/webhook/handler.py:NEW_FINDING alert",
        "modules/monitoring/guardduty.tf:severity >= 4"
      ]
      status = "COMPLIANT"
    }

    # ── Dominio 17: Continuidad de negocio ─────────────────
    "A.17.1.1" = {
      control     = "Planificación de la continuidad de seguridad"
      implemented = true
      evidence = [
        "modules/database/main.tf:final_snapshot antes destroy",
        "modules/database/main.tf:deletion_protection prod",
        "modules/storage/main.tf:force_destroy=false prod"
      ]
      status = "COMPLIANT"
      note   = "Single-AZ: RTO <4h documentado y aceptado para presupuesto PyME"
    }

    # ── Dominio 18: Cumplimiento ───────────────────────────
    "A.18.1.3" = {
      control     = "Protección de registros"
      implemented = true
      evidence = [
        "modules/storage/main.tf:WORM COMPLIANCE 365d",
        "modules/storage/main.tf:DenyDelete policy",
        "modules/monitoring/config.tf:CloudTrail integridad"
      ]
      status = "COMPLIANT"
    }

    "A.18.2.2" = {
      control     = "Cumplimiento de políticas de seguridad"
      implemented = true
      evidence = [
        "modules/monitoring/config.tf:9 reglas AWS Config",
        "modules/monitoring/config.tf:ENCRYPTED_VOLUMES",
        "modules/monitoring/config.tf:RDS_STORAGE_ENCRYPTED"
      ]
      status = "COMPLIANT"
    }
  }
}

# Salida documental: consumida por scripts/generate-compliance-report.py
# (y evita el falso positivo terraform_unused_declarations de TFLint).
output "iso27001_controls" {
  description = "Mapeo de controles ISO 27001:2022 a recursos Terraform"
  value       = local.iso27001_controls
}
