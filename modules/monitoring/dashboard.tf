# ============================================================
# modules/monitoring/dashboard.tf
# CloudWatch Dashboard: vista unificada del sistema
# FIX: for-expressions eliminadas de jsonencode() — no soportado en Terraform
# Métricas de categorías expandidas manualmente
# ============================================================

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project}-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [

      # ── Fila 1: Estado general ──────────────────────────
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 6
        height = 6
        properties = {
          title  = "Findings activos por severidad"
          view   = "singleValue"
          period = 3600
          metrics = [
            ["VulnMgmt/DefectDojo", "ActiveFindings", "Severity", "Critical", "Environment", var.environment, "Project", var.project, { label = "Críticos" }],
            ["VulnMgmt/DefectDojo", "ActiveFindings", "Severity", "High", "Environment", var.environment, "Project", var.project, { label = "Altos" }],
            ["VulnMgmt/DefectDojo", "ActiveFindings", "Severity", "Medium", "Environment", var.environment, "Project", var.project, { label = "Medios" }],
            ["VulnMgmt/DefectDojo", "ActiveFindings", "Severity", "Low", "Environment", var.environment, "Project", var.project, { label = "Bajos" }]
          ]
        }
      },

      {
        type   = "metric"
        x      = 6
        y      = 0
        width  = 6
        height = 6
        properties = {
          title  = "Findings fuera de SLA"
          view   = "singleValue"
          period = 3600
          metrics = [
            ["VulnMgmt/DefectDojo", "OverdueCriticalFindings", "Environment", var.environment, "Project", var.project, { label = "Críticos >30d" }],
            ["VulnMgmt/DefectDojo", "OverdueHighFindings", "Environment", var.environment, "Project", var.project, { label = "Altos >60d" }]
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 6
        height = 6
        properties = {
          title  = "EC2 DefectDojo"
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", var.defectdojo_instance_id, { label = "CPU %" }],
            ["VulnMgmt/DefectDojo", "mem_used_percent", "InstanceId", var.defectdojo_instance_id, { label = "RAM %" }]
          ]
          yAxis = { left = { min = 0, max = 100 } }
        }
      },

      {
        type   = "metric"
        x      = 18
        y      = 0
        width  = 6
        height = 6
        properties = {
          title  = "ALB: tráfico y errores"
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_arn_suffix, { label = "Requests", stat = "Sum" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", var.alb_arn_suffix, { label = "5xx", stat = "Sum" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", var.alb_arn_suffix, { label = "4xx", stat = "Sum" }]
          ]
        }
      },

      # ── Fila 2: Base de datos + red ─────────────────────
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "RDS PostgreSQL — conexiones y CPU"
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", var.rds_identifier, { label = "Conexiones" }],
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.rds_identifier, { label = "CPU %", yAxis = "right" }]
          ]
        }
      },

      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "RDS — almacenamiento libre"
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", var.rds_identifier, { label = "Libre (bytes)" }]
          ]
        }
      },

      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "WAF — permitidas vs bloqueadas"
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", var.waf_web_acl_name, "Region", local.region, "Rule", "ALL", { label = "Permitidas", stat = "Sum" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", var.waf_web_acl_name, "Region", local.region, "Rule", "ALL", { label = "Bloqueadas", stat = "Sum" }]
          ]
        }
      },

      # ── Fila 3: Findings por categoría — expandido manualmente ─────────
      # (Terraform no soporta for-expressions dentro de jsonencode)
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Findings críticos por categoría"
          view   = "bar"
          period = 3600
          metrics = [
            ["VulnMgmt/DefectDojo", "ActiveFindingsByCategory", "Category", "SAST", "Severity", "Critical", "Environment", var.environment, "Project", var.project, { label = "SAST Críticos" }],
            ["VulnMgmt/DefectDojo", "ActiveFindingsByCategory", "Category", "DAST", "Severity", "Critical", "Environment", var.environment, "Project", var.project, { label = "DAST Críticos" }],
            ["VulnMgmt/DefectDojo", "ActiveFindingsByCategory", "Category", "SCA", "Severity", "Critical", "Environment", var.environment, "Project", var.project, { label = "SCA Críticos" }],
            ["VulnMgmt/DefectDojo", "ActiveFindingsByCategory", "Category", "Infraestructura", "Severity", "Critical", "Environment", var.environment, "Project", var.project, { label = "Infra Críticos" }],
            ["VulnMgmt/DefectDojo", "ActiveFindingsByCategory", "Category", "Runtime", "Severity", "Critical", "Environment", var.environment, "Project", var.project, { label = "Runtime Críticos" }]
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Errores sync / enrichment Lambda"
          view   = "timeSeries"
          period = 300
          metrics = [
            ["VulnMgmt/DefectDojo", "SyncErrors", "Environment", var.environment, "Project", var.project, { label = "Errores sync", stat = "Sum" }],
            ["VulnMgmt/DefectDojo", "EnrichedFindings", "Environment", var.environment, "Project", var.project, { label = "Findings enriquecidos", stat = "Sum" }]
          ]
        }
      }
    ]
  })
}
