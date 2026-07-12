# ============================================================
# modules/monitoring/main.tf
# CloudWatch: dashboards + alarmas + log groups + SNS
# Well-Architected: Operational Excellence + Security pillars
# ISO 27001: A.12.4 logging y monitorización
# ============================================================

data "aws_region" "current" {}

locals {
  region = data.aws_region.current.name
}

# -----------------------------------------------------------
# SNS Topic — el topic real se crea en el módulo security
# (para romper la dependencia circular entre defectdojo y
# monitoring, ambos necesitan referenciarlo). Aquí solo se
# referencia su ARN, pasado por variable.
# ISO 27001: A.16.1.2 — notificación eventos seguridad
# -----------------------------------------------------------

# -----------------------------------------------------------
# Log Groups CloudWatch — DefectDojo
# ISO 27001: A.12.4.1 — registro de eventos
# -----------------------------------------------------------
resource "aws_cloudwatch_log_group" "defectdojo_app" {
  name              = "/vuln-mgmt/defectdojo/django"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_cloudwatch_arn

  tags = merge(var.common_tags, { Service = "defectdojo" })
}

resource "aws_cloudwatch_log_group" "defectdojo_celery" {
  name              = "/vuln-mgmt/defectdojo/celery"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_cloudwatch_arn

  tags = merge(var.common_tags, { Service = "defectdojo" })
}

resource "aws_cloudwatch_log_group" "defectdojo_install" {
  name              = "/vuln-mgmt/defectdojo/install"
  retention_in_days = 30
  kms_key_id        = var.kms_cloudwatch_arn

  tags = merge(var.common_tags, { Service = "defectdojo" })
}

resource "aws_cloudwatch_log_group" "lambda_enrichment" {
  name              = "/aws/lambda/${var.project}-finding-enrichment-${var.environment}"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_cloudwatch_arn

  tags = merge(var.common_tags, { Service = "lambda" })
}

resource "aws_cloudwatch_log_group" "lambda_metrics" {
  name              = "/aws/lambda/${var.project}-defectdojo-metrics-${var.environment}"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_cloudwatch_arn

  tags = merge(var.common_tags, { Service = "lambda" })
}

resource "aws_cloudwatch_log_group" "lambda_webhook" {
  name              = "/aws/lambda/${var.project}-webhook-receiver-${var.environment}"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_cloudwatch_arn

  tags = merge(var.common_tags, { Service = "lambda" })
}

# -----------------------------------------------------------
# ALARMAS: EC2 DefectDojo
# -----------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "defectdojo_cpu_high" {
  alarm_name          = "${var.project}-defectdojo-cpu-high-${var.environment}"
  alarm_description   = "DefectDojo CPU > 80% durante 10 minutos"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = var.defectdojo_instance_id
  }

  alarm_actions = [var.sns_alerts_arn]
  ok_actions    = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "defectdojo_memory_high" {
  alarm_name          = "${var.project}-defectdojo-memory-high-${var.environment}"
  alarm_description   = "DefectDojo RAM > 85% — riesgo OOM contenedor"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "VulnMgmt/DefectDojo"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = var.defectdojo_instance_id
  }

  alarm_actions = [var.sns_alerts_arn]
  ok_actions    = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "defectdojo_disk_root" {
  alarm_name          = "${var.project}-defectdojo-disk-root-${var.environment}"
  alarm_description   = "DefectDojo disco raíz > 80%"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "disk_used_percent"
  namespace           = "VulnMgmt/DefectDojo"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = var.defectdojo_instance_id
    path       = "/"
    fstype     = "xfs"
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "defectdojo_disk_data" {
  alarm_name          = "${var.project}-defectdojo-disk-data-${var.environment}"
  alarm_description   = "DefectDojo disco datos /opt/defectdojo > 75%"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "disk_used_percent"
  namespace           = "VulnMgmt/DefectDojo"
  period              = 300
  statistic           = "Average"
  threshold           = 75
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = var.defectdojo_instance_id
    path       = "/opt/defectdojo"
    fstype     = "xfs"
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "defectdojo_status_check" {
  alarm_name          = "${var.project}-defectdojo-status-${var.environment}"
  alarm_description   = "DefectDojo fallo de status check EC2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "breaching"

  dimensions = {
    InstanceId = var.defectdojo_instance_id
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

# -----------------------------------------------------------
# ALARMAS: RDS PostgreSQL
# -----------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "rds_connections_high" {
  alarm_name          = "${var.project}-rds-connections-high-${var.environment}"
  alarm_description   = "RDS conexiones > 80 (límite t3.micro: 100)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = var.rds_identifier
  }

  alarm_actions = [var.sns_alerts_arn]
  ok_actions    = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu_high" {
  alarm_name          = "${var.project}-rds-cpu-high-${var.environment}"
  alarm_description   = "RDS CPU > 75% durante 10 minutos"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 75
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = var.rds_identifier
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rds_storage_low" {
  alarm_name          = "${var.project}-rds-storage-low-${var.environment}"
  alarm_description   = "RDS espacio libre < 5GB — revisar autoscaling"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 5368709120 # 5GB en bytes
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = var.rds_identifier
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rds_write_latency" {
  alarm_name          = "${var.project}-rds-write-latency-${var.environment}"
  alarm_description   = "RDS latencia escritura > 20ms — posible saturación I/O"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "WriteLatency"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 0.02
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = var.rds_identifier
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

# -----------------------------------------------------------
# ALARMAS: ALB + WAF
# -----------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "alb_5xx_high" {
  alarm_name          = "${var.project}-alb-5xx-high-${var.environment}"
  alarm_description   = "ALB errores 5xx > 10 en 5 minutos"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "alb_4xx_high" {
  alarm_name          = "${var.project}-alb-4xx-high-${var.environment}"
  alarm_description   = "ALB errores 4xx > 50 en 5 minutos — posible enumeración"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_4XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "alb_latency_high" {
  alarm_name          = "${var.project}-alb-latency-high-${var.environment}"
  alarm_description   = "ALB latencia P95 > 3 segundos"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  extended_statistic  = "p95"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  threshold           = 3
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "waf_blocked_high" {
  alarm_name          = "${var.project}-waf-blocked-high-${var.environment}"
  alarm_description   = "WAF bloqueos > 100 en 5 minutos — posible ataque"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = local.region
    Rule   = "ALL"
  }

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}

# -----------------------------------------------------------
# MÉTRICAS CUSTOM: errores sync CI/CD → DefectDojo
# -----------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "sync_errors" {
  name           = "${var.project}-sync-errors-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.lambda_enrichment.name
  pattern        = "ERROR"

  metric_transformation {
    name          = "SyncErrors"
    namespace     = "VulnMgmt/DefectDojo"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "sync_errors_alarm" {
  alarm_name          = "${var.project}-sync-errors-${var.environment}"
  alarm_description   = "Errores en Lambda enrichment / sync CI/CD — revisar pipeline"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SyncErrors"
  namespace           = "VulnMgmt/DefectDojo"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.sns_alerts_arn]

  tags = var.common_tags
}
