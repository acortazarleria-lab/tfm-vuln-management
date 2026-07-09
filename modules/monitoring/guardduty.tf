# ============================================================
# modules/monitoring/guardduty.tf
# GuardDuty: detección amenazas + EventBridge → SNS
# ISO 27001: A.16.1.1 — responsabilidades gestión incidentes
# ============================================================

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-guardduty-${var.environment}"
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project}-guardduty-findings-${var.environment}"
  description = "GuardDuty findings severity >= 4 → SNS"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]
    }
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuardDutySNS"
  arn       = var.sns_alerts_arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      description = "$.detail.description"
      region      = "$.region"
      time        = "$.time"
    }
    input_template = <<-EOT
      "GUARDDUTY ALERT | Severidad: <severity> | Tipo: <type> | Región: <region> | Hora: <time> | <description>"
    EOT
  }
}
