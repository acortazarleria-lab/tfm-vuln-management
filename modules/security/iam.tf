# ============================================================
# modules/security/iam.tf
# IAM roles + instance profiles
# Principio: cada instancia/función tiene SÓLO los permisos
#            necesarios
# Well-Architected: Security – least privilege
# ISO 27001: A.9.2.3 — gestión privilegios acceso
#
# SCOPE REDUCIDO: role DefectDojo + role Lambda integración
#                 + role Scheduler (compartido)
# ============================================================

# -----------------------------------------------------------
# Trust policy compartida EC2
# -----------------------------------------------------------
data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# -----------------------------------------------------------
# IAM Role: DefectDojo
# Necesita: SSM, CloudWatch, S3 (reports), Secrets (DB creds)
# NO necesita: EC2 full, IAM, KMS admin
# -----------------------------------------------------------
resource "aws_iam_role" "defectdojo" {
  name               = "${var.project}-role-defectdojo-${var.environment}"
  description        = "Role DefectDojo: SSM + CW + S3 + Secrets DB"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  tags               = merge(var.common_tags, { Service = "defectdojo" })
}

data "aws_iam_policy_document" "defectdojo_policy" {
  # SSM Session Manager (acceso sin SSH expuesto)
  statement {
    sid    = "SSMSessionManager"
    effect = "Allow"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.region}:${local.account_id}:log-group:/vuln-mgmt/defectdojo*"
    ]
  }

  # S3: reports de vulnerabilidades (lectura + escritura)
  statement {
    sid    = "S3Reports"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      "arn:aws:s3:::${var.project}-reports-${var.environment}-${local.account_id}",
      "arn:aws:s3:::${var.project}-reports-${var.environment}-${local.account_id}/defectdojo/*"
    ]
  }

  statement {
    sid    = "KMSAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.ec2.arn,
      aws_kms_key.s3.arn,
      aws_kms_key.secrets.arn
    ]
  }

  # Secrets: SÓLO las credenciales de DefectDojo
  statement {
    sid    = "SecretsDefectDojo"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue"
    ]
    resources = [
      "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.project}/defectdojo/*"
    ]
  }
}

resource "aws_iam_policy" "defectdojo" {
  name   = "${var.project}-policy-defectdojo-${var.environment}"
  policy = data.aws_iam_policy_document.defectdojo_policy.json
  tags   = var.common_tags
}

resource "aws_iam_role_policy_attachment" "defectdojo" {
  role       = aws_iam_role.defectdojo.name
  policy_arn = aws_iam_policy.defectdojo.arn
}

resource "aws_iam_instance_profile" "defectdojo" {
  name = "${var.project}-profile-defectdojo-${var.environment}"
  role = aws_iam_role.defectdojo.name
  tags = var.common_tags
}

# -----------------------------------------------------------
# SNS Topic — canal de alertas (creado aquí para romper
# dependencia circular entre módulos defectdojo y monitoring,
# ambos necesitan referenciarlo)
# ISO 27001: A.16.1.2 — notificación eventos seguridad
# -----------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name              = "${var.project}-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.cloudwatch.arn

  tags = merge(var.common_tags, {
    Name = "${var.project}-sns-alerts-${var.environment}"
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

data "aws_iam_policy_document" "sns_policy" {
  statement {
    sid    = "CloudWatchAlarms"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "GuardDutyAlerts"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid    = "LambdaIntegration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda_integration.arn]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

# -----------------------------------------------------------
# IAM Role: Lambda de integración
# (enrichment + webhook + métricas)
# -----------------------------------------------------------
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_integration" {
  name               = "${var.project}-role-lambda-integration-${var.environment}"
  description        = "Role Lambdas integración: CW + Secrets + VPC"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = merge(var.common_tags, { Service = "lambda-integration" })
}

data "aws_iam_policy_document" "lambda_integration_policy" {
  statement {
    sid    = "LambdaBasicExecution"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.project}-*"
    ]
  }

  statement {
    sid    = "VPCAccess"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SecretsAPIKeys"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = [
      "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.project}/defectdojo/api-key*"
    ]
  }

  statement {
    sid    = "KMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.secrets.arn]
  }

  statement {
    sid    = "CloudWatchMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SNSPublish"
    effect = "Allow"
    actions = [
      "sns:Publish"
    ]
    resources = [
      "arn:aws:sns:${local.region}:${local.account_id}:${var.project}-alerts-${var.environment}"
    ]
  }
}

resource "aws_iam_policy" "lambda_integration" {
  name   = "${var.project}-policy-lambda-integration-${var.environment}"
  policy = data.aws_iam_policy_document.lambda_integration_policy.json
  tags   = var.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_integration" {
  role       = aws_iam_role.lambda_integration.name
  policy_arn = aws_iam_policy.lambda_integration.arn
}

# -----------------------------------------------------------
# IAM Role: Scheduler (apagado/encendido dev)
# Compartido para todas las instancias del proyecto
# -----------------------------------------------------------
data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.project}-role-scheduler-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
  tags               = var.common_tags
}

data "aws_iam_policy_document" "scheduler_policy" {
  statement {
    effect    = "Allow"
    actions   = ["ec2:StartInstances", "ec2:StopInstances"]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [var.project]
    }
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "${var.project}-policy-scheduler-${var.environment}"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_policy.json
}

# -----------------------------------------------------------
# IAM Role: AWS Config (compliance continuo)
# -----------------------------------------------------------
data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.project}-role-config-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# -----------------------------------------------------------
# IAM Role: DLM (snapshots EBS DefectDojo)
# -----------------------------------------------------------
data "aws_iam_policy_document" "dlm_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["dlm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dlm" {
  name               = "${var.project}-role-dlm-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.dlm_assume.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

# -----------------------------------------------------------
# IAM Role: RDS Enhanced Monitoring
# -----------------------------------------------------------
data "aws_iam_policy_document" "rds_monitoring_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${var.project}-role-rds-monitoring-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
