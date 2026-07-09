# ============================================================
# modules/security/kms.tf
# CMK independiente por servicio → blast radius mínimo
# Well-Architected: Security Pillar – protección en reposo
# ISO 27001: A.10.1.2 — gestión de claves criptográficas
# Rotación automática (GDPR: minimización exposición)
#
# SCOPE REDUCIDO: 3 CMKs (rds, s3, secrets) + 1 cloudwatch
# DefectDojo es el único servicio EC2 — comparte CMK ec2
# ============================================================

# -----------------------------------------------------------
# Data sources
# -----------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# -----------------------------------------------------------
# Política base reutilizable
# Principio: root siempre puede gestionar,
#            cada servicio sólo puede usar su propia key
# -----------------------------------------------------------
data "aws_iam_policy_document" "kms_base" {
  statement {
    sid    = "RootFullControl"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:*"]
    }
  }
}

# -----------------------------------------------------------
# CMK 1: RDS PostgreSQL (DefectDojo)
# -----------------------------------------------------------
data "aws_iam_policy_document" "kms_rds" {
  source_policy_documents = [data.aws_iam_policy_document.kms_base.json]

  statement {
    sid    = "RDSServiceAccess"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "rds" {
  description             = "${var.project}-${var.environment}: CMK RDS PostgreSQL"
  deletion_window_in_days = 14
  enable_key_rotation     = true
  multi_region            = false
  policy                  = data.aws_iam_policy_document.kms_rds.json

  tags = merge(var.common_tags, {
    Name    = "${var.project}-kms-rds-${var.environment}"
    Service = "rds"
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.project}-rds-${var.environment}"
  target_key_id = aws_kms_key.rds.key_id
}

# -----------------------------------------------------------
# CMK 2: S3 (logs, reports, backups)
# -----------------------------------------------------------
data "aws_iam_policy_document" "kms_s3" {
  source_policy_documents = [data.aws_iam_policy_document.kms_base.json]

  statement {
    sid    = "S3ServiceAccess"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "WAFLogsAccess"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "s3" {
  description             = "${var.project}-${var.environment}: CMK S3"
  deletion_window_in_days = 14
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_s3.json

  tags = merge(var.common_tags, {
    Name    = "${var.project}-kms-s3-${var.environment}"
    Service = "s3"
  })
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.project}-s3-${var.environment}"
  target_key_id = aws_kms_key.s3.key_id
}

# -----------------------------------------------------------
# CMK 3: EC2 EBS — DefectDojo
# -----------------------------------------------------------
data "aws_iam_policy_document" "kms_ec2" {
  source_policy_documents = [data.aws_iam_policy_document.kms_base.json]

  statement {
    sid    = "EC2EBSAccess"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "ec2" {
  description             = "${var.project}-${var.environment}: CMK EC2 EBS DefectDojo"
  deletion_window_in_days = 14
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_ec2.json

  tags = merge(var.common_tags, {
    Name    = "${var.project}-kms-ec2-${var.environment}"
    Service = "defectdojo"
  })
}

resource "aws_kms_alias" "ec2" {
  name          = "alias/${var.project}-ec2-${var.environment}"
  target_key_id = aws_kms_key.ec2.key_id
}

# -----------------------------------------------------------
# CMK 4: Secrets Manager (credenciales DB, API keys)
# -----------------------------------------------------------
data "aws_iam_policy_document" "kms_secrets" {
  source_policy_documents = [data.aws_iam_policy_document.kms_base.json]

  statement {
    sid    = "SecretsManagerAccess"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "secrets" {
  description             = "${var.project}-${var.environment}: CMK Secrets Manager"
  deletion_window_in_days = 14
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_secrets.json

  tags = merge(var.common_tags, {
    Name    = "${var.project}-kms-secrets-${var.environment}"
    Service = "secrets-manager"
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.project}-secrets-${var.environment}"
  target_key_id = aws_kms_key.secrets.key_id
}

# -----------------------------------------------------------
# CMK 5: CloudWatch Logs
# -----------------------------------------------------------
data "aws_iam_policy_document" "kms_cloudwatch" {
  source_policy_documents = [data.aws_iam_policy_document.kms_base.json]

  statement {
    sid    = "CloudWatchLogsEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt", "kms:Decrypt",
      "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_kms_key" "cloudwatch" {
  description             = "${var.project}-${var.environment}: CMK CloudWatch Logs"
  deletion_window_in_days = 14
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_cloudwatch.json

  tags = merge(var.common_tags, {
    Name    = "${var.project}-kms-cw-${var.environment}"
    Service = "cloudwatch"
  })
}

resource "aws_kms_alias" "cloudwatch" {
  name          = "alias/${var.project}-cloudwatch-${var.environment}"
  target_key_id = aws_kms_key.cloudwatch.key_id
}
