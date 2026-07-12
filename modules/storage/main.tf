# ============================================================
# modules/storage/main.tf
# S3: logs, reports, backups + lifecycle + WORM + SSE-KMS
# Well-Architected: Security + Cost Optimization pillars
# ISO 27001: A.12.3.1 backup, A.18.1.3 protección registros
# GDPR: Art.5(1)(e) limitación conservación
# ============================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# -----------------------------------------------------------
# BUCKET 1: Logs de auditoría (VPC Flow, WAF, ALB, CloudTrail)
# WORM: Object Lock Compliance mode
# ISO 27001: A.18.1.3 — protección registros auditoría
# -----------------------------------------------------------
resource "aws_s3_bucket" "logs" {
  bucket        = "${var.project}-logs-${var.environment}-${local.account_id}"
  force_destroy = var.environment == "prod" ? false : true

  # object_lock_enabled=true activa automáticamente versioning
  # y permite configurar la retención por defecto en el mismo resource (provider 5.x)
  object_lock_enabled = true

  tags = merge(var.common_tags, {
    Name       = "${var.project}-logs-${var.environment}"
    DataClass  = "confidential"
    Retention  = "365d"
    Compliance = "ISO27001-GDPR-WORM"
  })
}

# Configuración WORM inline — compatible con provider AWS ~> 5.50
# default_retention aplica a todos los objetos sin retención explícita
resource "aws_s3_bucket_object_lock_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_s3_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "vpc-flow-logs-tiering"
    status = "Enabled"
    filter { prefix = "vpc-flow/" }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "waf-logs-tiering"
    status = "Enabled"
    filter { prefix = "waf/" }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "alb-logs-tiering"
    status = "Enabled"
    filter { prefix = "alb/" }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "cloudtrail-tiering"
    status = "Enabled"
    filter { prefix = "cloudtrail/" }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "aws-config-tiering"
    status = "Enabled"
    filter { prefix = "aws-config/" }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "compliance-reports-tiering"
    status = "Enabled"
    filter { prefix = "compliance-reports/" }

    transition {
      days          = 180
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 730 # 2 años — evidencia auditoría histórica
    }
  }

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "logs_bucket_policy" {
  statement {
    sid    = "DenyNonSSL"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyNonKMSEncryption"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  # ALB Access Logs — account ID del servicio ELB en eu-west-1
  statement {
    sid    = "ALBAccessLogs"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::156460612806:root"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/alb/*"]
  }

  statement {
    sid    = "WAFLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/waf/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "ConfigServiceAccess"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = ["s3:PutObject", "s3:GetBucketAcl"]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/aws-config/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "CloudTrailAccess"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = ["s3:PutObject", "s3:GetBucketAcl"]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/cloudtrail/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "DefectDojoInstanceAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.defectdojo_role_arn]
    }
    actions = [
      "s3:PutObject",
      "s3:GetObject"
    ]
    resources = ["${aws_s3_bucket.logs.arn}/*"]
  }

  statement {
    sid    = "DenyDelete"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:DeleteBucket"
    ]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*"
    ]
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# -----------------------------------------------------------
# BUCKET 2: Reports vulnerabilidades (DefectDojo SBOMs, scans)
# Sin WORM — los reports se actualizan periódicamente
# -----------------------------------------------------------
resource "aws_s3_bucket" "reports" {
  bucket        = "${var.project}-reports-${var.environment}-${local.account_id}"
  force_destroy = var.environment == "prod" ? false : true

  tags = merge(var.common_tags, {
    Name      = "${var.project}-reports-${var.environment}"
    DataClass = "confidential"
    Retention = "365d"
  })
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_s3_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_intelligent_tiering_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  name   = "reports-intelligent-tiering"

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "reports-version-cleanup"
    status = "Enabled"
    filter { prefix = "" }

    noncurrent_version_expiration {
      noncurrent_days           = 90
      newer_noncurrent_versions = 3
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 365
    }
  }
}

data "aws_iam_policy_document" "reports_bucket_policy" {
  statement {
    sid    = "DenyNonSSL"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.reports.arn,
      "${aws_s3_bucket.reports.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DefectDojoInstanceAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.defectdojo_role_arn]
    }
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:DeleteObject"
    ]
    resources = [
      aws_s3_bucket.reports.arn,
      "${aws_s3_bucket.reports.arn}/*"
    ]
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = data.aws_iam_policy_document.reports_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.reports]
}

# -----------------------------------------------------------
# BUCKET 3: Backups RDS + snapshots EBS exportados
# -----------------------------------------------------------
resource "aws_s3_bucket" "backups" {
  bucket        = "${var.project}-backups-${var.environment}-${local.account_id}"
  force_destroy = var.environment == "prod" ? false : true

  tags = merge(var.common_tags, {
    Name      = "${var.project}-backups-${var.environment}"
    DataClass = "restricted"
    Retention = "365d"
  })
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_s3_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "rds-backups-tiering"
    status = "Enabled"
    filter { prefix = "rds/" }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }

  rule {
    id     = "ebs-snapshots-tiering"
    status = "Enabled"
    filter { prefix = "ebs/" }

    transition {
      days          = 7
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 30
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "abort-multipart"
    status = "Enabled"
    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 3
    }
  }
}

data "aws_iam_policy_document" "backups_bucket_policy" {
  statement {
    sid    = "DenyNonSSL"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.backups.arn,
      "${aws_s3_bucket.backups.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "RDSSnapshotExport"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["export.rds.amazonaws.com"]
    }
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:DeleteObject"
    ]
    resources = [
      aws_s3_bucket.backups.arn,
      "${aws_s3_bucket.backups.arn}/rds/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "DenyManualDelete"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:DeleteObject", "s3:DeleteBucket"]
    resources = [
      aws_s3_bucket.backups.arn,
      "${aws_s3_bucket.backups.arn}/*"
    ]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalServiceName"
      values   = ["backup.amazonaws.com", "export.rds.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "backups" {
  bucket = aws_s3_bucket.backups.id
  policy = data.aws_iam_policy_document.backups_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.backups]
}

# -----------------------------------------------------------
# BUCKET 5: WAF Logs — nombre DEBE empezar con "aws-waf-logs-"
# Requisito de servicio WAFv2 para destino S3 de logging
# ISO 27001: A.12.4.1 — registro de eventos
# -----------------------------------------------------------
resource "aws_s3_bucket" "waf_logs" {
  # AWS WAFv2 exige que el bucket se llame exactamente aws-waf-logs-*
  bucket        = "aws-waf-logs-${var.project}-${var.environment}-${local.account_id}"
  force_destroy = var.environment == "prod" ? false : true

  tags = merge(var.common_tags, {
    Name      = "aws-waf-logs-${var.project}-${var.environment}"
    DataClass = "confidential"
    Retention = "90d"
  })
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_s3_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket                  = aws_s3_bucket.waf_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  rule {
    id     = "waf-logs-expire"
    status = "Enabled"
    filter { prefix = "" }
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    expiration { days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 3 }
  }
}

# -----------------------------------------------------------
# BUCKET 4: S3 Access Logging meta-bucket
# Evita bucle infinito: el bucket de logs no se loggea a sí mismo
# -----------------------------------------------------------
resource "aws_s3_bucket" "access_logs_meta" {
  bucket        = "${var.project}-s3access-${var.environment}-${local.account_id}"
  force_destroy = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-s3-access-logs-meta"
  })
}

resource "aws_s3_bucket_public_access_block" "access_logs_meta" {
  bucket                  = aws_s3_bucket.access_logs_meta.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_meta" {
  bucket = aws_s3_bucket.access_logs_meta.id
  rule {
    id     = "expire-meta-logs"
    status = "Enabled"
    filter { prefix = "" }
    expiration { days = 90 }
  }
}

resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = aws_s3_bucket.access_logs_meta.id
  target_prefix = "logs-bucket/"
}

resource "aws_s3_bucket_logging" "reports" {
  bucket        = aws_s3_bucket.reports.id
  target_bucket = aws_s3_bucket.access_logs_meta.id
  target_prefix = "reports-bucket/"
}

resource "aws_s3_bucket_logging" "backups" {
  bucket        = aws_s3_bucket.backups.id
  target_bucket = aws_s3_bucket.access_logs_meta.id
  target_prefix = "backups-bucket/"
}
