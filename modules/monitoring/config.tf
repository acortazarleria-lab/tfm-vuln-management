# ============================================================
# modules/monitoring/config.tf
# AWS Config: compliance continuo ISO 27001
# CloudTrail: trazabilidad completa
# ISO 27001: A.18.2.2 — cumplimiento políticas seguridad
# ============================================================

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project}-config-recorder-${var.environment}"
  role_arn = var.config_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project}-config-channel-${var.environment}"
  s3_bucket_name = var.s3_logs_bucket
  s3_key_prefix  = "aws-config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# ── Reglas ISO 27001 ───────────────────────────────────────

resource "aws_config_config_rule" "ebs_encrypted" {
  name        = "${var.project}-ebs-encrypted-${var.environment}"
  description = "ISO 27001 A.10.1.1: EBS volumes deben estar cifrados"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "rds_encrypted" {
  name        = "${var.project}-rds-encrypted-${var.environment}"
  description = "ISO 27001 A.10.1.1: RDS instancias deben estar cifradas"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "s3_encrypted" {
  name        = "${var.project}-s3-encrypted-${var.environment}"
  description = "ISO 27001 A.10.1.1: S3 buckets con SSE habilitado"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "rds_no_public" {
  name        = "${var.project}-rds-no-public-${var.environment}"
  description = "ISO 27001 A.13.1.1: RDS no debe ser accesible públicamente"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "root_mfa" {
  name        = "${var.project}-root-mfa-${var.environment}"
  description = "ISO 27001 A.9.4.2: MFA habilitado en cuenta root"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "${var.project}-cloudtrail-enabled-${var.environment}"
  description = "ISO 27001 A.12.4.1: CloudTrail debe estar habilitado"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "kms_rotation" {
  name        = "${var.project}-kms-rotation-${var.environment}"
  description = "ISO 27001 A.10.1.2: KMS CMKs con rotación automática"

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "vpc_flow_logs" {
  name        = "${var.project}-vpc-flow-logs-${var.environment}"
  description = "ISO 27001 A.12.4.1: VPC Flow Logs deben estar habilitados"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

resource "aws_config_config_rule" "s3_no_public" {
  name        = "${var.project}-s3-no-public-${var.environment}"
  description = "GDPR Art.32: S3 buckets no deben tener acceso público"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.common_tags
}

# -----------------------------------------------------------
# CloudTrail — auditoría completa multi-servicio
# ISO 27001: A.12.4.2 — protección de la información de registro
# -----------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = "${var.project}-trail-${var.environment}"
  s3_bucket_name                = var.s3_logs_bucket
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_cloudwatch_arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-cloudtrail-${var.environment}"
  })
}
