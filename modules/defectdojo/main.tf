# ============================================================
# modules/defectdojo/main.tf
# EC2 t3.small: DefectDojo vía Docker Compose
# Well-Architected: Security + Cost Optimization
# ISO 27001: A.12.6 gestión vulnerabilidades técnicas
# Categorías: SAST, DAST, SCA, Infraestructura, Código
# ============================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# -----------------------------------------------------------
# AMI Ubuntu 22.04 LTS
# -----------------------------------------------------------
data "aws_ami" "ubuntu_22" {
  most_recent = true
  owners      = ["099720109477"] # Canonical oficial

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# -----------------------------------------------------------
# Secret: API Key DefectDojo (generada en primer arranque)
# -----------------------------------------------------------
resource "aws_secretsmanager_secret" "defectdojo_api_key" {
  name        = "${var.project}/defectdojo/api-key"
  description = "API Key DefectDojo para integraciones (CI/CD, Lambdas)"
  kms_key_id  = var.kms_secrets_arn

  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = merge(var.common_tags, {
    Name    = "${var.project}-secret-defectdojo-apikey"
    Service = "defectdojo"
  })
}

resource "aws_secretsmanager_secret_version" "defectdojo_api_key" {
  secret_id = aws_secretsmanager_secret.defectdojo_api_key.id
  secret_string = jsonencode({
    api_key  = "PLACEHOLDER_UPDATED_ON_FIRST_BOOT"
    base_url = "http://localhost:8080"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Secret: credenciales admin DefectDojo
resource "random_password" "defectdojo_admin" {
  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}|"
}

resource "aws_secretsmanager_secret" "defectdojo_admin" {
  name        = "${var.project}/defectdojo/admin-credentials"
  description = "Credenciales administrador DefectDojo"
  kms_key_id  = var.kms_secrets_arn

  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = merge(var.common_tags, {
    Name    = "${var.project}-secret-defectdojo-admin"
    Service = "defectdojo"
  })
}

resource "aws_secretsmanager_secret_version" "defectdojo_admin" {
  secret_id = aws_secretsmanager_secret.defectdojo_admin.id
  secret_string = jsonencode({
    username = "admin"
    password = random_password.defectdojo_admin.result
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# -----------------------------------------------------------
# EC2 Instance — DefectDojo
# -----------------------------------------------------------
resource "aws_instance" "defectdojo" {
  ami                    = data.aws_ami.ubuntu_22.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.sg_id]
  iam_instance_profile   = var.instance_profile

  associate_public_ip_address = false
  key_name                    = null

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted              = true
    kms_key_id             = var.kms_key_arn
    delete_on_termination  = true

    tags = merge(var.common_tags, {
      Name = "${var.project}-ebs-defectdojo-os-${var.environment}"
    })
  }

  # Volumen datos: media files DefectDojo + SBOMs archivados
  ebs_block_device {
    device_name           = "/dev/sdb"
    volume_type            = "gp3"
    volume_size             = 50
    encrypted               = true
    kms_key_id              = var.kms_key_arn
    delete_on_termination   = false
    iops                    = 3000
    throughput              = 125

    tags = merge(var.common_tags, {
      Name    = "${var.project}-ebs-defectdojo-data-${var.environment}"
      Service = "defectdojo"
    })
  }

  user_data = base64encode(templatefile(
    "${path.module}/templates/defectdojo-install.sh.tpl",
    {
      project             = var.project
      environment         = var.environment
      region              = local.region
      db_secret_arn       = var.db_secret_arn
      admin_secret_arn    = aws_secretsmanager_secret.defectdojo_admin.arn
      api_key_secret_arn  = aws_secretsmanager_secret.defectdojo_api_key.arn
      s3_reports_bucket   = var.s3_bucket_id
      defectdojo_version  = var.defectdojo_version
      db_host             = var.db_endpoint.host
      db_port             = var.db_endpoint.port
      db_name             = var.db_endpoint.dbname
    }
  ))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring = true

  tags = merge(var.common_tags, {
    Name     = "${var.project}-defectdojo-${var.environment}"
    Service  = "defectdojo"
    Schedule = "business-hours"
  })

  lifecycle {
    # Ignorar cambios de AMI y user_data_base64 para no recrear la instancia
    # cuando AWS publique nueva AMI o se modifique el script de instalación
    # (los cambios de configuración se gestionan vía SSM, no recreando la instancia)
    ignore_changes = [ami, user_data_base64]
  }

  depends_on = [
    aws_secretsmanager_secret_version.defectdojo_admin,
    aws_secretsmanager_secret_version.defectdojo_api_key
  ]
}

# -----------------------------------------------------------
# ALB Target Group Attachment
# -----------------------------------------------------------
resource "aws_lb_target_group_attachment" "defectdojo" {
  target_group_arn = var.tg_arn
  target_id        = aws_instance.defectdojo.id
  port             = 8080
}

# -----------------------------------------------------------
# EBS Snapshots — 7 días retención
# -----------------------------------------------------------
resource "aws_dlm_lifecycle_policy" "defectdojo_ebs" {
  description        = "${var.project} DefectDojo EBS snapshots"
  execution_role_arn = var.dlm_role_arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "daily-7d"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["02:00"]
      }

      retain_rule {
        count = 7
      }

      copy_tags = true
    }

    target_tags = {
      Service = "defectdojo"
    }
  }

  tags = var.common_tags
}

# -----------------------------------------------------------
# Scheduler apagado/encendido dev
# Horario laboral España: 08:00–20:00 CET (L-V)
# -----------------------------------------------------------
resource "aws_scheduler_schedule" "defectdojo_stop" {
  count = var.environment == "dev" ? 1 : 0

  name                         = "${var.project}-defectdojo-stop-${var.environment}"
  schedule_expression          = "cron(0 19 ? * MON-FRI *)"
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 15
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:ec2:stopInstances"
    role_arn = var.scheduler_role_arn

    input = jsonencode({
      InstanceIds = [aws_instance.defectdojo.id]
    })
  }
}

resource "aws_scheduler_schedule" "defectdojo_start" {
  count = var.environment == "dev" ? 1 : 0

  name                         = "${var.project}-defectdojo-start-${var.environment}"
  schedule_expression          = "cron(0 7 ? * MON-FRI *)"
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:ec2:startInstances"
    role_arn = var.scheduler_role_arn

    input = jsonencode({
      InstanceIds = [aws_instance.defectdojo.id]
    })
  }
}

# -----------------------------------------------------------
# SSM Parameters — URLs internas para otros módulos
# -----------------------------------------------------------
resource "aws_ssm_parameter" "defectdojo_url" {
  name        = "/${var.project}/${var.environment}/defectdojo/internal-url"
  description = "URL interna DefectDojo API"
  type        = "String"
  value       = "http://${aws_instance.defectdojo.private_ip}:8080"
  tags        = var.common_tags
}
