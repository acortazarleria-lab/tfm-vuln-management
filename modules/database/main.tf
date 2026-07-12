# ============================================================
# modules/database/main.tf
# RDS PostgreSQL 16 — cifrado KMS + Secrets Manager
# Well-Architected: Security + Reliability pillars
# ISO 27001: A.10.1.1 cifrado, A.12.3.1 backup información
#
# SCOPE REDUCIDO: una instancia, una base de datos (defectdojo)
# ============================================================

# -----------------------------------------------------------
# Subnet Group — RDS solo en subnet privada datos
# -----------------------------------------------------------
resource "aws_db_subnet_group" "main" {
  name        = "${var.project}-dbsg-${var.environment}"
  description = "Subnet group RDS: subnet privada datos únicamente"
  subnet_ids  = var.subnet_ids

  tags = merge(var.common_tags, {
    Name = "${var.project}-dbsg-${var.environment}"
  })
}

# -----------------------------------------------------------
# Parameter Group hardened — PostgreSQL 16
# ISO 27001: A.14.2.5 — principios ingeniería sistemas seguros
# -----------------------------------------------------------
resource "aws_db_parameter_group" "postgres" {
  name        = "${var.project}-pg-postgres16-${var.environment}"
  family      = "postgres16"
  description = "Parameter group hardened ISO27001/GDPR"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_connections"
    value        = "1"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_disconnections"
    value        = "1"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_min_duration_statement"
    value        = "1000"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_statement"
    value        = "ddl"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_duration"
    value        = "0"
    apply_method = "immediate"
  }

  parameter {
    name         = "timezone"
    value        = "Europe/Madrid"
    apply_method = "immediate"
  }

  parameter {
    name         = "max_connections"
    value        = "100"
    apply_method = "pending-reboot"
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-pg-${var.environment}"
  })
}

# -----------------------------------------------------------
# Security Group RDS — least privilege
# -----------------------------------------------------------
resource "aws_security_group" "rds" {
  name        = "${var.project}-sg-rds-${var.environment}"
  description = "SG RDS: solo DefectDojo en subnet compute"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL desde DefectDojo"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.sg_defectdojo_id]
  }

  egress {
    description = "Respuestas TCP hacia subnet compute"
    from_port   = 1024
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.private_compute_cidr]
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-sg-rds-${var.environment}"
  })
}

# -----------------------------------------------------------
# Secrets Manager — credenciales master RDS
# ISO 27001: A.9.4.3 — gestión contraseñas sistemas
# -----------------------------------------------------------
resource "random_password" "db_master" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}|;:,.<>?"
}

resource "aws_secretsmanager_secret" "db_master" {
  name        = "${var.project}/rds/master-credentials"
  description = "Credenciales master RDS PostgreSQL"
  kms_key_id  = var.kms_secrets_arn

  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = merge(var.common_tags, {
    Name    = "${var.project}-secret-rds-master"
    Service = "rds"
  })
}

resource "aws_secretsmanager_secret_version" "db_master" {
  secret_id = aws_secretsmanager_secret.db_master.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = random_password.db_master.result
    engine   = "postgres"
    port     = 5432
    dbname   = "postgres"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Secret específico para DefectDojo
resource "random_password" "defectdojo_db" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}|;:,.<>?"
}

resource "aws_secretsmanager_secret" "defectdojo_db" {
  name        = "${var.project}/defectdojo/db-credentials"
  description = "Credenciales DB DefectDojo"
  kms_key_id  = var.kms_secrets_arn

  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = merge(var.common_tags, {
    Name    = "${var.project}-secret-defectdojo-db"
    Service = "defectdojo"
  })
}

resource "aws_secretsmanager_secret_version" "defectdojo_db" {
  secret_id = aws_secretsmanager_secret.defectdojo_db.id
  secret_string = jsonencode({
    username = "defectdojo"
    password = random_password.defectdojo_db.result
    engine   = "postgres"
    host     = aws_db_instance.main.address
    port     = 5432
    dbname   = "defectdojo"
    # jdbc_url construido sin interpolación directa para evitar problemas de escapado
    jdbc_url = "jdbc:postgresql://${aws_db_instance.main.address}:5432/defectdojo?ssl=true&sslmode=require"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# random_id para el sufijo del snapshot final (evitar formatdate+timestamp que causa
# diff en cada plan porque timestamp() se evalúa en plan-time)
resource "random_id" "snapshot_suffix" {
  byte_length = 4
}

# -----------------------------------------------------------
# RDS Instance — PostgreSQL 16
# -----------------------------------------------------------
resource "aws_db_instance" "main" {
  identifier = "${var.project}-rds-${var.environment}"

  engine         = "postgres"
  engine_version = "16.3"
  instance_class = var.instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_rds_arn

  username = jsondecode(aws_secretsmanager_secret_version.db_master.secret_string)["username"]
  password = jsondecode(aws_secretsmanager_secret_version.db_master.secret_string)["password"]

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  port                   = 5432

  parameter_group_name = aws_db_parameter_group.postgres.name

  backup_retention_period = var.backup_retention_days
  backup_window           = "02:00-03:00"
  maintenance_window      = "sun:03:00-sun:04:00"

  skip_final_snapshot = false
  # Sufijo estable: random_id no cambia entre plans (evita diff perpetuo)
  final_snapshot_identifier = "${var.project}-rds-final-${var.environment}-${random_id.snapshot_suffix.hex}"
  delete_automated_backups  = false

  monitoring_interval = 60
  monitoring_role_arn = var.rds_monitoring_role_arn

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_rds_arn
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = [
    "postgresql",
    "upgrade"
  ]

  deletion_protection = var.environment == "prod" ? true : false

  auto_minor_version_upgrade = true
  apply_immediately          = false

  tags = merge(var.common_tags, {
    Name    = "${var.project}-rds-${var.environment}"
    Service = "database"
  })
}

# -----------------------------------------------------------
# Recordatorio: inicialización DB
# Ejecutar scripts/db-init.sql vía SSM Run Command tras el
# primer apply (ver scripts/db-init.sql)
# -----------------------------------------------------------
resource "null_resource" "db_init_reminder" {
  depends_on = [
    aws_db_instance.main,
    aws_secretsmanager_secret_version.defectdojo_db
  ]

  triggers = {
    rds_id = aws_db_instance.main.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      echo "AVISO: ejecutar manualmente scripts/db-init.sql"
      echo "mediante SSM Run Command en la instancia DefectDojo."
      echo "RDS Endpoint: ${aws_db_instance.main.address}"
    EOT
  }
}
