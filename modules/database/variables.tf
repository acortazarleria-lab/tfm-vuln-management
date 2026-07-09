# ============================================================
# modules/database/variables.tf
# ============================================================

variable "project" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "private_compute_cidr" {
  type = string
}

variable "kms_rds_arn" {
  type = string
}

variable "kms_secrets_arn" {
  type = string
}

variable "sg_defectdojo_id" {
  type = string
}

variable "rds_monitoring_role_arn" {
  description = "ARN del role IAM para Enhanced Monitoring (creado en módulo security)"
  type        = string
}

variable "common_tags" {
  type = map(string)
}

variable "instance_class" {
  type        = string
  default     = "db.t3.micro"
  description = "Instancia RDS. Escalar a db.t3.small si >50 conexiones concurrentes"
}

variable "backup_retention_days" {
  type        = number
  default     = 30
  description = "Retención backups RDS. ISO 27001 A.12.3.1 mínimo 30 días"

  validation {
    condition     = var.backup_retention_days >= 30
    error_message = "Mínimo 30 días para cumplimiento ISO 27001."
  }
}
