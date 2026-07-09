# ============================================================
# modules/security/variables.tf
# ============================================================

variable "project" {
  description = "Nombre del proyecto"
  type        = string
}

variable "environment" {
  description = "Entorno (dev|prod)"
  type        = string
}

variable "aws_region" {
  description = "Región AWS"
  type        = string
}

variable "common_tags" {
  description = "Tags comunes aplicados a todos los recursos"
  type        = map(string)
}

variable "alarm_email" {
  description = "Email destino de alertas SNS"
  type        = string
}

