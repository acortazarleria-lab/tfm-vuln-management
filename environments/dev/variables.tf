# ============================================================
# variables.tf (raíz)
# Variables globales compartidas entre todos los entornos
# ============================================================

variable "project" {
  description = "Nombre del proyecto — usado como prefijo en todos los recursos"
  type        = string
  default     = "vuln-mgmt"
}

variable "environment" {
  description = "Entorno de despliegue (dev|prod)"
  type        = string

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "El entorno debe ser 'dev' o 'prod'."
  }
}

variable "aws_region" {
  description = "Región AWS de despliegue"
  type        = string
  default     = "eu-west-1"
}

variable "owner" {
  description = "Equipo propietario del recurso (tag obligatorio)"
  type        = string
  default     = "equipo-seguridad"
}

variable "cost_center" {
  description = "Centro de coste (tag obligatorio)"
  type        = string
  default     = "IT-SEC-001"
}

variable "internal_domain" {
  description = "Dominio interno corporativo (ej: empresa.internal)"
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN del certificado corporativo importado en ACM"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:acm:", var.acm_certificate_arn))
    error_message = "Debe ser un ARN de ACM válido."
  }
}

variable "alarm_email" {
  description = "Email destino de alertas CloudWatch/SNS"
  type        = string
}
