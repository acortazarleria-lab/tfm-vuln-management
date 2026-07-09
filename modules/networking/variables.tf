# ============================================================
# modules/networking/variables.tf
# ============================================================

variable "project" {
  type = string
}

variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "public_subnet_cidr" {
  type = string
}

variable "public_subnet_cidr_b" {
  description = "CIDR segunda subnet pública (AZ-b) — requerida por ALB (min 2 AZs)"
  type        = string
  default     = "10.0.6.0/24"
}

variable "private_compute_cidr" {
  type = string
}

variable "private_data_cidr" {
  type = string
}

variable "private_data_cidr_b" {
  description = "CIDR segunda subnet datos (AZ-b) — requerida por RDS subnet group (min 2 AZs)"
  type        = string
  default     = "10.0.5.0/24"
}

variable "private_lambda_cidr" {
  type = string
}

variable "internal_domain" {
  description = "Dominio interno corporativo (ej: empresa.internal)"
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN del certificado corporativo importado en ACM"
  type        = string
}

variable "kms_cloudwatch_arn" {
  description = "ARN CMK para cifrar VPC Flow Logs en CloudWatch"
  type        = string
}

variable "alb_logs_bucket_id" {
  description = "Bucket S3 destino de los access logs del ALB"
  type        = string
}

variable "waf_logs_bucket_arn" {
  description = "ARN del bucket S3 destino de los logs del WAF"
  type        = string
}

variable "common_tags" {
  type = map(string)
}

variable "flow_logs_retention_days" {
  type    = number
  default = 90
}
