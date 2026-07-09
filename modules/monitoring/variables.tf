# ============================================================
# modules/monitoring/variables.tf
# ============================================================

variable "project" {
  type = string
}

variable "environment" {
  type = string
}

variable "alb_arn_suffix" {
  type = string
}

variable "waf_web_acl_name" {
  type = string
}

variable "defectdojo_instance_id" {
  type = string
}

variable "rds_identifier" {
  type = string
}

variable "s3_logs_bucket" {
  type = string
}

variable "kms_cloudwatch_arn" {
  type = string
}

variable "sns_alerts_arn" {
  description = "ARN del topic SNS de alertas, creado en el módulo security"
  type        = string
}

variable "config_role_arn" {
  description = "ARN del role IAM para AWS Config (módulo security)"
  type        = string
}

variable "lambda_integration_role_arn" {
  description = "ARN del role IAM de las Lambdas de integración (módulo security)"
  type        = string
}

variable "common_tags" {
  type = map(string)
}

variable "retention_days" {
  type    = number
  default = 90
}
