# ============================================================
# modules/defectdojo/variables.tf
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

variable "subnet_id" {
  type = string
}

variable "sg_id" {
  type = string
}

variable "tg_arn" {
  type = string
}

variable "kms_key_arn" {
  description = "CMK para cifrado EBS"
  type        = string
}

variable "kms_secrets_arn" {
  description = "CMK para cifrado Secrets Manager"
  type        = string
}

variable "instance_profile" {
  type = string
}

variable "s3_bucket_id" {
  description = "Bucket S3 de reports (módulo storage)"
  type        = string
}

variable "db_secret_arn" {
  type = string
}

variable "db_endpoint" {
  type = object({
    host   = string
    port   = number
    dbname = string
  })
}

variable "dlm_role_arn" {
  description = "ARN role IAM para Data Lifecycle Manager (snapshots EBS)"
  type        = string
}

variable "scheduler_role_arn" {
  type = string
}

variable "lambda_role_arn" {
  description = "ARN role IAM para las Lambdas de integración"
  type        = string
}

variable "sns_alerts_arn" {
  description = "ARN del topic SNS de alertas (módulo monitoring)"
  type        = string
}

variable "private_compute_cidr" {
  type = string
}

variable "internal_domain" {
  type = string
}

variable "common_tags" {
  type = map(string)
}

variable "instance_type" {
  type        = string
  default     = "t3.small"
  description = "t3.small: 2 vCPU, 2GB RAM. Suficiente con PostgreSQL en RDS externo"
}

variable "defectdojo_version" {
  type    = string
  default = "2.38.0"
}
