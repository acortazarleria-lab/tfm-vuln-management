# ============================================================
# modules/storage/variables.tf
# ============================================================

variable "project" {
  type = string
}

variable "environment" {
  type = string
}

variable "kms_s3_arn" {
  type = string
}

variable "defectdojo_role_arn" {
  type = string
}

variable "common_tags" {
  type = map(string)
}
