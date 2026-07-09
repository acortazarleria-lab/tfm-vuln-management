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

variable "retention" {
  type = object({
    hot_days     = number
    glacier_days = number
    backup_days  = number
  })
  default = {
    hot_days     = 90
    glacier_days = 365
    backup_days  = 30
  }
}
