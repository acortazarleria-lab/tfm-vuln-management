# ============================================================
# environments/prod/backend.tf
# Estado remoto en S3 + locking con DynamoDB
# ISO 27001: A.12.1.2 — gestión de cambios controlada
# Recursos creados previamente por scripts/bootstrap-backend.sh
# ============================================================

terraform {
  backend "s3" {
    bucket         = "vuln-mgmt-tfstate-prod"
    key            = "prod/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state"
    dynamodb_table = "vuln-mgmt-tfstate-lock"
  }
}
