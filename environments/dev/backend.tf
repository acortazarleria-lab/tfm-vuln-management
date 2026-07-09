# ============================================================
# environments/dev/backend.tf
# Estado remoto en S3 + locking con DynamoDB — entorno dev
# Bucket y tabla independientes de prod (aislamiento de estado)
# ISO 27001: A.12.1.2 — gestión de cambios controlada
# Recursos creados previamente por scripts/bootstrap-backend.sh dev
# ============================================================

terraform {
  backend "s3" {
    bucket         = "vuln-mgmt-tfstate-dev"
    key            = "dev/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state"
    dynamodb_table = "vuln-mgmt-tfstate-lock"
  }
}
