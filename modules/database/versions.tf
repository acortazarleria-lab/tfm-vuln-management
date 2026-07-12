# ============================================================
# versions.tf
# Constraints de versión del módulo (exigido por TFLint:
# terraform_required_version / terraform_required_providers).
# Los root modules (environments/*) pinan las versiones exactas.
# ============================================================

terraform {
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}
