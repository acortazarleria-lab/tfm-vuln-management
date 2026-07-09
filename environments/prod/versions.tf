# ============================================================
# versions.tf
# Providers + constraints de versiones
# Política: versiones pinadas → reproducibilidad garantizada
# Well-Architected: Operational Excellence – IaC versionado
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
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      Owner       = var.owner
      CostCenter  = var.cost_center
      Compliance  = "ISO27001-GDPR"
      ManagedBy   = "terraform"
    }
  }
}
