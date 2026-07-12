# ============================================================
# localstack.override.tf
# Override SOLO de los endpoints del provider AWS existente.
# Terraform permite override de bloques con archivos _override.tf
# — el nombre del archivo DEBE terminar en _override.tf para que
# Terraform lo trate como override (fusiona con el provider base
# en vez de duplicarlo).
#
# Este archivo se copia como "localstack_override.tf" al directorio
# del entorno durante plan-only.sh y se elimina al terminar.
# NO commitear — está en .gitignore
# ============================================================

# Constraints exigidos por TFLint; en un fichero *_override.tf estos
# bloques se FUSIONAN con los del root module (mismos valores → no-op).
terraform {
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

provider "aws" {
  # Credenciales ficticias para LocalStack
  access_key = "test"
  secret_key = "test"

  # Desactivar validaciones que requieren AWS real
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  # LocalStack: forzar path-style para S3
  s3_use_path_style = true

  endpoints {
    acm            = "http://localhost:4566"
    apigateway     = "http://localhost:4566"
    cloudwatch     = "http://localhost:4566"
    cloudwatchlogs = "http://localhost:4566"
    cloudtrail     = "http://localhost:4566"
    config         = "http://localhost:4566"
    dlm            = "http://localhost:4566"
    dynamodb       = "http://localhost:4566"
    ec2            = "http://localhost:4566"
    elbv2          = "http://localhost:4566"
    events         = "http://localhost:4566"
    guardduty      = "http://localhost:4566"
    iam            = "http://localhost:4566"
    kms            = "http://localhost:4566"
    lambda         = "http://localhost:4566"
    rds            = "http://localhost:4566"
    s3             = "http://localhost:4566"
    scheduler      = "http://localhost:4566"
    secretsmanager = "http://localhost:4566"
    sns            = "http://localhost:4566"
    ssm            = "http://localhost:4566"
    wafv2          = "http://localhost:4566"
  }
}
