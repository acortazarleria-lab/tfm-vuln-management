# ============================================================
# modules/networking/vpc.tf
# VPC + subnets por capa + Flow Logs + VPC Endpoints
# Well-Architected: Security – red privada sin exposición
# ISO 27001: A.13.1.1 controles de red, A.13.1.3 segregación
# Sin NAT Gateway → VPC Endpoints cubren tráfico AWS
# ============================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# -----------------------------------------------------------
# VPC principal
# -----------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpc-${var.environment}"
  })
}

# -----------------------------------------------------------
# Subnets — 4 capas de segmentación
# Single-AZ (eu-west-1a) → decisión coste/HA documentada
# ISO 27001: A.13.1.3 — segregación en redes
# -----------------------------------------------------------

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = merge(var.common_tags, {
    Name = "${var.project}-subnet-public-${var.environment}"
    Tier = "public"
  })
}

resource "aws_subnet" "private_compute" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_compute_cidr
  availability_zone = "${var.aws_region}a"

  tags = merge(var.common_tags, {
    Name = "${var.project}-subnet-compute-${var.environment}"
    Tier = "private-compute"
  })
}

resource "aws_subnet" "private_data" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_data_cidr
  availability_zone = "${var.aws_region}a"

  tags = merge(var.common_tags, {
    Name = "${var.project}-subnet-data-${var.environment}"
    Tier = "private-data"
  })
}

# Segunda subnet de datos en AZ-b — requerida por AWS para el RDS DB Subnet Group
# (mínimo 2 AZs distintas). No se despliega RDS en esta AZ (single-AZ),
# solo satisface el requisito estructural del servicio.
resource "aws_subnet" "private_data_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_data_cidr_b # 10.0.5.0/24
  availability_zone = "${var.aws_region}b"

  tags = merge(var.common_tags, {
    Name = "${var.project}-subnet-data-b-${var.environment}"
    Tier = "private-data-standby"
  })
}

resource "aws_route_table_association" "private_data_b" {
  subnet_id      = aws_subnet.private_data_b.id
  route_table_id = aws_route_table.private_data.id
}

resource "aws_subnet" "private_lambda" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_lambda_cidr
  availability_zone = "${var.aws_region}a"

  tags = merge(var.common_tags, {
    Name = "${var.project}-subnet-lambda-${var.environment}"
    Tier = "private-lambda"
  })
}

# -----------------------------------------------------------
# Route Tables
# -----------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags = merge(var.common_tags, {
    Name = "${var.project}-rt-public-${var.environment}"
  })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private_compute" {
  vpc_id = aws_vpc.main.id
  tags = merge(var.common_tags, {
    Name = "${var.project}-rt-compute-${var.environment}"
  })
}

resource "aws_route_table_association" "private_compute" {
  subnet_id      = aws_subnet.private_compute.id
  route_table_id = aws_route_table.private_compute.id
}

resource "aws_route_table" "private_data" {
  vpc_id = aws_vpc.main.id
  tags = merge(var.common_tags, {
    Name = "${var.project}-rt-data-${var.environment}"
  })
}

resource "aws_route_table_association" "private_data" {
  subnet_id      = aws_subnet.private_data.id
  route_table_id = aws_route_table.private_data.id
}

resource "aws_route_table" "private_lambda" {
  vpc_id = aws_vpc.main.id
  tags = merge(var.common_tags, {
    Name = "${var.project}-rt-lambda-${var.environment}"
  })
}

resource "aws_route_table_association" "private_lambda" {
  subnet_id      = aws_subnet.private_lambda.id
  route_table_id = aws_route_table.private_lambda.id
}

# -----------------------------------------------------------
# VPC Flow Logs → CloudWatch
# GDPR: trazabilidad de accesos a red
# ISO 27001: A.12.4.1 — registro de eventos
# -----------------------------------------------------------
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flow-logs/${var.project}-${var.environment}"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = var.kms_cloudwatch_arn

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpc-flow-logs"
  })
}

data "aws_iam_policy_document" "vpc_flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vpc_flow_logs" {
  name               = "${var.project}-role-vpc-flow-logs-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.vpc_flow_logs_assume.json
  tags               = var.common_tags
}

data "aws_iam_policy_document" "vpc_flow_logs_policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = [
      "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name   = "${var.project}-policy-vpc-flow-logs-${var.environment}"
  role   = aws_iam_role.vpc_flow_logs.id
  policy = data.aws_iam_policy_document.vpc_flow_logs_policy.json
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"

  tags = merge(var.common_tags, {
    Name = "${var.project}-flow-log-${var.environment}"
  })
}

# -----------------------------------------------------------
# VPC Endpoints — tráfico AWS sin salir de la red privada
# Elimina necesidad de NAT Gateway → ahorro ~$32/mes
# ISO 27001: A.13.2.1 — políticas de transferencia información
# -----------------------------------------------------------

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project}-sg-vpc-endpoints-${var.environment}"
  description = "SG VPC Endpoints: acepta HTTPS desde subnets privadas"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS desde subnets privadas"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      var.private_compute_cidr,
      var.private_data_cidr,
      var.private_lambda_cidr
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-sg-endpoints-${var.environment}"
  })
}

data "aws_iam_policy_document" "endpoint_policy_base" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# S3 — tipo Gateway (gratuito)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  policy            = data.aws_iam_policy_document.endpoint_policy_base.json

  route_table_ids = [
    aws_route_table.private_compute.id,
    aws_route_table.private_data.id,
    aws_route_table.private_lambda.id
  ]

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-s3-${var.environment}"
  })
}

# SSM — acceso sin SSH expuesto
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_compute.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.endpoint_policy_base.json

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-ssm-${var.environment}"
  })
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_compute.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-ssmmessages-${var.environment}"
  })
}

resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_compute.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-ec2messages-${var.environment}"
  })
}

resource "aws_vpc_endpoint" "cloudwatch_logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_compute.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-logs-${var.environment}"
  })
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_compute.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-secretsmanager-${var.environment}"
  })
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_compute.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-kms-${var.environment}"
  })
}

# -----------------------------------------------------------
# Network ACLs — capa adicional sobre Security Groups
# SGs son stateful; NACLs son stateless → defensa en profundidad
# ISO 27001: A.13.1.1 — controles de red
# -----------------------------------------------------------

resource "aws_network_acl" "private_compute" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.private_compute.id]

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 443
    to_port    = 443
  }

  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 8080
    to_port    = 8080
  }

  ingress {
    rule_no    = 900
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  ingress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 65535
  }

  egress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-nacl-compute-${var.environment}"
  })
}

resource "aws_network_acl" "private_data" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.private_data.id]

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.private_compute_cidr
    from_port  = 5432
    to_port    = 5432
  }

  ingress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.private_lambda_cidr
    from_port  = 5432
    to_port    = 5432
  }

  ingress {
    rule_no    = 900
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  ingress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-nacl-data-${var.environment}"
  })
}
