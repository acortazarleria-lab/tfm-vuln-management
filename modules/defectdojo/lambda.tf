# ============================================================
# modules/defectdojo/lambda.tf
# Infraestructura Lambda: enrichment + webhook
# Well-Architected: Security – enriquecimiento automatizado
# ISO 27001: A.12.6 gestión vulnerabilidades, A.16.1.2 notificación
# ============================================================

# -----------------------------------------------------------
# Lambda Enrichment — enriquece findings con EPSS/KEV/SLA
# -----------------------------------------------------------
data "archive_file" "enrichment" {
  type        = "zip"
  output_path = "${path.module}/lambda/enrichment.zip"
  source_dir  = "${path.module}/lambda/enrichment/"
}

resource "aws_lambda_function" "enrichment" {
  filename         = data.archive_file.enrichment.output_path
  function_name    = "${var.project}-finding-enrichment-${var.environment}"
  role             = var.lambda_role_arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 512
  source_code_hash = data.archive_file.enrichment.output_base64sha256

  environment {
    variables = {
      DD_SECRET_ARN = aws_secretsmanager_secret.defectdojo_api_key.arn
      CW_NAMESPACE  = "VulnMgmt/DefectDojo"
      PROJECT       = var.project
      ENVIRONMENT   = var.environment
    }
  }

  vpc_config {
    subnet_ids         = [var.subnet_id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  layers = [aws_lambda_layer_version.python_deps.arn]

  tags = merge(var.common_tags, { Service = "enrichment" })
}

resource "aws_cloudwatch_event_rule" "enrichment_schedule" {
  name                = "${var.project}-enrichment-schedule-${var.environment}"
  description         = "Enriquecer findings DefectDojo cada 30 minutos"
  schedule_expression = "rate(30 minutes)"
  tags                = var.common_tags
}

resource "aws_cloudwatch_event_target" "enrichment" {
  rule      = aws_cloudwatch_event_rule.enrichment_schedule.name
  target_id = "FindingEnrichment"
  arn       = aws_lambda_function.enrichment.arn
}

resource "aws_lambda_permission" "enrichment_eventbridge" {
  statement_id  = "AllowEventBridgeEnrichment"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enrichment.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.enrichment_schedule.arn
}

# -----------------------------------------------------------
# Lambda Métricas — publica métricas DefectDojo en CloudWatch
# -----------------------------------------------------------
data "archive_file" "metrics" {
  type        = "zip"
  output_path = "${path.module}/lambda/metrics.zip"
  source_dir  = "${path.module}/lambda/metrics/"
}

resource "aws_lambda_function" "metrics" {
  filename         = data.archive_file.metrics.output_path
  function_name    = "${var.project}-defectdojo-metrics-${var.environment}"
  role             = var.lambda_role_arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  source_code_hash = data.archive_file.metrics.output_base64sha256

  environment {
    variables = {
      DD_SECRET_ARN = aws_secretsmanager_secret.defectdojo_api_key.arn
      DD_BASE_URL   = "http://${aws_instance.defectdojo.private_ip}:8080"
      CW_NAMESPACE  = "VulnMgmt/DefectDojo"
      ENVIRONMENT   = var.environment
      PROJECT       = var.project
    }
  }

  vpc_config {
    subnet_ids         = [var.subnet_id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  layers = [aws_lambda_layer_version.python_deps.arn]

  tags = merge(var.common_tags, { Service = "monitoring" })
}

resource "aws_cloudwatch_event_rule" "metrics_schedule" {
  name                = "${var.project}-metrics-schedule-${var.environment}"
  description         = "Publicar métricas DefectDojo en CloudWatch cada hora"
  schedule_expression = "rate(1 hour)"
  tags                = var.common_tags
}

resource "aws_cloudwatch_event_target" "metrics_lambda" {
  rule      = aws_cloudwatch_event_rule.metrics_schedule.name
  target_id = "DefectDojoMetrics"
  arn       = aws_lambda_function.metrics.arn
}

resource "aws_lambda_permission" "metrics_eventbridge" {
  statement_id  = "AllowEventBridgeMetrics"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.metrics.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.metrics_schedule.arn
}

# -----------------------------------------------------------
# Lambda Webhook — recibe notificaciones de DefectDojo
# -----------------------------------------------------------
data "archive_file" "webhook" {
  type        = "zip"
  output_path = "${path.module}/lambda/webhook.zip"
  source_dir  = "${path.module}/lambda/webhook/"
}

resource "aws_lambda_function" "webhook" {
  filename         = data.archive_file.webhook.output_path
  function_name    = "${var.project}-webhook-receiver-${var.environment}"
  role             = var.lambda_role_arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  source_code_hash = data.archive_file.webhook.output_base64sha256

  environment {
    variables = {
      SNS_ALERTS_ARN = var.sns_alerts_arn
      CW_NAMESPACE   = "VulnMgmt/DefectDojo"
      WEBHOOK_SECRET = ""
      DEFECTDOJO_URL = "https://defectdojo.${var.internal_domain}"
      PROJECT        = var.project
      ENVIRONMENT    = var.environment
    }
  }

  vpc_config {
    subnet_ids         = [var.subnet_id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  tags = merge(var.common_tags, { Service = "webhook" })
}

# API Gateway privado para recibir webhooks de DefectDojo
resource "aws_api_gateway_rest_api" "webhook" {
  name        = "${var.project}-webhook-${var.environment}"
  description = "Receptor webhooks DefectDojo"

  endpoint_configuration {
    types            = ["PRIVATE"]
    # VPC Endpoint requerido para API Gateway PRIVATE
    vpc_endpoint_ids = [aws_vpc_endpoint.execute_api.id]
  }

  tags = var.common_tags
}

# Resource Policy — requerida para API Gateway PRIVATE:
# sin ella el endpoint es inaccesible incluso desde dentro de la VPC
resource "aws_api_gateway_rest_api_policy" "webhook" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.webhook.execution_arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = var.vpc_id
          }
        }
      }
    ]
  })
}

# VPC Endpoint para execute-api — requerido por API Gateway PRIVATE
# Sin este endpoint, el API Gateway no es enrutable desde dentro de la VPC
resource "aws_vpc_endpoint" "execute_api" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${local.region}.execute-api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [var.subnet_id]
  security_group_ids  = [aws_security_group.lambda.id]
  private_dns_enabled = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-vpce-execute-api-${var.environment}"
  })
}

resource "aws_api_gateway_resource" "webhook" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id
  parent_id   = aws_api_gateway_rest_api.webhook.root_resource_id
  path_part   = "webhook"
}

resource "aws_api_gateway_method" "webhook_post" {
  rest_api_id   = aws_api_gateway_rest_api.webhook.id
  resource_id   = aws_api_gateway_resource.webhook.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "webhook_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.webhook.id
  resource_id             = aws_api_gateway_resource.webhook.id
  http_method             = aws_api_gateway_method.webhook_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.webhook.invoke_arn
}

resource "aws_api_gateway_deployment" "webhook" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id
  depends_on  = [aws_api_gateway_integration.webhook_lambda]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "webhook" {
  deployment_id = aws_api_gateway_deployment.webhook.id
  rest_api_id   = aws_api_gateway_rest_api.webhook.id
  stage_name    = var.environment

  tags = var.common_tags
}

resource "aws_lambda_permission" "webhook_apigw" {
  statement_id  = "AllowAPIGatewayWebhook"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.webhook.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.webhook.execution_arn}/*/*"
}

# -----------------------------------------------------------
# SG Lambda — solo salida hacia DefectDojo y APIs externas
# -----------------------------------------------------------
resource "aws_security_group" "lambda" {
  name        = "${var.project}-sg-lambda-${var.environment}"
  description = "SG Lambdas integración DefectDojo"
  vpc_id      = var.vpc_id

  egress {
    description = "Hacia DefectDojo (mismo SG compute)"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.private_compute_cidr]
  }

  egress {
    description = "HTTPS hacia APIs externas via VPC Endpoint / Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-sg-lambda-${var.environment}"
  })
}

# -----------------------------------------------------------
# Layer Python con dependencias (requests + boto3)
# El zip debe construirse antes del apply:
#   pip install requests -t lambda/layer/python/ --platform manylinux2014_x86_64 \
#     --only-binary=:all: --python-version 3.12
#   cd lambda/layer && zip -r python-deps.zip python/
# -----------------------------------------------------------
resource "aws_lambda_layer_version" "python_deps" {
  layer_name          = "${var.project}-python-deps-${var.environment}"
  description         = "requests + boto3 para Lambdas integración"
  compatible_runtimes = ["python3.12"]
  filename            = "${path.module}/lambda/layer/python-deps.zip"

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------
# SSM: URL del webhook para configurar en DefectDojo
# -----------------------------------------------------------
resource "aws_ssm_parameter" "webhook_url" {
  name        = "/${var.project}/${var.environment}/webhook/url"
  description = "URL API Gateway webhook para configurar en DefectDojo"
  type        = "String"
  value       = "${aws_api_gateway_stage.webhook.invoke_url}/webhook"
  tags        = var.common_tags
}
