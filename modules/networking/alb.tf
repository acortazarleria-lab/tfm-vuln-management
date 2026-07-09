# ============================================================
# modules/networking/alb.tf
# ALB interno + TLS 1.3 + WAF + routing → DefectDojo
# Well-Architected: Security Pillar
# ISO 27001: A.13.1.3, A.10.1.1, A.12.6.1
# ============================================================

# Segunda subnet pública en AZ-b — requerida por ALB (min 2 AZs)
resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr_b
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false

  tags = merge(var.common_tags, {
    Name = "${var.project}-subnet-public-b-${var.environment}"
    Tier = "public-standby"
  })
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# -----------------------------------------------------------
# WAF Web ACL
# FIX: override_action { none {} } no es sintaxis HCL válida.
#      Los bloques anidados vacíos deben ir en líneas separadas.
# -----------------------------------------------------------
resource "aws_wafv2_web_acl" "main" {
  name        = "${var.project}-waf-${var.environment}"
  description = "WAF ALB interno – OWASP CRS + rate limit"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Regla 1: IP Reputation
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 5

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPReputation"
      sampled_requests_enabled   = true
    }
  }

  # Regla 2: OWASP Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Regla 3: SQL Injection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Regla 4: Rate limiting
  rule {
    name     = "RateLimitPerIP"
    priority = 30

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-waf"
    sampled_requests_enabled   = true
  }

  tags = var.common_tags
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  log_destination_configs = [var.waf_logs_bucket_arn]
  resource_arn            = aws_wafv2_web_acl.main.arn

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

# -----------------------------------------------------------
# ALB — scheme internal
# ISO 27001: A.13.1.3 — segregación en redes
# -----------------------------------------------------------
resource "aws_lb" "main" {
  name               = "${var.project}-alb-${var.environment}"
  internal           = true
  load_balancer_type = "application"

  security_groups = [aws_security_group.alb.id]
  subnets         = [aws_subnet.public.id, aws_subnet.public_b.id]

  enable_deletion_protection = var.environment == "prod" ? true : false

  access_logs {
    bucket  = var.alb_logs_bucket_id
    prefix  = "alb"
    enabled = true
  }

  drop_invalid_header_fields = true

  tags = merge(var.common_tags, {
    Name = "${var.project}-alb-${var.environment}"
  })
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# -----------------------------------------------------------
# Listener HTTPS:443 — TLS 1.3
# -----------------------------------------------------------
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# -----------------------------------------------------------
# Target Group — DefectDojo
# -----------------------------------------------------------
resource "aws_lb_target_group" "defectdojo" {
  name        = "${var.project}-tg-defectdojo-${var.environment}"
  port        = 8080
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id

  health_check {
    enabled             = true
    path                = "/api/v2/users/?format=json"
    protocol            = "HTTP"
    matcher             = "200,401"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = merge(var.common_tags, { Service = "defectdojo" })
}

resource "aws_lb_listener_rule" "defectdojo" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  condition {
    host_header {
      values = [
        "defectdojo.${var.internal_domain}",
        "vuln.${var.internal_domain}"
      ]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.defectdojo.arn
  }
}

# -----------------------------------------------------------
# Security Groups
# -----------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "${var.project}-sg-alb-${var.environment}"
  description = "SG ALB interno: acepta HTTPS solo desde VPC"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS desde rango VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Hacia target groups en subnet privada"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.private_compute_cidr]
  }

  tags = merge(var.common_tags, { Name = "${var.project}-sg-alb" })
}

resource "aws_security_group" "defectdojo" {
  name        = "${var.project}-sg-defectdojo-${var.environment}"
  description = "SG DefectDojo: ALB + CI/CD runners + API externa"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "App desde ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description = "API desde subnet CI/CD runners / Lambdas"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.private_lambda_cidr]
  }

  egress {
    description = "Salida hacia VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.common_tags, {
    Name = "${var.project}-sg-defectdojo-${var.environment}"
  })
}
