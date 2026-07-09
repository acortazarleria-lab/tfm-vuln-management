# ============================================================
# modules/networking/outputs.tf
# ============================================================

output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "private_compute_subnet_id" {
  value = aws_subnet.private_compute.id
}

output "private_data_subnet_ids" {
  description = "IDs de ambas subnets de datos (AZ-a y AZ-b) para el RDS subnet group"
  value       = [aws_subnet.private_data.id, aws_subnet.private_data_b.id]
}

output "private_lambda_subnet_ids" {
  value = [aws_subnet.private_lambda.id]
}

output "sg_vpc_endpoints_id" {
  value = aws_security_group.vpc_endpoints.id
}

output "vpc_endpoint_s3_id" {
  value = aws_vpc_endpoint.s3.id
}

output "flow_log_group_name" {
  value = aws_cloudwatch_log_group.vpc_flow_logs.name
}

output "sg_alb_id" {
  value = aws_security_group.alb.id
}

output "sg_defectdojo_id" {
  value = aws_security_group.defectdojo.id
}

output "tg_defectdojo_arn" {
  value = aws_lb_target_group.defectdojo.arn
}

output "alb_arn" {
  value = aws_lb.main.arn
}

output "alb_arn_suffix" {
  value = aws_lb.main.arn_suffix
}

output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "waf_web_acl_arn" {
  value = aws_wafv2_web_acl.main.arn
}

output "waf_web_acl_name" {
  value = aws_wafv2_web_acl.main.name
}
