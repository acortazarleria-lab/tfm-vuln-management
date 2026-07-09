# ============================================================
# modules/defectdojo/outputs.tf
# ============================================================

output "instance_id" {
  value = aws_instance.defectdojo.id
}

output "instance_arn" {
  value = aws_instance.defectdojo.arn
}

output "private_ip" {
  value = aws_instance.defectdojo.private_ip
}

output "api_key_secret_arn" {
  value = aws_secretsmanager_secret.defectdojo_api_key.arn
}

output "admin_secret_arn" {
  value = aws_secretsmanager_secret.defectdojo_admin.arn
}

output "internal_url" {
  value     = aws_ssm_parameter.defectdojo_url.value
  sensitive = true
}

output "dashboard_url" {
  value = "https://defectdojo.${var.internal_domain}"
}

output "enrichment_lambda_arn" {
  value = aws_lambda_function.enrichment.arn
}

output "metrics_lambda_arn" {
  value = aws_lambda_function.metrics.arn
}

output "webhook_url" {
  value     = aws_ssm_parameter.webhook_url.value
  sensitive = true
}

output "webhook_lambda_arn" {
  value = aws_lambda_function.webhook.arn
}

output "sg_lambda_id" {
  value = aws_security_group.lambda.id
}
