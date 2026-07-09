# ============================================================
# modules/security/outputs.tf
# Contratos hacia otros módulos
# ============================================================

output "kms_rds_arn" {
  value = aws_kms_key.rds.arn
}

output "kms_s3_arn" {
  value = aws_kms_key.s3.arn
}

output "kms_ec2_arn" {
  value = aws_kms_key.ec2.arn
}

output "kms_secrets_arn" {
  value = aws_kms_key.secrets.arn
}

output "kms_cloudwatch_arn" {
  value = aws_kms_key.cloudwatch.arn
}

output "defectdojo_instance_profile" {
  value = aws_iam_instance_profile.defectdojo.name
}

output "defectdojo_role_arn" {
  value = aws_iam_role.defectdojo.arn
}

output "defectdojo_role_name" {
  value = aws_iam_role.defectdojo.name
}

output "lambda_integration_role_arn" {
  value = aws_iam_role.lambda_integration.arn
}

output "lambda_integration_role_name" {
  value = aws_iam_role.lambda_integration.name
}

output "scheduler_role_arn" {
  value = aws_iam_role.scheduler.arn
}

output "config_role_arn" {
  value = aws_iam_role.config.arn
}

output "dlm_role_arn" {
  value = aws_iam_role.dlm.arn
}

output "rds_monitoring_role_arn" {
  value = aws_iam_role.rds_monitoring.arn
}

output "sns_alerts_arn" {
  value = aws_sns_topic.alerts.arn
}
