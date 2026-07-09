# ============================================================
# modules/storage/outputs.tf
# ============================================================

output "logs_bucket_id" {
  value = aws_s3_bucket.logs.id
}

output "logs_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}

output "reports_bucket_id" {
  value = aws_s3_bucket.reports.id
}

output "reports_bucket_arn" {
  value = aws_s3_bucket.reports.arn
}

output "backups_bucket_id" {
  value = aws_s3_bucket.backups.id
}

output "backups_bucket_arn" {
  value = aws_s3_bucket.backups.arn
}

output "waf_logs_bucket_arn" {
  description = "ARN del bucket WAF logs (nombre aws-waf-logs-*) para wafv2_logging_configuration"
  value       = aws_s3_bucket.waf_logs.arn
}

output "waf_logs_bucket_id" {
  value = aws_s3_bucket.waf_logs.id
}
