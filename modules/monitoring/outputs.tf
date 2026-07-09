# ============================================================
# modules/monitoring/outputs.tf
# ============================================================

output "sns_alerts_arn" {
  value = var.sns_alerts_arn
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "dashboard_name" {
  value = aws_cloudwatch_dashboard.main.dashboard_name
}

output "dashboard_url" {
  value = "https://${local.region}.console.aws.amazon.com/cloudwatch/home#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.main.arn
}
