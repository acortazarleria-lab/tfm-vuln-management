# ============================================================
# environments/prod/outputs.tf
# Outputs expuestos a nivel de entorno — usados por CI/CD
# ============================================================

output "defectdojo_dashboard_url" {
  value = module.defectdojo.dashboard_url
}

output "defectdojo_internal_url" {
  value     = module.defectdojo.internal_url
  sensitive = true
}

output "defectdojo_instance_id" {
  value = module.defectdojo.instance_id
}

output "rds_endpoint" {
  value = module.database.rds_endpoint
}

output "alb_dns_name" {
  value = module.networking.alb_dns_name
}

output "webhook_url" {
  value     = module.defectdojo.webhook_url
  sensitive = true
}

output "cloudwatch_dashboard_url" {
  value = module.monitoring.dashboard_url
}

output "logs_bucket_id" {
  value = module.storage.logs_bucket_id
}

output "reports_bucket_id" {
  value = module.storage.reports_bucket_id
}

output "sns_alerts_arn" {
  value = module.security.sns_alerts_arn
}
