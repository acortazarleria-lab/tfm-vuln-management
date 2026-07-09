# ============================================================
# modules/database/outputs.tf
# ============================================================

output "rds_identifier" {
  value = aws_db_instance.main.id
}

output "rds_arn" {
  value = aws_db_instance.main.arn
}

output "rds_endpoint" {
  value = aws_db_instance.main.address
}

output "rds_port" {
  value = aws_db_instance.main.port
}

output "sg_rds_id" {
  value = aws_security_group.rds.id
}

output "defectdojo_secret_arn" {
  value       = aws_secretsmanager_secret.defectdojo_db.arn
  description = "ARN secreto credenciales DefectDojo → módulo defectdojo"
}

output "defectdojo_endpoint" {
  value = {
    host   = aws_db_instance.main.address
    port   = aws_db_instance.main.port
    dbname = "defectdojo"
  }
}
