# ============================================================
# environments/prod/main.tf
# Orquestador: instancia módulos y pasa outputs entre ellos
# Scope: DefectDojo (core) + RDS + ALB/WAF + S3 + Security +
#        Monitoring + CI/CD
# Wazuh fuera de scope. Dependency-Track se ejecuta como step
# de CI/CD (ver .github/workflows/security-scan.yml), no como
# infraestructura EC2.
# ============================================================

module "security" {
  source = "../../modules/security"

  project     = var.project
  environment = var.environment
  aws_region  = var.aws_region
  alarm_email = var.alarm_email
  common_tags = local.common_tags
}

module "networking" {
  source = "../../modules/networking"

  project              = var.project
  environment          = var.environment
  aws_region           = var.aws_region
  vpc_cidr             = local.cidrs.vpc
  public_subnet_cidr   = local.cidrs.public
  public_subnet_cidr_b = local.cidrs.public_b
  private_compute_cidr = local.cidrs.private_compute
  private_data_cidr    = local.cidrs.private_data
  private_data_cidr_b  = local.cidrs.private_data_b
  private_lambda_cidr  = local.cidrs.private_lambda
  internal_domain      = var.internal_domain
  acm_certificate_arn  = var.acm_certificate_arn
  kms_cloudwatch_arn   = module.security.kms_cloudwatch_arn
  alb_logs_bucket_id   = module.storage.logs_bucket_id
  waf_logs_bucket_arn  = module.storage.waf_logs_bucket_arn
  common_tags          = local.common_tags

  depends_on = [module.storage]
}

module "storage" {
  source = "../../modules/storage"

  project             = var.project
  environment         = var.environment
  kms_s3_arn          = module.security.kms_s3_arn
  defectdojo_role_arn = module.security.defectdojo_role_arn
  retention           = local.retention
  common_tags         = local.common_tags
}

module "database" {
  source = "../../modules/database"

  project                 = var.project
  environment             = var.environment
  vpc_id                  = module.networking.vpc_id
  subnet_ids              = module.networking.private_data_subnet_ids
  kms_rds_arn             = module.security.kms_rds_arn
  kms_secrets_arn         = module.security.kms_secrets_arn
  sg_defectdojo_id        = module.networking.sg_defectdojo_id
  private_compute_cidr    = local.cidrs.private_compute
  rds_monitoring_role_arn = module.security.rds_monitoring_role_arn
  backup_retention_days   = local.retention.backup_days
  common_tags             = local.common_tags
}

module "defectdojo" {
  source = "../../modules/defectdojo"

  project              = var.project
  environment          = var.environment
  vpc_id               = module.networking.vpc_id
  subnet_id            = module.networking.private_compute_subnet_id
  sg_id                = module.networking.sg_defectdojo_id
  tg_arn               = module.networking.tg_defectdojo_arn
  kms_key_arn          = module.security.kms_ec2_arn
  kms_secrets_arn      = module.security.kms_secrets_arn
  instance_profile     = module.security.defectdojo_instance_profile
  s3_bucket_id         = module.storage.reports_bucket_id
  db_secret_arn        = module.database.defectdojo_secret_arn
  db_endpoint          = module.database.defectdojo_endpoint
  dlm_role_arn         = module.security.dlm_role_arn
  scheduler_role_arn   = module.security.scheduler_role_arn
  lambda_role_arn      = module.security.lambda_integration_role_arn
  sns_alerts_arn       = module.security.sns_alerts_arn
  private_compute_cidr = local.cidrs.private_compute
  internal_domain      = var.internal_domain
  common_tags          = local.common_tags
}

module "monitoring" {
  source = "../../modules/monitoring"

  project                     = var.project
  environment                 = var.environment
  alb_arn_suffix              = module.networking.alb_arn_suffix
  waf_web_acl_name            = module.networking.waf_web_acl_name
  defectdojo_instance_id      = module.defectdojo.instance_id
  rds_identifier              = module.database.rds_identifier
  s3_logs_bucket              = module.storage.logs_bucket_id
  kms_cloudwatch_arn          = module.security.kms_cloudwatch_arn
  sns_alerts_arn              = module.security.sns_alerts_arn
  config_role_arn             = module.security.config_role_arn
  lambda_integration_role_arn = module.security.lambda_integration_role_arn
  retention_days              = local.retention.hot_days
  common_tags                 = local.common_tags
}
