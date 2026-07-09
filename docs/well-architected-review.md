# AWS Well-Architected Review

Revisión de los 5 pilares para la arquitectura de gestión del ciclo
de vida de vulnerabilidades (DefectDojo + RDS + ALB/WAF + S3 +
Security + Monitoring + CI/CD).

## Pilar 1 — Operational Excellence

| Pregunta WA | Implementación | Evidencia |
|---|---|---|
| OPS 1: Organización | Terraform IaC 100% — zero snowflakes | `modules/` + `environments/` |
| OPS 2: Preparación | `user_data` con logging desde el primer boot | `defectdojo-install.sh.tpl` → CloudWatch |
| OPS 3: Operación | CI/CD automatizado, 4 workflows | `.github/workflows/` |
| OPS 4: Evolución | Drift detection en plan + estado versionado | `terraform-plan.yml` job `drift` |
| OPS 5: Respuesta | Alarmas SNS + scripts de runbook | `modules/monitoring/` |

**Trade-offs documentados:**
- Single-AZ reduce el RTO a <4h, aceptado para PyME con presupuesto <$200/mes.
- `user_data` en lugar de AMIs preconfiguradas: mayor tiempo de arranque
  (~15 min) a cambio de cero drift en la configuración.

## Pilar 2 — Security

| Pregunta WA | Implementación | Evidencia |
|---|---|---|
| SEC 1: IAM | Roles por servicio, least privilege, sin root programático | `modules/security/iam.tf` |
| SEC 2: Detección | GuardDuty + CloudTrail + VPC Flow Logs + AWS Config | `modules/monitoring/guardduty.tf`, `config.tf` |
| SEC 3: Infraestructura | VPC privada + SGs + NACLs + WAF + ALB interno | `modules/networking/` |
| SEC 4: Datos | KMS CMK por servicio + S3 WORM + RDS cifrado | `modules/security/kms.tf` |
| SEC 5: Incidentes | EventBridge → SNS + Lambda webhook de enriquecimiento | `modules/defectdojo/lambda.tf` |
| SEC 6: Aplicación | DefectDojo como single source of truth de vulns + enriquecimiento EPSS/KEV | `modules/defectdojo/lambda/enrichment/handler.py` |

## Pilar 3 — Reliability

| Pregunta WA | Implementación | Evidencia |
|---|---|---|
| REL 1: Fundamentos | VPC con subnets segmentadas + endpoints | `modules/networking/vpc.tf` |
| REL 2: Workload | RDS backup 30d + EBS snapshots 7d (DLM) | `modules/database/main.tf` |
| REL 3: Cambios | Estado Terraform en S3 + DynamoDB lock | `environments/prod/backend.tf` |
| REL 4: Fallos | `deletion_protection=true` + `skip_final_snapshot=false` | `modules/database/main.tf` |
| REL 5: Recuperación | RTO <4h documentado | Este documento |

**Decisión Single-AZ:** RTO <4h aceptable para contexto académico/PyME.
Multi-AZ añadiría ~$60/mes, superando presupuesto. Mitigación: backups
automáticos cada 24h, snapshots EBS cada 24h y estado Terraform
versionado en S3.

## Pilar 4 — Performance Efficiency

| Pregunta WA | Implementación | Evidencia |
|---|---|---|
| PERF 1: Selección | Right-sizing: t3.small DefectDojo, db.t3.micro RDS | `variables.tf` con defaults justificados |
| PERF 2: Review | Storage autoscaling RDS hasta 100GB | `modules/database/main.tf` |
| PERF 3: Monitorización | CloudWatch métricas custom + Performance Insights | `modules/monitoring/`, `modules/defectdojo/lambda/metrics/` |
| PERF 4: Trade-offs | gp3 sobre gp2: mismo coste, +20% IOPS baseline | EBS config en `modules/defectdojo/main.tf` |

## Pilar 5 — Cost Optimization

| Pregunta WA | Implementación | Evidencia |
|---|---|---|
| COST 1: Conciencia | Tags `CostCenter` en todos los recursos | `locals.tf` `common_tags` |
| COST 2: Gasto | Infracost en CI/CD + estimación por módulo | `terraform-plan.yml` |
| COST 3: Recursos | Apagado automático dev 20:00–08:00 CET | `aws_scheduler_schedule` en `modules/defectdojo/main.tf` |
| COST 4: Almacenamiento | S3 Intelligent Tiering + Glacier 90d | `modules/storage/main.tf` |
| COST 5: Optimización | `bucket_key_enabled=true` reduce coste KMS ~99% | `modules/storage/main.tf` |

## Resumen de costes (entorno prod)

| Componente | Coste/mes aprox. |
|---|---|
| EC2 DefectDojo + EBS | ~$23 |
| RDS PostgreSQL | ~$25 |
| ALB + WAF | ~$26 |
| VPC Endpoints (sin NAT) | ~$45 |
| S3 (logs/reports/backups) | ~$3 |
| KMS (5 CMKs) | ~$5 |
| Monitoring (CloudWatch/GuardDuty/Config/CloudTrail) | ~$30 |
| Lambdas integración | ~$2 |
| CI/CD (GitHub Actions/Infracost) | ~$0–5 |
| **Total** | **~$118/mes** |

Margen sobre el límite de $200/mes: **~$82/mes**.
