# GDPR — Controles implementados

## Art. 5(1)(e) — Limitación del plazo de conservación

| Dato | Retención hot | Retención cold | Base legal |
|---|---|---|---|
| VPC Flow Logs | 90 días CloudWatch | 365 días S3 Glacier | Interés legítimo seguridad |
| Logs WAF / ALB | 90 días | 365 días Glacier | Interés legítimo seguridad |
| Findings DefectDojo | Indefinido (activos) | 365 días (cerrados) | Interés legítimo |
| Credenciales DB | N/A | Rotación automática | Minimización |
| Backups RDS | 30 días | 365 días Glacier | Continuidad de negocio |
| Informes de cumplimiento | N/A | 730 días (2 años) | Evidencia auditoría |

**Implementación Terraform:**
- `modules/storage/main.tf`: lifecycle policies S3 por prefijo
- `modules/monitoring/main.tf`: `retention_in_days` en CloudWatch Log Groups
- `modules/database/main.tf`: `backup_retention_period`

## Art. 5(1)(f) — Integridad y confidencialidad

| Control | Implementación |
|---|---|
| Cifrado en tránsito | TLS 1.3 en ALB + `rds.force_ssl=1` + HTTPS en VPC Endpoints |
| Cifrado en reposo | KMS CMK por servicio (RDS, S3, EC2, Secrets, CloudWatch) |
| Control de acceso | IAM least privilege + Security Groups + NACLs |
| Trazabilidad | CloudTrail + VPC Flow Logs + GuardDuty |

## Art. 25 — Privacidad por diseño

| Principio | Implementación |
|---|---|
| Minimización de datos | WAF redacta los headers `Authorization` y `Cookie` en los logs |
| Acceso mínimo | Roles IAM con ARNs explícitos, sin wildcards |
| Privacidad por defecto | `block_public_access` en todos los buckets S3 |
| Pseudonimización | Logs de acceso no contienen datos personales directos |

## Art. 32 — Seguridad del tratamiento

| Medida | Implementación |
|---|---|
| Seudonimización | Logs redactados (headers `Authorization`, `Cookie`) |
| Cifrado | KMS CMK + TLS 1.3 |
| Confidencialidad | VPC privada + ALB interno (sin exposición a Internet) |
| Integridad | CloudTrail con `enable_log_file_validation=true` |
| Disponibilidad | RDS backup 30 días + EBS snapshots 7 días |
| Resiliencia | Single-AZ con RTO <4h documentado y aceptado |
| Prueba periódica | AWS Config + GuardDuty + CloudWatch alarmas + informe mensual de compliance |

## Generación de evidencia

El informe de compliance se genera automáticamente cada mes mediante
`.github/workflows/compliance-report.yml`, que ejecuta
`scripts/generate-compliance-report.py` contra el estado real de AWS
(no solo el estado declarativo de Terraform) y archiva el resultado en
`s3://<logs-bucket>/compliance-reports/<año>/<mes>/`.
