# Gestión del ciclo de vida de vulnerabilidades — TFM

Arquitectura Terraform en AWS para la detección, correlación y gestión
de vulnerabilidades de una PyME española, con **DefectDojo** como
núcleo de gestión y **Dependency-Track** integrado vía CI/CD.

## 3 reglas inquebrantables

1. **Costes mínimos** — presupuesto objetivo <$200/mes (real: ~$118/mes)
2. **AWS Well-Architected + ISO 27001** — ver `docs/well-architected-review.md` y `docs/iso27001-controls.tf`
3. **100% Open Source** — DefectDojo, Dependency-Track, OWASP ZAP, Trivy, Checkov, Semgrep

## Alcance de la arquitectura

El proyecto partió de un diseño más amplio (Wazuh SIEM + DefectDojo +
Dependency-Track, los tres como infraestructura EC2) y se redujo
deliberadamente de scope:

- **DefectDojo** es el núcleo del sistema — única instancia EC2, gestiona
  findings de las 5 categorías: SAST, DAST, SCA, Infraestructura y
  Código/Servicios.
- **Dependency-Track** se ejecuta como step del pipeline CI/CD
  (`.github/workflows/security-scan.yml`), no como infraestructura
  propia. Sube SBOMs, espera el análisis de vulnerabilidades y reenvía
  los resultados a DefectDojo.
- **Wazuh** queda fuera de alcance.

```
Push de código → GitHub Actions
  ├── Trivy (SCA imagen Docker + filesystem + IaC)   → DefectDojo
  ├── Dependency-Track CLI (SBOM CycloneDX)          → DefectDojo
  ├── Checkov / tfsec (IaC scan)                     → DefectDojo
  ├── Semgrep (SAST)                                 → DefectDojo
  └── OWASP ZAP (DAST, baseline scan)                → DefectDojo
```

DefectDojo enriquece automáticamente los findings críticos/altos con
EPSS, CISA KEV y SLA mediante una Lambda programada
(`modules/defectdojo/lambda/enrichment/`), y notifica eventos críticos
vía webhook + SNS.

## Estructura del repositorio

```
.
├── .github/workflows/         CI/CD: validate, plan, apply, security-scan, compliance-report
├── .zap/                      Reglas personalizadas OWASP ZAP
├── docs/                      Well-Architected Review, ISO 27001, GDPR
├── environments/
│   ├── dev/                   Root module — entorno dev (apagado automático)
│   └── prod/                  Root module — entorno prod (24/7)
├── modules/
│   ├── security/               KMS (5 CMKs) + IAM roles + SNS alerts
│   ├── networking/              VPC + subnets + VPC Endpoints + ALB + WAF
│   ├── database/                 RDS PostgreSQL + Secrets Manager
│   ├── storage/                   S3 (logs WORM, reports, backups)
│   ├── defectdojo/                 EC2 DefectDojo + Lambdas integración
│   └── monitoring/                  CloudWatch + GuardDuty + Config + CloudTrail
└── scripts/                    Bootstrap backend, init DB, informes compliance
```

Cada entorno (`environments/dev`, `environments/prod`) es un *root
module* autocontenido: incluye su propio `versions.tf`, `variables.tf`,
`locals.tf`, `backend.tf`, `main.tf` (orquestador de módulos),
`terraform.tfvars` y `outputs.tf`.

## Despliegue

### 1. Bootstrap del backend remoto (una vez por entorno)

```bash
./scripts/bootstrap-backend.sh prod
./scripts/bootstrap-backend.sh dev
```

Crea el bucket S3 (versionado, cifrado, bloqueo de acceso público) y
la tabla DynamoDB de locking necesarios antes del primer `terraform init`.

### 2. Construir la Lambda layer de dependencias Python

```bash
cd modules/defectdojo/lambda/layer
mkdir -p python
pip install requests -t python/ \
  --platform manylinux2014_x86_64 --only-binary=:all: --python-version 3.12
zip -r python-deps.zip python/
```

### 3. Configurar variables sensibles

Editar `environments/<env>/terraform.tfvars` con el ARN del
certificado ACM corporativo, el dominio interno y el email de alertas.
En CI/CD estas variables se inyectan desde GitHub Secrets (ver
`.github/workflows/terraform-plan.yml`).

### 4. Desplegar

```bash
cd environments/prod
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

### 5. Inicializar la base de datos DefectDojo

Ejecutar `scripts/db-init.sql` vía SSM Run Command contra la instancia
DefectDojo, sustituyendo `${DEFECTDOJO_PASSWORD}` por el valor real
almacenado en el secret `vuln-mgmt/defectdojo/db-credentials`.

### 6. Configurar el webhook de DefectDojo

```bash
python3 scripts/configure-defectdojo-webhook.py \
  --project vuln-mgmt --environment prod --region eu-west-1
```

## CI/CD — GitHub Secrets requeridos

| Secret | Descripción |
|---|---|
| `AWS_ROLE_TERRAFORM` | ARN del role IAM asumido vía OIDC por GitHub Actions |
| `ACM_CERT_ARN` | ARN del certificado corporativo importado en ACM |
| `ALARM_EMAIL` | Email destino de alertas SNS |
| `INTERNAL_DOMAIN` | Dominio interno corporativo (ej. `empresa.internal`) |
| `DEFECTDOJO_API_KEY` / `DEFECTDOJO_URL` / `DEFECTDOJO_APP_URL` | Acceso a la API de DefectDojo |
| `DTRACK_API_KEY` / `DTRACK_URL` | Acceso a Dependency-Track (paso de CI/CD) |
| `SEMGREP_APP_TOKEN` | Token Semgrep (opcional si se usa solo el ruleset OSS) |
| `INFRACOST_API_KEY` | Estimación de costes en PRs |
| `SNS_ALERTS_ARN` | ARN del topic SNS para notificaciones de apply |
| `S3_LOGS_BUCKET` | Bucket destino de informes de compliance |

Variables no sensibles (`Settings → Variables`): `DEFECTDOJO_VERSION`,
`DTRACK_PROJECT_APP_UUID`.

## Documentación de cumplimiento

- `docs/well-architected-review.md` — revisión de los 5 pilares AWS Well-Architected
- `docs/iso27001-controls.tf` — mapeo de 22 controles ISO 27001:2022 a recursos Terraform
- `docs/gdpr-controls.md` — controles GDPR (Art. 5, 25, 32)

El informe de cumplimiento se regenera automáticamente cada mes
(`.github/workflows/compliance-report.yml`) contra el estado real de
AWS, no solo el estado declarativo de Terraform.

## Coste estimado

~$118/mes en producción (margen de $82 sobre el límite de $200/mes).
Desglose completo en `docs/well-architected-review.md`.
