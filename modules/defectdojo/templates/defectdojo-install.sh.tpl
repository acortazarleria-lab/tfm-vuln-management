#!/usr/bin/env bash
# ============================================================
# defectdojo-install.sh.tpl
# DefectDojo vía Docker Compose + configuración categorías
# (SAST/DAST/SCA/Infraestructura/Código) + deduplicación
# ============================================================
set -euo pipefail

PROJECT="${project}"
ENVIRONMENT="${environment}"
REGION="${region}"
DB_SECRET_ARN="${db_secret_arn}"
ADMIN_SECRET_ARN="${admin_secret_arn}"
API_KEY_SECRET_ARN="${api_key_secret_arn}"
S3_REPORTS_BUCKET="${s3_reports_bucket}"
DD_VERSION="${defectdojo_version}"
DB_HOST="${db_host}"
DB_PORT="${db_port}"
DB_NAME="${db_name}"

exec > >(tee /var/log/defectdojo-install.log) 2>&1
echo "=== Inicio instalación DefectDojo $(date) ==="

# -----------------------------------------------------------
# 1. Sistema base + Docker
# -----------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  curl wget gnupg2 apt-transport-https \
  ca-certificates jq awscli python3-pip

curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/ubuntu jammy stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -qq
apt-get install -y -qq \
  docker-ce docker-ce-cli containerd.io docker-compose-plugin

systemctl enable docker
systemctl start docker

# -----------------------------------------------------------
# 2. Montar volumen datos
# -----------------------------------------------------------
DEVICE="/dev/nvme1n1"
DATA_DIR="/opt/defectdojo"

if ! blkid "$DEVICE" &>/dev/null; then
  mkfs.xfs -f "$DEVICE"
fi

mkdir -p "$DATA_DIR"
UUID=$(blkid -s UUID -o value "$DEVICE")
echo "UUID=$UUID $DATA_DIR xfs defaults,noatime 0 2" >> /etc/fstab
mount -a

mkdir -p \
  "$DATA_DIR/media" \
  "$DATA_DIR/nginx" \
  "$DATA_DIR/logs"

# -----------------------------------------------------------
# 3. Recuperar credenciales desde Secrets Manager
# -----------------------------------------------------------
echo "→ Recuperando credenciales..."

DB_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "$DB_SECRET_ARN" \
  --region "$REGION" \
  --query SecretString --output text)

DB_USER=$(echo "$DB_SECRET" | jq -r '.username')
DB_PASS=$(echo "$DB_SECRET" | jq -r '.password')

ADMIN_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "$ADMIN_SECRET_ARN" \
  --region "$REGION" \
  --query SecretString --output text)

DD_ADMIN_USER=$(echo "$ADMIN_SECRET" | jq -r '.username')
DD_ADMIN_PASS=$(echo "$ADMIN_SECRET" | jq -r '.password')

# -----------------------------------------------------------
# 4. Docker Compose DefectDojo
# PostgreSQL externo (RDS) — sin DB local
# -----------------------------------------------------------
DD_SECRET_KEY=$(openssl rand -base64 50 | tr -d '\n')
DD_AES_KEY=$(openssl rand -base64 32 | tr -d '\n')

cat > "$DATA_DIR/docker-compose.yml" <<EOF
version: '3.9'

services:
  defectdojo:
    image: defectdojo/defectdojo-django:$DD_VERSION
    container_name: defectdojo
    restart: unless-stopped
    depends_on:
      - celerybeat
      - celeryworker
      - redis
    environment:
      DD_DEBUG: "False"
      DD_ALLOWED_HOSTS: "*"
      DD_SITE_URL: "https://defectdojo.$ENVIRONMENT.internal"

      DD_DATABASE_ENGINE: "django.db.backends.postgresql"
      DD_DATABASE_HOST: "$DB_HOST"
      DD_DATABASE_PORT: "$DB_PORT"
      DD_DATABASE_NAME: "$DB_NAME"
      DD_DATABASE_USER: "$DB_USER"
      DD_DATABASE_PASSWORD: "$DB_PASS"

      DD_SECRET_KEY: "$DD_SECRET_KEY"
      DD_CREDENTIAL_AES_256_KEY: "$DD_AES_KEY"

      DD_INITIALIZE: "true"
      DD_ADMIN_USER: "$DD_ADMIN_USER"
      DD_ADMIN_PASSWORD: "$DD_ADMIN_PASS"
      DD_ADMIN_MAIL: "soc@empresa.com"

      DD_MEDIA_ROOT: "/opt/defectdojo/media"
      DD_CELERY_BROKER_URL: "redis://redis:6379/0"

      DD_ENABLE_FINDING_GROUPS: "True"
      DD_DUPLICATE_CLUSTER_CASCADE_DELETE: "False"

    volumes:
      - $DATA_DIR/media:/opt/defectdojo/media
      - $DATA_DIR/logs:/var/log/defectdojo
    ports:
      - "8080:8080"
    logging:
      driver: "awslogs"
      options:
        awslogs-region: "$REGION"
        awslogs-group: "/vuln-mgmt/defectdojo"
        awslogs-stream: "django"

  celerybeat:
    image: defectdojo/defectdojo-django:$DD_VERSION
    container_name: defectdojo-celerybeat
    restart: unless-stopped
    depends_on:
      - redis
    environment:
      DD_DATABASE_ENGINE: "django.db.backends.postgresql"
      DD_DATABASE_HOST: "$DB_HOST"
      DD_DATABASE_PORT: "$DB_PORT"
      DD_DATABASE_NAME: "$DB_NAME"
      DD_DATABASE_USER: "$DB_USER"
      DD_DATABASE_PASSWORD: "$DB_PASS"
      DD_CELERY_BROKER_URL: "redis://redis:6379/0"
      DD_SECRET_KEY: "$DD_SECRET_KEY"
    command: ["bash", "-c", "celery -A dojo beat -l INFO"]
    logging:
      driver: "awslogs"
      options:
        awslogs-region: "$REGION"
        awslogs-group: "/vuln-mgmt/defectdojo"
        awslogs-stream: "celerybeat"

  celeryworker:
    image: defectdojo/defectdojo-django:$DD_VERSION
    container_name: defectdojo-celeryworker
    restart: unless-stopped
    depends_on:
      - redis
    environment:
      DD_DATABASE_ENGINE: "django.db.backends.postgresql"
      DD_DATABASE_HOST: "$DB_HOST"
      DD_DATABASE_PORT: "$DB_PORT"
      DD_DATABASE_NAME: "$DB_NAME"
      DD_DATABASE_USER: "$DB_USER"
      DD_DATABASE_PASSWORD: "$DB_PASS"
      DD_CELERY_BROKER_URL: "redis://redis:6379/0"
      DD_SECRET_KEY: "$DD_SECRET_KEY"
    command: ["bash", "-c", "celery -A dojo worker -l INFO"]
    logging:
      driver: "awslogs"
      options:
        awslogs-region: "$REGION"
        awslogs-group: "/vuln-mgmt/defectdojo"
        awslogs-stream: "celeryworker"

  redis:
    image: redis:7-alpine
    container_name: defectdojo-redis
    restart: unless-stopped
    volumes:
      - redis_data:/data
    logging:
      driver: "awslogs"
      options:
        awslogs-region: "$REGION"
        awslogs-group: "/vuln-mgmt/defectdojo"
        awslogs-stream: "redis"

volumes:
  redis_data:
EOF

echo "→ Iniciando DefectDojo..."
cd "$DATA_DIR"
docker compose up -d

echo "→ Esperando inicialización DefectDojo (~3 minutos)..."
until curl -sf "http://localhost:8080/api/v2/users/?format=json" \
  -H "Authorization: Token placeholder" 2>/dev/null | grep -q "detail\|results"; do
  sleep 15
  echo "  Esperando..."
done

# -----------------------------------------------------------
# 5. Configuración inicial vía API
# Crear estructura de productos por categoría de vuln
# ISO 27001: A.12.6 — gestión vulnerabilidades técnicas
# -----------------------------------------------------------
echo "→ Obteniendo API key real..."

DD_TOKEN=$(curl -sf -X POST \
  "http://localhost:8080/api/v2/api-token-auth/" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$DD_ADMIN_USER\", \"password\": \"$DD_ADMIN_PASS\"}" \
  | jq -r '.token')

aws secretsmanager put-secret-value \
  --secret-id "$API_KEY_SECRET_ARN" \
  --region "$REGION" \
  --secret-string "{\"api_key\": \"$DD_TOKEN\", \"base_url\": \"http://localhost:8080\"}"

echo "→ Creando productos por categoría de vulnerabilidad..."

create_product() {
  local name="$1"
  local desc="$2"
  local tags="$3"

  curl -sf -X POST \
    "http://localhost:8080/api/v2/products/" \
    -H "Authorization: Token $DD_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"$name\",
      \"description\": \"$desc\",
      \"prod_type\": 1,
      \"tags\": $tags,
      \"enable_simple_risk_acceptance\": false,
      \"enable_full_risk_acceptance\": true
    }"
}

create_product \
  "SAST - Análisis Estático" \
  "Vulnerabilidades detectadas por análisis estático de código fuente. Fuentes: SonarQube, Semgrep, Bandit, Checkmarx." \
  '["sast", "static-analysis", "code-security"]'

create_product \
  "DAST - Análisis Dinámico" \
  "Vulnerabilidades detectadas en aplicaciones en ejecución. Fuentes: OWASP ZAP, Burp Suite, Nikto." \
  '["dast", "dynamic-analysis", "web-security"]'

create_product \
  "SCA - Dependencias" \
  "Vulnerabilidades en dependencias y librerías de terceros. Fuentes: Dependency-Track, Trivy, OSS Index." \
  '["sca", "dependencies", "supply-chain"]'

create_product \
  "Infraestructura - IaC y Cloud" \
  "Vulnerabilidades en configuración de infraestructura. Fuentes: Checkov, tfsec, Trivy IaC, AWS Config." \
  '["infrastructure", "iac", "cloud-security", "misconfig"]'

create_product \
  "Código y Servicios - Runtime" \
  "Vulnerabilidades detectadas en servicios en ejecución y revisiones manuales." \
  '["runtime", "services"]'

echo "→ Creando engagements continuos por categoría..."

create_engagement() {
  local product_id="$1"
  local name="$2"
  local scan_type="$3"

  curl -sf -X POST \
    "http://localhost:8080/api/v2/engagements/" \
    -H "Authorization: Token $DD_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"$name\",
      \"product\": $product_id,
      \"status\": \"In Progress\",
      \"engagement_type\": \"CI/CD\",
      \"deduplication_on_engagement\": false,
      \"target_start\": \"$(date +%Y-%m-%d)\",
      \"target_end\": \"$(date -d '+1 year' +%Y-%m-%d)\",
      \"tags\": [\"automated\", \"$scan_type\"]
    }"
}

PRODUCTS=$(curl -sf \
  "http://localhost:8080/api/v2/products/?limit=10" \
  -H "Authorization: Token $DD_TOKEN" \
  | jq '.results[] | {id, name}')

SAST_ID=$(echo "$PRODUCTS" | jq 'select(.name | contains("SAST")) | .id')
DAST_ID=$(echo "$PRODUCTS" | jq 'select(.name | contains("DAST")) | .id')
SCA_ID=$(echo "$PRODUCTS"  | jq 'select(.name | contains("SCA"))  | .id')
INFRA_ID=$(echo "$PRODUCTS" | jq 'select(.name | contains("Infraestructura")) | .id')
CODE_ID=$(echo "$PRODUCTS"  | jq 'select(.name | contains("Código")) | .id')

create_engagement "$SAST_ID"  "SAST Continuous Scan"   "sonarqube"
create_engagement "$DAST_ID"  "DAST Continuous Scan"   "zap"
create_engagement "$SCA_ID"   "SCA Dependency Scan"    "dependency-track"
create_engagement "$INFRA_ID" "IaC Security Scan"      "checkov"
create_engagement "$CODE_ID"  "Runtime Findings"       "manual"

echo "→ Configurando reglas de deduplicación global..."

curl -sf -X PATCH \
  "http://localhost:8080/api/v2/system_settings/1/" \
  -H "Authorization: Token $DD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enable_deduplication": true,
    "delete_duplicates": false,
    "max_dupes": 3,
    "enable_jira": false,
    "enable_github": false,
    "false_positive_history": true,
    "retroactive_false_positive_history": true
  }'

# -----------------------------------------------------------
# 6. CloudWatch Agent
# -----------------------------------------------------------
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/defectdojo-install.log",
            "log_group_name": "/vuln-mgmt/defectdojo/install",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 30
          }
        ]
      }
    }
  },
  "metrics": {
    "namespace": "VulnMgmt/DefectDojo",
    "metrics_collected": {
      "cpu":  {"measurement": ["cpu_usage_active"], "metrics_collection_interval": 60},
      "disk": {
        "measurement": ["used_percent"],
        "metrics_collection_interval": 60,
        "resources": ["/", "/opt/defectdojo"]
      },
      "mem":  {"measurement": ["mem_used_percent"], "metrics_collection_interval": 60}
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# -----------------------------------------------------------
# 7. Hardening OS básico
# ISO 27001: A.14.2.5 — principios ingeniería sistemas seguros
# -----------------------------------------------------------
echo "→ Aplicando hardening OS..."

systemctl disable --now snapd apport 2>/dev/null || true

cat >> /etc/sysctl.d/99-hardening.conf <<'SYSCTL'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
SYSCTL

sysctl -p /etc/sysctl.d/99-hardening.conf

echo "=== Instalación DefectDojo completada $(date) ==="
