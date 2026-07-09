# Validación local sin cuenta AWS

Tres opciones ordenadas de menor a mayor complejidad.

---

## Opción A — Solo `terraform plan` (recomendada para TFM)

**Requisito único:** Terraform instalado localmente.

### Instalación de Terraform

```bash
# macOS
brew tap hashicorp/tap && brew install hashicorp/tap/terraform

# Ubuntu/Debian
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform

# Windows
winget install Hashicorp.Terraform
# o: choco install terraform

# Verificar
terraform version   # debe mostrar >= 1.7.5
```

### Ejecutar el plan

```bash
# Linux/macOS
chmod +x localstack/plan-only.sh
./localstack/plan-only.sh

# Windows (PowerShell)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\localstack\plan-only.ps1
```

El script hace automáticamente:
1. `terraform init -backend=false` — sin necesidad de S3 ni DynamoDB reales
2. `terraform validate` — validación de sintaxis
3. `terraform plan` — con variables ficticias, sin llamar a AWS

### Qué valida

| Check | ¿Lo valida? |
|---|---|
| Sintaxis HCL | ✅ Sí |
| Referencias entre módulos (variables, outputs) | ✅ Sí |
| Tipos de datos | ✅ Sí |
| Recursos que se crearían (conteo) | ✅ Sí |
| Permisos IAM reales | ❌ No (necesita AWS) |
| Disponibilidad de recursos en AZ | ❌ No (necesita AWS) |

### Resultado esperado

```
Plan: 87 to add, 0 to change, 0 to destroy.
```

Si sale ese mensaje, la infraestructura está estructuralmente correcta.

---

## Opción B — LocalStack + terraform apply (más completo)

**Requisitos:** Docker Desktop + Terraform.

LocalStack simula AWS localmente. Cubre ~75% de los servicios del proyecto.

### Ejecutar

```bash
# 1. Levantar LocalStack
cd localstack/
docker compose up -d

# 2. Esperar a que esté listo (~20s)
curl http://localhost:4566/_localstack/health

# 3. Ejecutar plan + apply
chmod +x setup-and-plan.sh
./setup-and-plan.sh
```

### Servicios soportados en LocalStack Community (gratuito)

| Servicio | Soporte |
|---|---|
| S3 | ✅ Completo |
| IAM | ✅ Completo |
| KMS | ✅ Completo |
| Secrets Manager | ✅ Completo |
| Lambda | ✅ Completo |
| CloudWatch | ✅ Completo |
| SNS | ✅ Completo |
| DynamoDB | ✅ Completo |
| EC2 (básico) | ⚠️ Parcial (no user_data real) |
| RDS | ⚠️ Parcial (endpoint simulado) |
| ALB/WAF | ⚠️ Parcial |
| GuardDuty | ❌ Solo Pro |
| AWS Config | ❌ Solo Pro |

### Parar LocalStack

```bash
docker compose down
```

---

## Opción C — AWS Free Tier (~$15/mes, máxima fidelidad)

Crear cuenta gratuita en AWS (12 meses free tier) y cambiar los tamaños:

```hcl
# environments/dev/terraform.tfvars — añadir para ahorrar
# Estos valores sobrescriben los defaults del módulo
```

```hcl
# modules/defectdojo/variables.tf — cambiar default
variable "instance_type" {
  default = "t2.micro"   # en vez de t3.small (dentro del Free Tier)
}

# modules/database/variables.tf — cambiar default
variable "instance_class" {
  default = "db.t2.micro"   # dentro del Free Tier
}
```

Con estos cambios el coste mensual baja de ~$118 a ~$15.

---

## Checkov — validación de seguridad IaC (sin AWS, sin Docker)

```bash
pip install checkov

# Desde la raíz del repositorio
checkov -d . \
  --framework terraform \
  --compact \
  --skip-check CKV_AWS_2,CKV_AWS_130,CKV_AWS_117,CKV_AWS_272 \
  2>&1 | tee localstack/checkov-output.txt

# Ver resumen
grep -E "Passed|Failed|Skipped" localstack/checkov-output.txt | tail -3
```

Esto valida seguridad IaC: cifrado, acceso público, least privilege, etc.
Es lo que ejecuta el pipeline de CI/CD en cada PR.

---

## Flujo recomendado para la defensa del TFM

```
1. terraform init -backend=false    → valida sintaxis y módulos
2. terraform validate               → valida tipos y referencias
3. terraform plan -var-file=...     → muestra recursos a crear
4. checkov -d .                     → valida seguridad IaC
5. (Opcional) LocalStack apply      → demuestra apply funcional
```

Los pasos 1-4 no requieren ni cuenta AWS ni Docker.
El paso 5 solo requiere Docker Desktop.
