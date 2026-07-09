# Lambda Layer — Python dependencies

Este directorio aloja el `.zip` de la layer compartida `requests` + `boto3`
usada por las Lambdas `enrichment` y `metrics`.

`boto3` ya viene incluido en el runtime de Lambda, pero se referencia
aquí por claridad de versión. La dependencia real que hay que empaquetar
es `requests` (y sus dependencias transitivas `urllib3`, `certifi`,
`charset-normalizer`, `idna`).

## Build (ejecutar antes de `terraform apply`)

```bash
cd modules/defectdojo/lambda/layer
mkdir -p python
pip install requests -t python/ \
  --platform manylinux2014_x86_64 \
  --only-binary=:all: \
  --python-version 3.12
zip -r python-deps.zip python/
```

El resultado `python-deps.zip` debe quedar en este mismo directorio.
Terraform (`aws_lambda_layer_version.python_deps` en `lambda.tf`) lo
referencia directamente vía `filename`.

## CI/CD

El workflow `terraform-apply.yml` asume que este paso de build se ha
ejecutado previamente o se añade como step adicional antes del
`terraform init` si se desea automatizar completamente.
