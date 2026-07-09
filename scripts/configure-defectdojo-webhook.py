#!/usr/bin/env python3
"""
configure-defectdojo-webhook.py
Configura el webhook en DefectDojo apuntando al API Gateway
generado por Terraform (módulo defectdojo/lambda.tf).
Ejecutar tras el primer despliegue o cuando cambie la URL.

Uso:
  python3 configure-defectdojo-webhook.py \
    --project vuln-mgmt \
    --environment prod \
    --region eu-west-1
"""

import argparse
import json
import sys

import boto3
import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', required=True)
    parser.add_argument('--environment', required=True)
    parser.add_argument('--region', default='eu-west-1')
    args = parser.parse_args()

    ssm = boto3.client('ssm', region_name=args.region)
    secrets = boto3.client('secretsmanager', region_name=args.region)

    webhook_url = ssm.get_parameter(
        Name=f"/{args.project}/{args.environment}/webhook/url"
    )['Parameter']['Value']

    dd_secret = json.loads(
        secrets.get_secret_value(
            SecretId=f"{args.project}/defectdojo/api-key"
        )['SecretString']
    )

    dd_token = dd_secret['api_key']
    dd_base_url = dd_secret['base_url']
    headers = {
        "Authorization": f"Token {dd_token}",
        "Content-Type": "application/json"
    }

    print("Configurando webhook en DefectDojo")
    print(f"  URL webhook: {webhook_url}")
    print(f"  DefectDojo:  {dd_base_url}")

    resp = requests.patch(
        f"{dd_base_url}/api/v2/system_settings/1/",
        headers=headers,
        json={
            "slack_channel": webhook_url,
            "slack_token": "webhook",
            "enable_slack_notifications": True,
            "slack_notifications_level": "Critical"
        },
        timeout=15
    )

    if resp.status_code in (200, 201):
        print("Webhook configurado correctamente en DefectDojo")
    else:
        print(f"Error: {resp.status_code} — {resp.text[:200]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
