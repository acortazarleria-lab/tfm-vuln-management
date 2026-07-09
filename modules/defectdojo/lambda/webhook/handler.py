# ============================================================
# webhook/handler.py — Lambda Webhook Receiver
# Trigger: API Gateway → recibe notificaciones DefectDojo
# Acciones según tipo de evento:
#   - NEW_FINDING crítico/alto → SNS inmediato
#   - SLA_BREACH → escalar a email
#   - FINDING_CLOSED → actualizar métricas
# ISO 27001: A.16.1.1 / A.16.1.2 — gestión y notificación
#            de eventos de seguridad
# ============================================================

import json
import os
import logging
import hmac
import hashlib
from datetime import datetime, timezone

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

REGION         = os.environ.get('AWS_REGION', 'eu-west-1')
SNS_ARN        = os.environ['SNS_ALERTS_ARN']
CW_NAMESPACE   = os.environ.get('CW_NAMESPACE', 'VulnMgmt/DefectDojo')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')
PROJECT        = os.environ.get('PROJECT', 'vuln-mgmt')
ENVIRONMENT    = os.environ.get('ENVIRONMENT', 'prod')

sns = boto3.client('sns', region_name=REGION)
cw  = boto3.client('cloudwatch', region_name=REGION)


def verify_signature(body: str, signature: str) -> bool:
    """Verificar firma HMAC del webhook DefectDojo"""
    if not WEBHOOK_SECRET:
        return True

    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature)


def format_finding_message(finding: dict, event_type: str) -> str:
    severity = finding.get('severity', 'Unknown')
    title    = finding.get('title', 'Sin título')[:100]
    product  = finding.get('product_name', 'Desconocido')
    cve      = finding.get('cve', 'N/A')
    fid      = finding.get('id', 'N/A')

    event_labels = {
        "NEW_FINDING":    "Nuevo finding",
        "SLA_BREACH":     "SLA VENCIDO",
        "FINDING_CLOSED": "Finding cerrado"
    }

    return f"""{event_labels.get(event_type, event_type)}

Severidad:  {severity}
Título:     {title}
Producto:   {product}
CVE:        {cve}
Finding ID: {fid}
Entorno:    {ENVIRONMENT}
Timestamp:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

Gestionar: {os.environ.get('DEFECTDOJO_URL', '')}/finding/{fid}
"""


def publish_metric(name: str, value: float, dims: list):
    cw.put_metric_data(
        Namespace  = CW_NAMESPACE,
        MetricData = [{
            "MetricName": name,
            "Timestamp":  datetime.utcnow(),
            "Value":      value,
            "Unit":       "Count",
            "Dimensions": dims + [
                {"Name": "Environment", "Value": ENVIRONMENT},
                {"Name": "Project",     "Value": PROJECT}
            ]
        }]
    )


def handler(event, context):
    log.info("Webhook recibido")

    body      = event.get('body', '{}')
    headers   = event.get('headers', {})
    signature = headers.get('X-DefectDojo-Signature', '')

    if not verify_signature(body, signature):
        log.warning("Firma webhook inválida — rechazando")
        return {"statusCode": 401, "body": "Unauthorized"}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {"statusCode": 400, "body": "Invalid JSON"}

    event_type = payload.get('type', 'UNKNOWN')
    finding    = payload.get('finding', {})
    severity   = finding.get('severity', 'Info')

    log.info(f"Evento: {event_type} | Severidad: {severity}")

    dims = [{"Name": "Severity", "Value": severity}]

    if event_type == 'NEW_FINDING' and severity in ['Critical', 'High']:
        msg = format_finding_message(finding, event_type)

        sns.publish(
            TopicArn = SNS_ARN,
            Subject  = f"[{severity}] Nuevo finding DefectDojo — {finding.get('product_name', '')}",
            Message  = msg
        )

        publish_metric("WebhookNewFinding", 1, dims)
        log.info(f"Alerta SNS enviada: finding {finding.get('id')}")

    elif event_type == 'SLA_BREACH':
        msg = format_finding_message(finding, event_type)
        msg += f"\nSLA vencido hace {abs(finding.get('sla_days_remaining', 0))} días"

        sns.publish(
            TopicArn = SNS_ARN,
            Subject  = f"[SLA BREACH] {severity} finding sin remediar — {finding.get('product_name', '')}",
            Message  = msg
        )

        publish_metric("WebhookSLABreach", 1, dims)
        log.warning(f"SLA breach notificado: finding {finding.get('id')}")

    elif event_type == 'FINDING_CLOSED':
        publish_metric("WebhookFindingClosed", 1, dims)
        log.info(f"Finding cerrado registrado: {finding.get('id')}")

    else:
        log.info(f"Evento {event_type} recibido — sin acción configurada")

    return {
        "statusCode": 200,
        "body":       json.dumps({"status": "processed", "event": event_type})
    }
