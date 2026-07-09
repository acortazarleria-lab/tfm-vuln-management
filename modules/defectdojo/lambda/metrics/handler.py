# ============================================================
# handler.py — Lambda Métricas DefectDojo
# Trigger: EventBridge cada hora
# Publica métricas custom en CloudWatch: findings por
# severidad, categoría, SLA vencido y duplicados
# ISO 27001: A.12.4.1 — registro y monitorización
# ============================================================

import json
import os
import logging
from datetime import datetime, timedelta

import boto3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger()
log.setLevel(logging.INFO)

REGION       = os.environ.get('AWS_REGION', 'eu-west-1')
DD_SECRET    = os.environ['DD_SECRET_ARN']
DD_BASE_URL  = os.environ['DD_BASE_URL']
CW_NAMESPACE = os.environ['CW_NAMESPACE']
ENVIRONMENT  = os.environ['ENVIRONMENT']
PROJECT      = os.environ['PROJECT']

secrets = boto3.client('secretsmanager', region_name=REGION)
cw      = boto3.client('cloudwatch',     region_name=REGION)


def get_dd_token() -> str:
    resp = secrets.get_secret_value(SecretId=DD_SECRET)
    return json.loads(resp['SecretString'])['api_key']


def make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Token {token}",
        "Content-Type":  "application/json"
    })
    retry = Retry(total=3, backoff_factor=1,
                  status_forcelist=[429, 500, 502, 503])
    s.mount('http://', HTTPAdapter(max_retries=retry))
    return s


def get_findings_count(session: requests.Session, params: dict) -> int:
    resp = session.get(
        f"{DD_BASE_URL}/api/v2/findings/",
        params={**params, "limit": 1},
        timeout=15
    )
    resp.raise_for_status()
    return resp.json().get('count', 0)


def publish_metrics(metrics: list):
    for i in range(0, len(metrics), 20):
        cw.put_metric_data(
            Namespace  = CW_NAMESPACE,
            MetricData = metrics[i:i + 20]
        )
    log.info(f"Publicadas {len(metrics)} métricas en {CW_NAMESPACE}")


def handler(event, context):
    log.info("Iniciando publicación métricas DefectDojo")

    token   = get_dd_token()
    session = make_session(token)
    now     = datetime.utcnow()
    metrics = []

    def metric(name: str, value: float, dims: list, unit="Count") -> dict:
        return {
            "MetricName": name,
            "Timestamp":  now,
            "Value":      float(value),
            "Unit":       unit,
            "Dimensions": dims + [
                {"Name": "Environment", "Value": ENVIRONMENT},
                {"Name": "Project",     "Value": PROJECT}
            ]
        }

    severities = ["Critical", "High", "Medium", "Low", "Info"]

    for severity in severities:
        count_active = get_findings_count(session, {
            "severity": severity,
            "active":   True,
            "false_p":  False
        })
        metrics.append(metric(
            "ActiveFindings", count_active,
            [{"Name": "Severity", "Value": severity}]
        ))

        count_closed = get_findings_count(session, {
            "severity": severity,
            "active":   False,
            "mitigated__date__gte": now.strftime('%Y-%m-%d')
        })
        metrics.append(metric(
            "ClosedFindingsToday", count_closed,
            [{"Name": "Severity", "Value": severity}]
        ))

    categories = {
        "SAST":            "SAST - Análisis Estático",
        "DAST":            "DAST - Análisis Dinámico",
        "SCA":             "SCA - Dependencias",
        "Infraestructura": "Infraestructura - IaC y Cloud",
        "Runtime":         "Código y Servicios - Runtime"
    }

    for cat_key, product_name in categories.items():
        resp = session.get(
            f"{DD_BASE_URL}/api/v2/products/",
            params={"name": product_name, "limit": 1},
            timeout=10
        )
        products = resp.json().get('results', [])
        if not products:
            continue

        product_id = products[0]['id']

        for severity in ["Critical", "High"]:
            count = get_findings_count(session, {
                "product_id": product_id,
                "severity":   severity,
                "active":     True
            })
            metrics.append(metric(
                "ActiveFindingsByCategory", count,
                [
                    {"Name": "Category", "Value": cat_key},
                    {"Name": "Severity", "Value": severity}
                ]
            ))

    total_active = get_findings_count(session, {
        "active":  True,
        "false_p": False
    })
    metrics.append(metric("TotalActiveFindings", total_active, []))

    sla_date_critical = (now - timedelta(days=30)).strftime('%Y-%m-%d')
    overdue_critical = get_findings_count(session, {
        "active":    True,
        "severity":  "Critical",
        "date__lte": sla_date_critical,
        "false_p":   False
    })
    metrics.append(metric("OverdueCriticalFindings", overdue_critical, []))

    sla_date_high = (now - timedelta(days=60)).strftime('%Y-%m-%d')
    overdue_high = get_findings_count(session, {
        "active":    True,
        "severity":  "High",
        "date__lte": sla_date_high,
        "false_p":   False
    })
    metrics.append(metric("OverdueHighFindings", overdue_high, []))

    total_dupes = get_findings_count(session, {"duplicate": True})
    metrics.append(metric("DuplicateFindings", total_dupes, []))

    publish_metrics(metrics)

    return {
        "statusCode":    200,
        "total_active":  total_active,
        "metrics_count": len(metrics),
        "timestamp":     now.isoformat()
    }
