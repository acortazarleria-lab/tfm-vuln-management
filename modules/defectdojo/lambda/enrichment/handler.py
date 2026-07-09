# ============================================================
# handler.py — Lambda Enrichment
# Trigger: EventBridge cada 30min
# Funciones:
#   1. Enriquecer findings con CVSS, EPSS, KEV (CISA)
#   2. Correlacionar findings entre categorías
#   3. Calcular SLA restante y escalar si vence
#   4. Calcular risk score compuesto para priorización
# ISO 27001: A.12.6 — gestión vulnerabilidades técnicas
# ============================================================

import json
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from dataclasses import dataclass

import boto3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger()
log.setLevel(logging.INFO)

# ── Configuración ──────────────────────────────────────────
REGION       = os.environ.get('AWS_REGION', 'eu-west-1')
DD_SECRET    = os.environ['DD_SECRET_ARN']
CW_NAMESPACE = os.environ.get('CW_NAMESPACE', 'VulnMgmt/DefectDojo')
PROJECT      = os.environ.get('PROJECT', 'vuln-mgmt')
ENVIRONMENT  = os.environ.get('ENVIRONMENT', 'prod')

# SLA por severidad (días para remediar)
# ISO 27001: A.12.6.1 — gestión vulnerabilidades técnicas
SLA_DAYS = {
    "Critical": 7,
    "High":     30,
    "Medium":   90,
    "Low":      180,
    "Info":     365
}

secrets = boto3.client('secretsmanager', region_name=REGION)
cw      = boto3.client('cloudwatch',     region_name=REGION)


@dataclass
class FindingEnrichment:
    finding_id:         int
    cvss_v3:            Optional[float]
    epss_score:         Optional[float]
    epss_percentile:    Optional[float]
    in_kev:             bool
    kev_date_added:     Optional[str]
    sla_days_remaining: int
    sla_breached:       bool
    correlated_ids:     list
    risk_score:         float


def get_secret(arn: str) -> dict:
    resp = secrets.get_secret_value(SecretId=arn)
    return json.loads(resp['SecretString'])


def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    s.mount('http://', HTTPAdapter(max_retries=retry))
    s.mount('https://', HTTPAdapter(max_retries=retry))
    return s


# ── EPSS (Exploit Prediction Scoring System) ───────────────
def get_epss(session: requests.Session, cve_id: str) -> dict:
    if not cve_id or not cve_id.startswith('CVE-'):
        return {}

    try:
        resp = session.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_id},
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json().get('data', [])
        if data:
            return {
                "epss":       float(data[0].get('epss', 0)),
                "percentile": float(data[0].get('percentile', 0))
            }
    except Exception as e:
        log.warning(f"EPSS lookup failed for {cve_id}: {e}")

    return {}


# ── CISA KEV (Known Exploited Vulnerabilities) ─────────────
_kev_cache: dict = {}
_kev_loaded: bool = False


def load_kev_catalog(session: requests.Session) -> dict:
    global _kev_cache, _kev_loaded
    if _kev_loaded:
        return _kev_cache

    try:
        resp = session.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15
        )
        resp.raise_for_status()
        catalog = resp.json()
        _kev_cache = {
            v['cveID']: v
            for v in catalog.get('vulnerabilities', [])
        }
        _kev_loaded = True
        log.info(f"KEV catalog cargado: {len(_kev_cache)} entradas")
    except Exception as e:
        log.warning(f"No se pudo cargar KEV catalog: {e}")

    return _kev_cache


def check_kev(cve_id: str, kev_catalog: dict) -> dict:
    if not cve_id:
        return {"in_kev": False}

    entry = kev_catalog.get(cve_id, {})
    return {
        "in_kev":         bool(entry),
        "kev_date":       entry.get('dateAdded', ''),
        "kev_ransomware": entry.get('knownRansomwareCampaignUse', 'Unknown')
    }


def calculate_risk_score(
    cvss:     float,
    epss:     float,
    in_kev:   bool,
    severity: str
) -> float:
    base        = cvss if cvss else 5.0
    epss_factor = 1 + (epss * 2)
    kev_factor  = 1.5 if in_kev else 1.0
    sev_factor  = {
        "Critical": 1.2, "High": 1.0,
        "Medium": 0.8, "Low": 0.5, "Info": 0.2
    }.get(severity, 1.0)

    return round(min(base * epss_factor * kev_factor * sev_factor, 15.0), 2)


def calculate_sla(finding_date_str: str, severity: str) -> dict:
    try:
        finding_date = datetime.fromisoformat(
            finding_date_str.replace('Z', '+00:00')
        )
    except Exception:
        finding_date = datetime.now(timezone.utc)

    sla_limit = SLA_DAYS.get(severity, 90)
    deadline  = finding_date + timedelta(days=sla_limit)
    now       = datetime.now(timezone.utc)
    remaining = (deadline - now).days

    return {
        "sla_days_total":     sla_limit,
        "sla_days_remaining": remaining,
        "sla_deadline":       deadline.isoformat(),
        "sla_breached":       remaining < 0,
        "sla_critical":       0 <= remaining <= 3
    }


def correlate_findings(
    session:    requests.Session,
    dd_headers: dict,
    dd_base:    str,
    finding:    dict
) -> list:
    cve_id = finding.get('cve')
    if not cve_id:
        return []

    try:
        resp = session.get(
            f"{dd_base}/api/v2/findings/",
            headers=dd_headers,
            params={"cve": cve_id, "active": True, "limit": 20},
            timeout=10
        )
        resp.raise_for_status()
        findings = resp.json().get('results', [])

        correlated = [
            {
                "id":           f['id'],
                "product_name": f.get('product_name', ''),
                "severity":     f['severity'],
                "title":        f['title'][:100]
            }
            for f in findings
            if f['id'] != finding['id']
        ]

        if correlated:
            log.info(
                f"Finding {finding['id']} ({cve_id}): "
                f"{len(correlated)} correlaciones encontradas"
            )

        return correlated

    except Exception as e:
        log.warning(f"Correlación fallida para finding {finding.get('id')}: {e}")
        return []


def update_finding_notes(
    session:    requests.Session,
    dd_headers: dict,
    dd_base:    str,
    finding_id: int,
    enrichment: FindingEnrichment
):
    kev_text = ""
    if enrichment.in_kev:
        kev_text = f"""
CISA KEV: Explotación activa confirmada
   Fecha adición KEV: {enrichment.kev_date_added or 'Desconocida'}
"""

    corr_text = ""
    if enrichment.correlated_ids:
        ids  = ', '.join(str(c['id']) for c in enrichment.correlated_ids[:5])
        cats = ', '.join(set(c['product_name'] for c in enrichment.correlated_ids))
        corr_text = f"""
Correlaciones: encontrado en {len(enrichment.correlated_ids)} productos
   IDs relacionados: {ids}
   Categorías: {cats}
"""

    sla_label = "VENCIDO" if enrichment.sla_breached else "En plazo"

    note_text = f"""Enriquecimiento automático — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

Risk Score: {enrichment.risk_score:.2f}/15.00
CVSS v3: {enrichment.cvss_v3 or 'N/A'}
EPSS Score: {enrichment.epss_score if enrichment.epss_score else 'N/A'}
{kev_text}
SLA: {enrichment.sla_days_remaining} días restantes — Estado: {sla_label}
{corr_text}
---
Generado por Lambda enrichment — {PROJECT}/{ENVIRONMENT}
"""

    try:
        session.post(
            f"{dd_base}/api/v2/notes/",
            headers=dd_headers,
            json={"entry": note_text, "note_type": None, "private": False},
            timeout=10
        )

        if enrichment.in_kev and enrichment.sla_breached:
            session.patch(
                f"{dd_base}/api/v2/findings/{finding_id}/",
                headers=dd_headers,
                json={
                    "tags": [
                        "kev", "sla-breached", "high-priority",
                        f"risk-score-{int(enrichment.risk_score)}"
                    ]
                },
                timeout=10
            )

    except Exception as e:
        log.error(f"Error actualizando finding {finding_id}: {e}")


def publish_enrichment_metrics(stats: dict):
    now  = datetime.utcnow()
    dims = [
        {"Name": "Environment", "Value": ENVIRONMENT},
        {"Name": "Project",     "Value": PROJECT}
    ]

    metrics = [
        {
            "MetricName": "EnrichedFindings",
            "Timestamp":  now,
            "Value":      float(stats.get('enriched', 0)),
            "Unit":       "Count",
            "Dimensions": dims
        },
        {
            "MetricName": "KEVFindings",
            "Timestamp":  now,
            "Value":      float(stats.get('kev_count', 0)),
            "Unit":       "Count",
            "Dimensions": dims
        },
        {
            "MetricName": "SLABreachedFindings",
            "Timestamp":  now,
            "Value":      float(stats.get('sla_breached', 0)),
            "Unit":       "Count",
            "Dimensions": dims
        },
        {
            "MetricName": "CorrelatedFindings",
            "Timestamp":  now,
            "Value":      float(stats.get('correlated', 0)),
            "Unit":       "Count",
            "Dimensions": dims
        }
    ]

    cw.put_metric_data(Namespace=CW_NAMESPACE, MetricData=metrics)
    log.info(f"Métricas enriquecimiento publicadas: {stats}")


def handler(event, context):
    log.info(f"Enrichment Lambda iniciado | event: {event.get('source', 'manual')}")

    dd_creds    = get_secret(DD_SECRET)
    DD_TOKEN    = dd_creds['api_key']
    DD_BASE_URL = dd_creds['base_url']
    DD_HEADERS  = {
        "Authorization": f"Token {DD_TOKEN}",
        "Content-Type":  "application/json"
    }

    session     = make_session()
    kev_catalog = load_kev_catalog(session)

    resp = session.get(
        f"{DD_BASE_URL}/api/v2/findings/",
        headers=DD_HEADERS,
        params={
            "active":   True,
            "severity": ["Critical", "High"],
            "limit":    50,
            "ordering": "-date",
            "tags":     "!enriched"
        },
        timeout=30
    )
    resp.raise_for_status()
    findings = resp.json().get('results', [])

    log.info(f"Findings pendientes de enriquecimiento: {len(findings)}")

    stats = {
        "enriched":     0,
        "kev_count":    0,
        "sla_breached": 0,
        "correlated":   0,
        "errors":       0
    }

    for finding in findings:
        fid      = finding['id']
        cve_id   = finding.get('cve', '')
        severity = finding['severity']
        cvss     = finding.get('cvssv3_score') or finding.get('cvssv2_score')

        try:
            epss_data = get_epss(session, cve_id)
            epss      = epss_data.get('epss', 0.0)
            epss_pct  = epss_data.get('percentile', 0.0)

            kev_data = check_kev(cve_id, kev_catalog)
            in_kev   = kev_data.get('in_kev', False)

            sla_data = calculate_sla(
                finding.get('date', datetime.now(timezone.utc).isoformat()),
                severity
            )

            risk_score = calculate_risk_score(
                float(cvss) if cvss else 5.0, epss, in_kev, severity
            )

            correlated = correlate_findings(
                session, DD_HEADERS, DD_BASE_URL, finding
            )

            enrichment = FindingEnrichment(
                finding_id         = fid,
                cvss_v3            = float(cvss) if cvss else None,
                epss_score         = epss,
                epss_percentile    = epss_pct,
                in_kev             = in_kev,
                kev_date_added     = kev_data.get('kev_date'),
                sla_days_remaining = sla_data['sla_days_remaining'],
                sla_breached       = sla_data['sla_breached'],
                correlated_ids     = correlated,
                risk_score         = risk_score
            )

            update_finding_notes(
                session, DD_HEADERS, DD_BASE_URL, fid, enrichment
            )

            session.patch(
                f"{DD_BASE_URL}/api/v2/findings/{fid}/",
                headers=DD_HEADERS,
                json={"tags": finding.get('tags', []) + ["enriched"]},
                timeout=10
            )

            stats['enriched']     += 1
            stats['kev_count']    += 1 if in_kev else 0
            stats['sla_breached'] += 1 if sla_data['sla_breached'] else 0
            stats['correlated']   += 1 if correlated else 0

            log.info(
                f"Finding {fid} ({cve_id}): "
                f"EPSS={epss:.3f} KEV={in_kev} "
                f"SLA={sla_data['sla_days_remaining']}d "
                f"Score={risk_score}"
            )

        except Exception as e:
            log.error(f"Error enriqueciendo finding {fid}: {e}")
            stats['errors'] += 1
            continue

    publish_enrichment_metrics(stats)

    return {
        "statusCode": 200,
        "stats":      stats,
        "timestamp":  datetime.utcnow().isoformat()
    }
