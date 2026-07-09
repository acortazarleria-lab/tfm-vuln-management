#!/usr/bin/env python3
"""
generate-compliance-report.py
Genera informe de cumplimiento ISO 27001 + GDPR
desde el estado real de AWS (no solo declarativo).
Ejecutar mensualmente para evidencia de auditoría.

Uso:
  python3 generate-compliance-report.py \
    --project vuln-mgmt \
    --environment prod \
    --region eu-west-1 \
    --output report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3


def check_control(name: str, checks: list) -> dict:
    results = []
    for check_name, check_fn in checks:
        try:
            passed, detail = check_fn()
            results.append({
                "check": check_name,
                "passed": passed,
                "detail": detail
            })
        except Exception as e:
            results.append({
                "check": check_name,
                "passed": False,
                "detail": f"Error: {e}"
            })

    all_passed = all(r['passed'] for r in results)
    return {
        "control": name,
        "status": "COMPLIANT" if all_passed else "NON-COMPLIANT",
        "checks": results,
        "checked_at": datetime.now(timezone.utc).isoformat()
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', required=True)
    parser.add_argument('--environment', required=True)
    parser.add_argument('--region', default='eu-west-1')
    parser.add_argument('--output', default='compliance-report.json')
    args = parser.parse_args()

    prefix = f"{args.project}-{args.environment}"

    ec2 = boto3.client('ec2', region_name=args.region)
    rds = boto3.client('rds', region_name=args.region)
    s3 = boto3.client('s3', region_name=args.region)
    kms = boto3.client('kms', region_name=args.region)
    trail = boto3.client('cloudtrail', region_name=args.region)
    gd = boto3.client('guardduty', region_name=args.region)
    cfg = boto3.client('config', region_name=args.region)
    elbv2 = boto3.client('elbv2', region_name=args.region)

    print(f"Generando informe compliance: {prefix}")
    print(f"Fecha: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    controls = []

    # ── A.10.1.1: Cifrado en reposo ────────────────────────
    def check_rds_encrypted():
        instances = rds.describe_db_instances(
            Filters=[{'Name': 'db-instance-id', 'Values': [f"{prefix}-rds"]}]
        )['DBInstances']
        if not instances:
            return False, "Instancia RDS no encontrada"
        enc = instances[0]['StorageEncrypted']
        return enc, f"RDS StorageEncrypted={enc}"

    def check_ebs_encrypted():
        vols = ec2.describe_volumes(
            Filters=[
                {'Name': 'tag:Project', 'Values': [args.project]},
                {'Name': 'tag:Environment', 'Values': [args.environment]}
            ]
        )['Volumes']
        unencrypted = [v['VolumeId'] for v in vols if not v['Encrypted']]
        return not unencrypted, f"Volúmenes sin cifrar: {unencrypted or 'ninguno'}"

    def check_s3_encrypted():
        buckets = s3.list_buckets()['Buckets']
        project_buckets = [b for b in buckets if prefix in b['Name']]
        unencrypted = []
        for b in project_buckets:
            try:
                enc = s3.get_bucket_encryption(Bucket=b['Name'])
                rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if not rules:
                    unencrypted.append(b['Name'])
            except s3.exceptions.ClientError:
                unencrypted.append(b['Name'])
        return not unencrypted, f"Buckets sin SSE: {unencrypted or 'ninguno'}"

    controls.append(check_control("A.10.1.1 Cifrado en reposo", [
        ("RDS encrypted", check_rds_encrypted),
        ("EBS encrypted", check_ebs_encrypted),
        ("S3 SSE-KMS", check_s3_encrypted)
    ]))

    # ── A.10.1.2: Rotación de claves ───────────────────────
    def check_kms_rotation():
        aliases = kms.list_aliases()['Aliases']
        project_keys = [a for a in aliases if args.project in a.get('AliasName', '')]
        no_rotation = []
        for alias in project_keys:
            key_id = alias.get('TargetKeyId')
            if key_id:
                status = kms.get_key_rotation_status(KeyId=key_id)
                if not status.get('KeyRotationEnabled'):
                    no_rotation.append(alias['AliasName'])
        return not no_rotation, f"Keys sin rotación: {no_rotation or 'ninguna'}"

    controls.append(check_control("A.10.1.2 Gestión claves", [
        ("KMS key rotation", check_kms_rotation)
    ]))

    # ── A.12.3.1: Backup ──────────────────────────────────
    def check_rds_backup():
        instances = rds.describe_db_instances(
            Filters=[{'Name': 'db-instance-id', 'Values': [f"{prefix}-rds"]}]
        )['DBInstances']
        if not instances:
            return False, "RDS no encontrado"
        ret = instances[0]['BackupRetentionPeriod']
        return ret >= 30, f"Retención backup: {ret} días (mínimo 30)"

    controls.append(check_control("A.12.3.1 Backup información", [
        ("RDS backup 30d", check_rds_backup)
    ]))

    # ── A.12.4.1: Logging ─────────────────────────────────
    def check_cloudtrail():
        trails = trail.describe_trails(includeShadowTrails=False)['trailList']
        project_trails = [t for t in trails if args.project in t.get('Name', '')]
        if not project_trails:
            return False, "CloudTrail no encontrado"
        status = trail.get_trail_status(Name=project_trails[0]['TrailARN'])
        return status.get('IsLogging', False), f"CloudTrail IsLogging={status.get('IsLogging')}"

    def check_guardduty():
        detectors = gd.list_detectors()['DetectorIds']
        if not detectors:
            return False, "GuardDuty no habilitado"
        det = gd.get_detector(DetectorId=detectors[0])
        return det.get('Status') == 'ENABLED', f"GuardDuty Status={det.get('Status')}"

    controls.append(check_control("A.12.4.1 Registro eventos", [
        ("CloudTrail habilitado", check_cloudtrail),
        ("GuardDuty habilitado", check_guardduty)
    ]))

    # ── A.13.1.1: Controles de red ─────────────────────────
    def check_alb_internal():
        lbs = elbv2.describe_load_balancers()['LoadBalancers']
        project_lbs = [lb for lb in lbs if args.project in lb.get('LoadBalancerName', '')]
        if not project_lbs:
            return False, "ALB no encontrado"
        scheme = project_lbs[0]['Scheme']
        return scheme == 'internal', f"ALB Scheme={scheme}"

    controls.append(check_control("A.13.1.1 Controles de red", [
        ("ALB internal scheme", check_alb_internal)
    ]))

    # ── A.18.2.2: AWS Config compliance ───────────────────
    def check_config_rules():
        rules = cfg.describe_config_rules()['ConfigRules']
        project_rules = [r for r in rules if args.project in r.get('ConfigRuleName', '')]
        compliant = 0
        non_compliant = []
        for rule in project_rules:
            compliance = cfg.describe_compliance_by_config_rule(
                ConfigRuleNames=[rule['ConfigRuleName']]
            )['ComplianceByConfigRules']
            for c in compliance:
                if c.get('Compliance', {}).get('ComplianceType') == 'COMPLIANT':
                    compliant += 1
                else:
                    non_compliant.append(rule['ConfigRuleName'])

        return not non_compliant, f"Reglas OK: {compliant} | NOK: {non_compliant or 'ninguna'}"

    controls.append(check_control("A.18.2.2 Cumplimiento políticas", [
        ("AWS Config rules", check_config_rules)
    ]))

    total = len(controls)
    compliant = sum(1 for c in controls if c['status'] == 'COMPLIANT')

    report = {
        "project": args.project,
        "environment": args.environment,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework": "ISO 27001:2022 + GDPR",
        "summary": {
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": total - compliant,
            "compliance_rate": f"{(compliant/total*100):.1f}%"
        },
        "controls": controls
    }

    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*50}")
    print(f"INFORME COMPLIANCE: {report['summary']['compliance_rate']}")
    print(f"  Controles OK:  {compliant}/{total}")
    print(f"  No conformes:  {total - compliant}")
    for c in controls:
        status_label = "OK" if c['status'] == 'COMPLIANT' else "NOK"
        print(f"  [{status_label}] {c['control']}")
    print(f"{'='*50}")
    print(f"Informe guardado en: {args.output}")

    sys.exit(0 if total == compliant else 1)


if __name__ == "__main__":
    main()
