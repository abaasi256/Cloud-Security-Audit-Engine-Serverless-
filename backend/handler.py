"""
handler.py

AWS Lambda entry point for the Cloud Security Audit Engine.
Orchestrates all scanner modules, feeds findings through the risk engine,
persists the completed report to DynamoDB, and returns a structured response
for API Gateway or EventBridge invocations.

Expected event shapes:
  - EventBridge: {} (scheduled full scan)
  - API Gateway: { "scanners": ["iam", "s3"] }  (ad-hoc partial scan)
  - Direct invocation: { "simulate_abuse": false } (flag overrides)
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from scanners.iam_scanner import IAMScanner
from scanners.api_scanner import APIScanner
from scanners.s3_scanner import S3Scanner
from scanners.lambda_scanner import LambdaScanner
from risk_engine import RiskEngine

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# DynamoDB table name is injected via environment variable at deploy time
FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'cloud-security-findings')
ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', 'unknown')

AVAILABLE_SCANNERS = {'iam', 'api', 's3', 'lambda'}


def _get_dynamodb():
    return boto3.resource('dynamodb')


def _parse_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    API Gateway wraps the body as a JSON string; EventBridge sends raw dicts.
    Normalize both into a single config dict.
    """
    if 'body' in event and isinstance(event['body'], str):
        try:
            body = json.loads(event['body'])
        except json.JSONDecodeError:
            body = {}
        return body
    return event


def _run_scanners(config: Dict[str, Any], session: boto3.Session) -> List[Dict[str, Any]]:
    requested = set(config.get('scanners', list(AVAILABLE_SCANNERS)))
    requested = requested.intersection(AVAILABLE_SCANNERS)
    simulate = config.get('simulate_abuse', True)

    all_raw_findings: List[Dict[str, Any]] = []

    if 'iam' in requested:
        logger.info("Running IAM scanner...")
        try:
            findings = IAMScanner(session=session).run_scan()
            all_raw_findings.extend(findings)
            logger.info(f"IAM scanner: {len(findings)} raw findings.")
        except Exception as e:
            logger.error(f"IAM scanner failed: {e}")

    if 'api' in requested:
        logger.info("Running API scanner...")
        try:
            findings = APIScanner(session=session, simulate_abuse=simulate).run_scan()
            all_raw_findings.extend(findings)
            logger.info(f"API scanner: {len(findings)} raw findings.")
        except Exception as e:
            logger.error(f"API scanner failed: {e}")

    if 's3' in requested:
        logger.info("Running S3 scanner...")
        try:
            findings = S3Scanner(session=session).run_scan()
            all_raw_findings.extend(findings)
            logger.info(f"S3 scanner: {len(findings)} raw findings.")
        except Exception as e:
            logger.error(f"S3 scanner failed: {e}")

    if 'lambda' in requested:
        logger.info("Running Lambda scanner...")
        try:
            findings = LambdaScanner(session=session).run_scan()
            all_raw_findings.extend(findings)
            logger.info(f"Lambda scanner: {len(findings)} raw findings.")
        except Exception as e:
            logger.error(f"Lambda scanner failed: {e}")

    return all_raw_findings


def _persist_report(report: Dict[str, Any]) -> bool:
    """Writes the full report to DynamoDB. Returns True on success."""
    try:
        table = _get_dynamodb().Table(FINDINGS_TABLE)
        # DynamoDB requires Decimal for floats in some SDKs;
        # we serialise the findings list as a JSON string to avoid type conversion complexity
        item = {
            'scan_id': report['scan_id'],
            'scanned_at': report['scanned_at'],
            'account_id': report['account_id'],
            'overall_risk_score': str(report['overall_risk_score']),
            'overall_severity': report['overall_severity'],
            'total_findings': report['total_findings'],
            'findings_by_severity': {k: str(v) for k, v in report['findings_by_severity'].items()},
            'findings_by_scanner': {k: str(v) for k, v in report.get('findings_by_scanner', {}).items()},
            'findings_json': json.dumps(report['findings']),
            'ttl': int((datetime.now(timezone.utc).timestamp()) + (90 * 86400))  # 90-day TTL
        }
        table.put_item(Item=item)
        logger.info(f"Report {report['scan_id']} persisted to DynamoDB.")
        return True
    except ClientError as e:
        logger.error(f"Failed to persist report to DynamoDB: {e}")
        return False


def _build_response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'X-Scanner': 'CloudSecAuditEngine/1.0'
        },
        'body': json.dumps(body, default=str)
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info(f"Scan invoked. RequestId: {context.aws_request_id if context else 'local'}")

    config = _parse_event(event)
    scan_id = f"SCAN-{str(uuid.uuid4())[:12].upper()}"
    session = boto3.session.Session()

    try:
        raw_findings = _run_scanners(config, session)

        engine = RiskEngine()
        scored_findings = engine.aggregate(raw_findings)
        report = engine.build_report(scored_findings, scan_id=scan_id, account_id=ACCOUNT_ID)

        persisted = _persist_report(report)

        response_body = {
            "scan_id": scan_id,
            "overall_risk_score": report['overall_risk_score'],
            "overall_severity": report['overall_severity'],
            "total_findings": report['total_findings'],
            "findings_by_severity": report['findings_by_severity'],
            "persisted_to_dynamodb": persisted,
            "findings": report['findings']
        }

        logger.info(
            f"Scan {scan_id} completed. Score: {report['overall_risk_score']} "
            f"({report['overall_severity']}). Findings: {report['total_findings']}. "
            f"CRITICAL: {report['findings_by_severity'].get('CRITICAL', 0)}."
        )

        return _build_response(200, response_body)

    except Exception as e:
        logger.exception(f"Unhandled error in scan execution: {e}")
        return _build_response(500, {
            "error": "Scan execution failed",
            "scan_id": scan_id,
            "detail": str(e)
        })
