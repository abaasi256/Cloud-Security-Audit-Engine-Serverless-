"""
risk_engine.py

Aggregates raw findings from all scanner modules, applies a composite risk
scoring model (Impact × Exploitability × Exposure), deduplicates across scanners,
and emits a structured audit report ready for DynamoDB persistence or direct API response.
"""

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Severity thresholds against which the composite score is classified
SEVERITY_THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   5.0,
    "LOW":      0.0,
}

# Exploitability coefficients per scanner — weighted by how directly actionable
# a misconfiguration in that service is for an active attacker
SCANNER_EXPLOITABILITY = {
    "iam_misconfiguration":    1.0,   # Highest — direct path to account takeover
    "api_exposure":            0.95,  # Very high — externally reachable
    "s3_misconfiguration":     0.90,  # High — data exfiltration vector
    "lambda_misconfiguration": 0.85,  # High — potential code execution
    "unknown":                 0.70,
}

# Exposure coefficients — how broadly the resource surface is reachable
EXPOSURE_SURFACE = {
    "CRITICAL": 1.0,
    "HIGH":     0.85,
    "MEDIUM":   0.65,
    "LOW":      0.40,
}


class RiskEngine:
    """
    Composite risk scoring engine.

    Final Risk Score = base_risk_score × exploitability_coeff × exposure_coeff
    Capped at 10.0, floored at 0.1, rounded to 2dp.

    Also performs:
    - Cross-scanner deduplication (same resource + same issue class)
    - Severity re-classification based on composite score
    - Prioritised summary report generation
    """

    def __init__(self):
        self._processed_fingerprints: set = set()

    def _normalize_score(self, raw: float, exploitability: float, exposure: float) -> float:
        composite = raw * exploitability * exposure
        return round(min(max(composite, 0.1), 10.0), 2)

    def _classify_severity(self, score: float) -> str:
        for severity, threshold in SEVERITY_THRESHOLDS.items():
            if score >= threshold:
                return severity
        return "LOW"

    def _fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Generates a deduplication key. Two findings are considered duplicates when
        they share the same resource ARN AND the same type of issue across any scanner.
        Prevents duplicate alerts when the same misconfiguration is caught by multiple check paths.
        """
        resource = finding.get('resource_arn', '').lower()
        issue = finding.get('issue', '').lower()[:60]
        return f"{resource}::{issue}"

    def process_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        fingerprint = self._fingerprint(finding)
        if fingerprint in self._processed_fingerprints:
            logger.debug(f"Deduplicated finding: {fingerprint}")
            return None
        self._processed_fingerprints.add(fingerprint)

        scanner = finding.get('scanner', 'unknown')
        raw_score = finding.get('risk_score', 5.0)
        raw_severity = finding.get('severity', 'MEDIUM')

        exploitability = SCANNER_EXPLOITABILITY.get(scanner, 0.70)
        exposure = EXPOSURE_SURFACE.get(raw_severity, 0.65)

        composite_score = self._normalize_score(raw_score, exploitability, exposure)
        composite_severity = self._classify_severity(composite_score)

        enriched = finding.copy()
        enriched['risk_score'] = composite_score
        enriched['severity'] = composite_severity
        enriched['risk_model'] = {
            "base_score": raw_score,
            "exploitability_coefficient": exploitability,
            "exposure_coefficient": exposure,
            "formula": f"{raw_score} × {exploitability} × {exposure} = {composite_score}"
        }

        return enriched

    def aggregate(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and deduplicate all findings, returning a priority-sorted list."""
        self._processed_fingerprints.clear()
        processed = []
        for finding in raw_findings:
            result = self.process_finding(finding)
            if result:
                processed.append(result)

        # Sort: CRITICAL first, then descending risk score
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        processed.sort(key=lambda f: (severity_order.get(f['severity'], 4), -f['risk_score']))

        return processed

    def build_report(self, findings: List[Dict[str, Any]], scan_id: str, account_id: str = "unknown") -> Dict[str, Any]:
        """
        Builds the final structured audit report ready for DynamoDB persistence.
        Overall environment risk score is calculated as a weighted mean, biased
        toward high-severity findings.
        """
        if not findings:
            return {
                "scan_id": scan_id,
                "account_id": account_id,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "total_findings": 0,
                "overall_risk_score": 0.0,
                "overall_severity": "PASS",
                "findings_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "findings": []
            }

        severity_counts = defaultdict(int)
        for f in findings:
            severity_counts[f['severity']] += 1

        # Weighted risk score: CRITICAL findings 4x weighted vs LOW findings
        severity_weights = {"CRITICAL": 4.0, "HIGH": 2.5, "MEDIUM": 1.5, "LOW": 1.0}
        weighted_sum = sum(f['risk_score'] * severity_weights.get(f['severity'], 1.0) for f in findings)
        weight_total = sum(severity_weights.get(f['severity'], 1.0) for f in findings)
        overall_score = round(min(weighted_sum / weight_total, 10.0), 1) if weight_total else 0.0
        overall_severity = self._classify_severity(overall_score)

        return {
            "scan_id": scan_id,
            "account_id": account_id,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "overall_risk_score": overall_score,
            "overall_severity": overall_severity,
            "findings_by_severity": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0)
            },
            "findings_by_scanner": self._group_by_scanner(findings),
            "findings": findings
        }

    def _group_by_scanner(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = defaultdict(int)
        for f in findings:
            counts[f.get('scanner', 'unknown')] += 1
        return dict(counts)
