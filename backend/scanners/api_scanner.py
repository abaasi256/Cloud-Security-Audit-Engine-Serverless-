"""
api_scanner.py

Detects API Gateway misconfigurations: unauthenticated endpoints, missing WAF
coverage, absent usage plans, and validates findings via active abuse simulation.
All network probes are strictly rate-limited and bounded by configurable thresholds
to ensure the scanner cannot be misused as an actual DoS tool.
"""

import json
import logging
import random
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import boto3
import urllib.request
import urllib.error
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Active simulation constants — intentionally conservative
RATE_LIMIT_PROBE_REQUESTS = 25   # Max requests sent per endpoint probe
RATE_LIMIT_PROBE_RPS = 10        # Requests per second ceiling
PROBE_TIMEOUT_SECONDS = 3        # Per-request timeout


class APIScanner:
    """
    Scans REST API Gateway deployments for authentication gaps, missing WAF
    associations, absent rate limiting, and validates exploitability with
    controlled live probes against the caller's own endpoints.
    """

    def __init__(self, session: boto3.Session = None, simulate_abuse: bool = True):
        sess = session or boto3.session.Session()
        self.apigw = sess.client('apigateway')
        self.wafv2 = sess.client('wafv2', region_name='us-east-1')
        self.region = sess.region_name or 'us-east-1'
        self.simulate_abuse = simulate_abuse

    # ─── Discovery ────────────────────────────────────────────────────────────

    def get_all_rest_apis(self) -> List[Dict[str, Any]]:
        apis = []
        try:
            paginator = self.apigw.get_paginator('get_rest_apis')
            for page in paginator.paginate():
                apis.extend(page.get('items', []))
        except ClientError as e:
            logger.error(f"Failed to list REST APIs: {e}")
        return apis

    def get_stages(self, api_id: str) -> List[Dict[str, Any]]:
        try:
            response = self.apigw.get_stages(restApiId=api_id)
            return response.get('item', [])
        except ClientError as e:
            logger.error(f"Failed to get stages for API {api_id}: {e}")
            return []

    def get_resources(self, api_id: str) -> List[Dict[str, Any]]:
        resources = []
        try:
            paginator = self.apigw.get_paginator('get_resources')
            for page in paginator.paginate(restApiId=api_id, embed=['methods']):
                resources.extend(page.get('items', []))
        except ClientError as e:
            logger.error(f"Failed to list resources for API {api_id}: {e}")
        return resources

    def get_usage_plans_for_stage(self, api_id: str, stage_name: str) -> List[Dict[str, Any]]:
        try:
            response = self.apigw.get_usage_plans(keyId='')
        except ClientError:
            pass

        plans = []
        try:
            paginator = self.apigw.get_paginator('get_usage_plans')
            for page in paginator.paginate():
                for plan in page.get('items', []):
                    for api_stage in plan.get('apiStages', []):
                        if api_stage.get('apiId') == api_id and api_stage.get('stage') == stage_name:
                            plans.append(plan)
        except ClientError as e:
            logger.error(f"Failed to get usage plans: {e}")
        return plans

    def get_waf_associations(self) -> List[str]:
        """Returns a set of API Gateway stage ARNs currently protected by WAFv2."""
        protected_arns = []
        try:
            paginator = self.wafv2.get_paginator('list_web_acls')
            for page in paginator.paginate(Scope='REGIONAL'):
                for acl in page.get('WebACLs', []):
                    acl_arn = acl['ARN']
                    try:
                        resources = self.wafv2.list_resources_for_web_acl(
                            WebACLArn=acl_arn,
                            ResourceType='API_GATEWAY'
                        )
                        protected_arns.extend(resources.get('ResourceArns', []))
                    except ClientError:
                        continue
        except ClientError as e:
            logger.error(f"Failed to query WAFv2: {e}")
        return protected_arns

    # ─── Analysis ─────────────────────────────────────────────────────────────

    def _build_stage_invoke_url(self, api_id: str, stage_name: str) -> str:
        return f"https://{api_id}.execute-api.{self.region}.amazonaws.com/{stage_name}"

    def _check_auth_on_resource(self, resource: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Returns (has_unauth_method, list_of_unauthenticated_http_methods)."""
        unauth_methods = []
        for method_name, method_info in resource.get('resourceMethods', {}).items():
            if method_name == 'OPTIONS':
                continue
            auth_type = method_info.get('authorizationType', 'NONE')
            api_key_required = method_info.get('apiKeyRequired', False)
            if auth_type == 'NONE' and not api_key_required:
                unauth_methods.append(method_name)
        return bool(unauth_methods), unauth_methods

    @staticmethod
    def _random_ip() -> str:
        """Generates a plausible public IPv4 address for X-Forwarded-For header rotation."""
        # Avoid RFC1918 private ranges to simulate realistic external attacker IPs
        while True:
            octets = [random.randint(1, 254) for _ in range(4)]
            if octets[0] not in (10, 127, 172, 192):
                return '.'.join(map(str, octets))

    @staticmethod
    def _random_user_agent() -> str:
        """Rotates User-Agent strings to simulate bot tooling that evades string-match WAF rules."""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'python-requests/2.31.0',
            'curl/7.88.1',
            'Go-http-client/1.1',
            'Apache-HttpClient/4.5.13',
        ]
        return random.choice(agents)

    def _send_probe_request(self, invoke_url: str, headers: Dict[str, str]) -> int:
        """Fires a single probe request and returns the HTTP status code. Returns -1 on network error."""
        try:
            req = urllib.request.Request(invoke_url, method='GET')
            for key, value in headers.items():
                req.add_header(key, value)
            with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT_SECONDS) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return -1

    def _simulate_rate_limit(self, invoke_url: str) -> Dict[str, Any]:
        """
        Sends a bounded burst of requests using a fixed identity to measure whether
        the API Gateway throttles or WAF blocks traffic from a single consistent source.
        This establishes the baseline enforcement posture.
        """
        success_count = 0
        throttled_count = 0
        interval = 1.0 / RATE_LIMIT_PROBE_RPS
        fixed_headers = {'User-Agent': 'CloudSecAuditEngine/1.0'}

        for _ in range(RATE_LIMIT_PROBE_REQUESTS):
            status = self._send_probe_request(invoke_url, fixed_headers)
            if status in (429, 403):
                throttled_count += 1
            elif status != -1:
                success_count += 1
            time.sleep(interval)

        rate_limit_effective = throttled_count >= (RATE_LIMIT_PROBE_REQUESTS * 0.5)
        return {
            "probe_requests": RATE_LIMIT_PROBE_REQUESTS,
            "passed_through": success_count,
            "throttled_or_blocked": throttled_count,
            "rate_limit_effective": rate_limit_effective
        }

    def _simulate_header_bypass(self, invoke_url: str) -> Dict[str, Any]:
        """
        Tests whether IP-based rate limiting can be circumvented by rotating
        X-Forwarded-For source IPs and varying User-Agent strings — a standard
        technique used by automated attack tooling (e.g., sqlmap, nuclei, custom bots).

        A WAF relying solely on IP-based rules without identity-level throttling
        (API keys / JWT claims) will be fully bypassed by this technique.
        """
        bypass_success = 0
        blocked = 0
        # Use fewer requests than the baseline probe — just enough to confirm bypass
        probe_count = min(15, RATE_LIMIT_PROBE_REQUESTS)
        interval = 1.0 / RATE_LIMIT_PROBE_RPS

        for _ in range(probe_count):
            spoofed_headers = {
                'X-Forwarded-For': self._random_ip(),
                'X-Real-IP': self._random_ip(),
                'User-Agent': self._random_user_agent(),
            }
            status = self._send_probe_request(invoke_url, spoofed_headers)
            if status in (429, 403):
                blocked += 1
            elif status != -1:
                bypass_success += 1
            time.sleep(interval)

        bypass_effective = bypass_success > (probe_count * 0.5)
        return {
            "probe_count": probe_count,
            "bypass_successful_requests": bypass_success,
            "blocked_requests": blocked,
            "bypass_confirmed": bypass_effective
        }

    def analyze_api(self, api: Dict[str, Any], protected_stage_arns: List[str]) -> List[Dict[str, Any]]:
        findings = []
        api_id = api['id']
        api_name = api.get('name', api_id)

        stages = self.get_stages(api_id)
        resources = self.get_resources(api_id)

        for stage in stages:
            stage_name = stage['stageName']
            stage_arn = f"arn:aws:apigateway:{self.region}::/restapis/{api_id}/stages/{stage_name}"
            invoke_url = self._build_stage_invoke_url(api_id, stage_name)

            waf_protected = any(stage_arn in arn or arn.endswith(f"/{stage_name}") for arn in protected_stage_arns)
            usage_plans = self.get_usage_plans_for_stage(api_id, stage_name)
            has_rate_limiting = bool(usage_plans)

            # --- Missing WAF ---
            if not waf_protected:
                findings.append(self._generate_finding(
                    resource_arn=stage_arn,
                    severity="HIGH",
                    risk_score=8.2,
                    issue="API Stage Not Protected by WAF",
                    details=f"Stage '{stage_name}' on API '{api_name}' has no WAFv2 Web ACL association. The stage is fully exposed to volumetric attacks, SQL injection, and OWASP Top 10 exploits.",
                    action="Associate a WAFv2 Web ACL with IP rate-based and managed rule groups.",
                    recommendation="Use aws wafv2 associate-web-acl to attach a Web ACL with AWSManagedRulesCommonRuleSet and a rate-based rule."
                ))

            # --- Missing Rate Limiting / Usage Plan ---
            if not has_rate_limiting:
                findings.append(self._generate_finding(
                    resource_arn=stage_arn,
                    severity="MEDIUM",
                    risk_score=6.5,
                    issue="No Rate Limiting Configured on API Stage",
                    details=f"Stage '{stage_name}' on API '{api_name}' has no Usage Plan attached. Without throttling, the API is vulnerable to logic abuse and uncontrolled cost amplification.",
                    action="Create and associate an API Gateway Usage Plan with throttle limits.",
                    recommendation="Set a Usage Plan with rate: 100 req/s, burst: 200, and link an API Key for audit traceability."
                ))

            # --- Per-resource auth analysis ---
            for resource in resources:
                has_unauth, unauth_methods = self._check_auth_on_resource(resource)
                if has_unauth:
                    path = resource.get('path', '/')
                    resource_arn = f"arn:aws:apigateway:{self.region}::/restapis/{api_id}/resources/{resource['id']}"
                    findings.append(self._generate_finding(
                        resource_arn=resource_arn,
                        severity="CRITICAL",
                        risk_score=9.2,
                        issue="Public API Resource with No Authentication",
                        details=(
                            f"Path '{path}' on API '{api_name}' ({stage_name}) accepts "
                            f"{', '.join(unauth_methods)} without any authorizationType or apiKeyRequired. "
                            f"Any unauthenticated actor can invoke this endpoint."
                        ),
                        action=f"Configure an authorizer on the {', '.join(unauth_methods)} method(s) for path '{path}'.",
                        recommendation="Attach a Lambda Authorizer (JWT validation) or Cognito User Pool Authorizer. Set apiKeyRequired: true as a minimum baseline."
                    ))

            # --- Active abuse simulation ---
            if self.simulate_abuse and not waf_protected:
                logger.info(f"Running rate-limit probe against {invoke_url}")
                probe_result = self._simulate_rate_limit(invoke_url)
                if not probe_result['rate_limit_effective']:
                    findings.append(self._generate_finding(
                        resource_arn=stage_arn,
                        severity="HIGH",
                        risk_score=8.6,
                        issue="Rate Limiting Bypass Confirmed via Active Simulation",
                        details=(
                            f"Baseline probe sent {probe_result['probe_requests']} requests at "
                            f"{RATE_LIMIT_PROBE_RPS} req/s to {invoke_url}. "
                            f"{probe_result['passed_through']} requests were served without throttling. "
                            f"Effective rate limiting was NOT enforced."
                        ),
                        action="Enforce WAF rate-based rules and Usage Plan throttle limits immediately.",
                        recommendation="A WAFv2 rate-based rule set to 100 req/5-minute window should be the minimum config."
                    ))

                # --- Header manipulation bypass test ---
                logger.info(f"Running X-Forwarded-For bypass probe against {invoke_url}")
                bypass_result = self._simulate_header_bypass(invoke_url)
                if bypass_result['bypass_confirmed']:
                    findings.append(self._generate_finding(
                        resource_arn=stage_arn,
                        severity="HIGH",
                        risk_score=8.4,
                        issue="IP-Based Rate Limiting Bypassed via Header Manipulation",
                        details=(
                            f"X-Forwarded-For rotation probe confirmed: {bypass_result['bypass_successful_requests']} of "
                            f"{bypass_result['probe_count']} requests succeeded with spoofed source IPs and rotated "
                            f"User-Agent strings. WAF IP-based rules are insufficient — an attacker can sustain "
                            f"high request volumes indefinitely by rotating headers without actual IP changes."
                        ),
                        action="Replace or supplement IP-based WAF rules with identity-level throttling.",
                        recommendation=(
                            "Enforce rate limiting at the API Gateway Usage Plan level using API keys or "
                            "JWT sub claims — not IP addresses. Add WAFv2 rules that evaluate "
                            "X-Forwarded-For header consistency and block requests that manipulate it."
                        )
                    ))

        return findings

    # ─── Finding Schema ────────────────────────────────────────────────────────

    def _generate_finding(self, resource_arn: str, severity: str, risk_score: float,
                          issue: str, details: str, action: str, recommendation: str) -> Dict[str, Any]:
        return {
            "finding_id": f"SEC-API-{str(uuid.uuid4())[:8].upper()}",
            "scanner": "api_exposure",
            "severity": severity,
            "risk_score": risk_score,
            "resource_arn": resource_arn,
            "issue": issue,
            "details": details,
            "remediation": {
                "action": action,
                "recommendation": recommendation
            }
        }

    # ─── Entry Point ──────────────────────────────────────────────────────────

    def run_scan(self) -> List[Dict[str, Any]]:
        logger.info("Initializing API exposure scan...")
        all_findings = []

        apis = self.get_all_rest_apis()
        protected_stage_arns = self.get_waf_associations()

        logger.info(f"Discovered {len(apis)} REST APIs. {len(protected_stage_arns)} stage(s) currently WAF-protected.")

        for api in apis:
            api_findings = self.analyze_api(api, protected_stage_arns)
            all_findings.extend(api_findings)

        logger.info(f"API scan complete. {len(all_findings)} findings discovered.")
        return all_findings


if __name__ == "__main__":
    scanner = APIScanner(simulate_abuse=False)
    results = scanner.run_scan()
    print(json.dumps(results, indent=2))
