"""
lambda_scanner.py

Scans AWS Lambda functions for insecure execution role configurations,
secrets leaking through environment variables, dangerous function URL
exposure, and resource abuse vectors (timeout/memory settings enabling
cryptomining or cost amplification).
"""

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Patterns for detecting secrets in environment variable values
SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*.+'),
    re.compile(r'(?i)(secret|api[_-]?key|private[_-]?key|token|auth)\s*[:=]?\s*[a-zA-Z0-9+/=]{16,}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),                          # AWS Access Key ID
    re.compile(r'(?i)sk[_-]live[_0-9A-Za-z]{24,}'),           # Stripe live key
    re.compile(r'(?i)gh[pousr]_[A-Za-z0-9]{36,}'),            # GitHub PAT
    re.compile(r'(?i)xox[baprs]-[0-9A-Za-z-]+'),              # Slack token
    re.compile(r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'),
]

# Over-privileged IAM managed policies that are never appropriate for Lambda execution roles
OVERPRIVILEGED_MANAGED_POLICIES = {
    'arn:aws:iam::aws:policy/AdministratorAccess',
    'arn:aws:iam::aws:policy/IAMFullAccess',
    'arn:aws:iam::aws:policy/PowerUserAccess',
    'arn:aws:iam::aws:policy/AmazonEC2FullAccess',
    'arn:aws:iam::aws:policy/AmazonS3FullAccess',
    'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
}

# Thresholds for resource abuse risk
TIMEOUT_ABUSE_THRESHOLD_SECONDS = 600   # 10 minutes — viable for crypto workloads
MEMORY_ABUSE_THRESHOLD_MB = 3008        # Maximum Lambda memory


class LambdaScanner:
    """
    Validates that Lambda functions operate with least-privilege execution roles,
    do not expose sensitive configuration through environment variables, are not
    publicly invocable without authorization, and are bounded by sane resource limits.
    """

    def __init__(self, session: boto3.Session = None):
        sess = session or boto3.session.Session()
        self.lambda_client = sess.client('lambda')
        self.iam = sess.client('iam')

    # ─── Discovery ────────────────────────────────────────────────────────────

    def get_all_functions(self) -> List[Dict[str, Any]]:
        functions = []
        try:
            paginator = self.lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                functions.extend(page.get('Functions', []))
        except ClientError as e:
            logger.error(f"Failed to list Lambda functions: {e}")
        return functions

    def get_function_policy(self, function_name: str) -> Optional[Dict[str, Any]]:
        """Returns the resource-based policy on the function, if any."""
        try:
            response = self.lambda_client.get_policy(FunctionName=function_name)
            return json.loads(response['Policy'])
        except self.lambda_client.exceptions.ResourceNotFoundException:
            return None
        except ClientError as e:
            logger.warning(f"Could not read policy for {function_name}: {e}")
            return None

    def get_function_url_config(self, function_name: str) -> Optional[Dict[str, Any]]:
        """Returns Lambda Function URL config if it exists."""
        try:
            return self.lambda_client.get_function_url_config(FunctionName=function_name)
        except self.lambda_client.exceptions.ResourceNotFoundException:
            return None
        except ClientError as e:
            logger.warning(f"Could not read URL config for {function_name}: {e}")
            return None

    def get_attached_managed_policies(self, role_name: str) -> List[str]:
        policy_arns = []
        try:
            paginator = self.iam.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for p in page.get('AttachedPolicies', []):
                    policy_arns.append(p['PolicyArn'])
        except ClientError as e:
            logger.warning(f"Could not list policies for role {role_name}: {e}")
        return policy_arns

    # ─── Individual Checks ────────────────────────────────────────────────────

    def _extract_role_name(self, role_arn: str) -> str:
        return role_arn.rstrip('/').split('/')[-1]

    def _check_execution_role(self, function: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        role_arn = function.get('Role', '')
        role_name = self._extract_role_name(role_arn)
        function_arn = function['FunctionArn']

        attached_policies = self.get_attached_managed_policies(role_name)

        for policy_arn in attached_policies:
            if policy_arn in OVERPRIVILEGED_MANAGED_POLICIES:
                policy_name = policy_arn.split('/')[-1]
                findings.append(self._generate_finding(
                    resource_arn=function_arn,
                    severity="CRITICAL",
                    risk_score=9.3,
                    issue=f"Lambda Execution Role Uses Overprivileged Managed Policy: {policy_name}",
                    details=(
                        f"Function '{function['FunctionName']}' uses execution role '{role_name}' "
                        f"which has '{policy_name}' attached. A compromised function can perform "
                        f"unrestricted AWS API calls — including credential exfiltration and lateral movement."
                    ),
                    action=f"Detach '{policy_name}' from role '{role_name}'.",
                    recommendation="Replace with a custom policy referencing only the specific ARNs and actions the function needs. Apply resource-level conditions."
                ))

        return findings

    def _check_env_vars(self, function: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        env_vars = function.get('Environment', {}).get('Variables', {})

        suspicious_findings = []
        for key, value in env_vars.items():
            kv_pair = f"{key}={value}"
            for pattern in SECRET_PATTERNS:
                if pattern.search(key) or pattern.search(value):
                    suspicious_findings.append(key)
                    break

        if suspicious_findings:
            # Redact values in the finding detail — do not log raw secrets
            findings.append(self._generate_finding(
                resource_arn=function_arn,
                severity="HIGH",
                risk_score=8.5,
                issue="Potential Secrets Exposed in Lambda Environment Variables",
                details=(
                    f"Function '{function_name}' has {len(suspicious_findings)} environment variable(s) "
                    f"matching secret patterns: [{', '.join(suspicious_findings)}]. "
                    f"Environment variables are readable by anyone with lambda:GetFunction access on the execution role."
                ),
                action="Remove secrets from environment variables immediately.",
                recommendation="Store secrets in AWS Secrets Manager or Parameter Store (SecureString). Retrieve at runtime using the AWS SDK — never bake them into the function config."
            ))

        return findings

    def _check_function_url(self, function: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']

        url_config = self.get_function_url_config(function_name)
        if not url_config:
            return None

        auth_type = url_config.get('AuthType', 'NONE')
        function_url = url_config.get('FunctionUrl', '')

        if auth_type == 'NONE':
            return self._generate_finding(
                resource_arn=function_arn,
                severity="CRITICAL",
                risk_score=9.5,
                issue="Lambda Function URL Publicly Accessible Without Authentication",
                details=(
                    f"Function '{function_name}' has a public Function URL ({function_url}) with "
                    f"AuthType=NONE. Any unauthenticated actor on the internet can invoke this function directly."
                ),
                action="Change the Lambda Function URL AuthType to AWS_IAM.",
                recommendation="If public access is needed, front the function with API Gateway and attach a Lambda Authorizer or WAF rather than exposing Function URLs directly."
            )
        return None

    def _check_resource_policy(self, function: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect resource-based policies granting invoke to '*' (everyone)."""
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']

        policy = self.get_function_policy(function_name)
        if not policy:
            return None

        for stmt in policy.get('Statement', []):
            principal = stmt.get('Principal', {})
            effect = stmt.get('Effect')
            action = stmt.get('Action', '')

            is_public = principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*')
            is_invoke = 'lambda:InvokeFunction' in action or action == '*'

            if effect == 'Allow' and is_public and is_invoke:
                return self._generate_finding(
                    resource_arn=function_arn,
                    severity="CRITICAL",
                    risk_score=9.4,
                    issue="Lambda Resource Policy Allows Public Invocation",
                    details=(
                        f"Function '{function_name}' has a resource-based policy granting "
                        f"lambda:InvokeFunction to Principal: '*'. Any AWS account can trigger this function."
                    ),
                    action="Remove the public principal from the resource policy.",
                    recommendation="Restrict the principal to specific AWS account IDs, service ARNs (e.g., API Gateway), or use IAM conditions like aws:SourceArn for cross-account scoping."
                )
        return None

    def _check_resource_limits(self, function: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Flags functions with timeout + max-memory combinations viable for cryptomining or billing abuse."""
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        timeout = function.get('Timeout', 3)
        memory = function.get('MemorySize', 128)

        if timeout >= TIMEOUT_ABUSE_THRESHOLD_SECONDS and memory >= MEMORY_ABUSE_THRESHOLD_MB:
            return self._generate_finding(
                resource_arn=function_arn,
                severity="MEDIUM",
                risk_score=6.2,
                issue="Lambda Resource Configuration Enables Billing Abuse",
                details=(
                    f"Function '{function_name}' is configured with Timeout={timeout}s and "
                    f"Memory={memory}MB. If an attacker achieves invocation rights (however limited), "
                    f"this configuration can be abused to run compute-intensive workloads at your cost."
                ),
                action="Review whether the function requires these resource limits.",
                recommendation="Reduce timeout and memory to the minimum required for normal operation. Implement AWS Budgets alerts for Lambda invocation cost anomalies."
            )
        return None

    # ─── Finding Schema ────────────────────────────────────────────────────────

    def _generate_finding(self, resource_arn: str, severity: str, risk_score: float,
                          issue: str, details: str, action: str, recommendation: str) -> Dict[str, Any]:
        return {
            "finding_id": f"SEC-LMB-{str(uuid.uuid4())[:8].upper()}",
            "scanner": "lambda_misconfiguration",
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
        logger.info("Initializing Lambda misconfiguration scan...")
        all_findings = []
        functions = self.get_all_functions()
        logger.info(f"Discovered {len(functions)} Lambda functions.")

        for function in functions:
            all_findings.extend(self._check_execution_role(function))
            all_findings.extend(self._check_env_vars(function))

            url_finding = self._check_function_url(function)
            if url_finding:
                all_findings.append(url_finding)

            policy_finding = self._check_resource_policy(function)
            if policy_finding:
                all_findings.append(policy_finding)

            limits_finding = self._check_resource_limits(function)
            if limits_finding:
                all_findings.append(limits_finding)

        logger.info(f"Lambda scan complete. {len(all_findings)} findings discovered.")
        return all_findings


if __name__ == "__main__":
    scanner = LambdaScanner()
    results = scanner.run_scan()
    print(json.dumps(results, indent=2))
