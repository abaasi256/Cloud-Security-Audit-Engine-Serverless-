import json
import logging
import uuid
from typing import List, Dict, Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class IAMScanner:
    """
    Core Scanner for detecting IAM misconfigurations focused on Exploitability, 
    AssumeRole abuse, and Toxic Combinations leading to Privilege Escalation.
    """

    def __init__(self, session: boto3.Session = None):
        self.client = session.client('iam') if session else boto3.client('iam')

    def get_all_roles(self) -> List[Dict[str, Any]]:
        """Fetch all IAM roles safely using pagination."""
        roles = []
        try:
            paginator = self.client.get_paginator('list_roles')
            for page in paginator.paginate():
                roles.extend(page.get('Roles', []))
        except ClientError as e:
            logger.error(f"Failed to list roles: {e}")
        return roles

    def get_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """Fetch both inline and attached managed policies for a specific role."""
        policies = []
        try:
            # Inline policies
            inline_paginator = self.client.get_paginator('list_role_policies')
            for page in inline_paginator.paginate(RoleName=role_name):
                for policy_name in page.get('PolicyNames', []):
                    policy_doc = self.client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    policies.append({
                        'PolicyName': policy_name,
                        'PolicyType': 'Inline',
                        'PolicyDocument': policy_doc['PolicyDocument']
                    })

            # Attached managed policies
            attached_paginator = self.client.get_paginator('list_attached_role_policies')
            for page in attached_paginator.paginate(RoleName=role_name):
                for attached_policy in page.get('AttachedPolicies', []):
                    policy_arn = attached_policy['PolicyArn']
                    
                    # Prevent deep fetching of raw AWS managed policies to save time, unless customer managed.
                    # We fetch the policy version to evaluate custom managed policies.
                    if not policy_arn.startswith('arn:aws:iam::aws:policy/'):
                        policy_info = self.client.get_policy(PolicyArn=policy_arn)
                        version_id = policy_info['Policy']['DefaultVersionId']
                        policy_version = self.client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                        
                        policies.append({
                            'PolicyName': attached_policy['PolicyName'],
                            'PolicyType': 'CustomerManaged',
                            'PolicyDocument': policy_version['PolicyVersion']['Document']
                        })
        except ClientError as e:
            logger.error(f"Failed to get policies for role {role_name}: {e}")

        return policies

    def normalize_statement(self, statement: Any) -> List[Dict[str, Any]]:
        """Ensures the statement is a list and normalizes Actions/Resources to lists."""
        if not isinstance(statement, list):
            statement = [statement]

        normalized = []
        for stmt in statement:
            if not isinstance(stmt, dict):
                continue

            norm_stmt = stmt.copy()
            for key in ['Action', 'NotAction', 'Resource', 'NotResource']:
                if key in norm_stmt and isinstance(norm_stmt[key], str):
                    norm_stmt[key] = [norm_stmt[key]]
            normalized.append(norm_stmt)

        return normalized

    def analyze_policy(self, policy_doc: Dict[str, Any], role_arn: str, policy_name: str, policy_type: str) -> List[Dict[str, Any]]:
        """Core analysis engine for an individual policy document."""
        findings = []
        statements = self.normalize_statement(policy_doc.get('Statement', []))

        all_allowed_actions = set()
        all_allowed_resources = set()

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue

            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            conditions = stmt.get('Condition', {})

            all_allowed_actions.update([a.lower() for a in actions])
            all_allowed_resources.update(resources)

            # 1. Detect Action: *
            if any(a == '*' for a in actions):
                findings.append(self.generate_finding(
                    role_arn=role_arn,
                    severity="CRITICAL",
                    risk_score=9.8,
                    issue="Overly Permissive Actions Detected",
                    details=f"Policy '{policy_name}' ({policy_type}) grants '*' Action. Total administrative control.",
                    recommendation="Restrict Action to specific required API calls based on actual usage.",
                    policy_name=policy_name
                ))

            # 2. Detect Resource: * with broad scope (especially inline)
            if any(r == '*' for r in resources):
                if not any(a == '*' for a in actions):  # Avoid duplicate critical finding
                    if policy_type == 'Inline':
                        findings.append(self.generate_finding(
                            role_arn=role_arn,
                            severity="HIGH",
                            risk_score=7.5,
                            issue="Inline Policy with Broad Resource Scope",
                            details=f"Inline policy '{policy_name}' grants permissions over '*' Resource, creating hidden exposure.",
                            recommendation="Scope down Resource to specific ARNs (e.g., specific S3 buckets or DynamoDB tables).",
                            policy_name=policy_name
                        ))

            # 3. Detect iam:PassRole over broad/wildcard resources
            pass_role_actions = [a for a in actions if a.lower() in ('iam:passrole', 'iam:*', '*')]
            if pass_role_actions and any(r == '*' or r.endswith('/*') for r in resources):
                if not conditions:
                    findings.append(self.generate_finding(
                        role_arn=role_arn,
                        severity="CRITICAL",
                        risk_score=9.5,
                        issue="iam:PassRole Abuse Path Detected",
                        details=f"Policy '{policy_name}' allows passing any IAM role without condition boundaries.",
                        recommendation="Restrict iam:PassRole to specific target execution roles via precise ARNs or strict Condition blocks.",
                        policy_name=policy_name
                    ))

        # 4. Check Toxic Combinations across the entire policy document
        self._check_privilege_escalation(all_allowed_actions, role_arn, policy_name, findings)

        return findings

    def _check_privilege_escalation(self, actions: set, role_arn: str, policy_name: str, findings: list):
        """Identifies paths where an attacker can escalate privileges by provisioning compute resources with a passed role."""
        has_pass_role = 'iam:passrole' in actions or 'iam:*' in actions or '*' in actions

        escalation_paths = {
            'lambda:createfunction': "Lambda Execution",
            'lambda:*': "Lambda Execution",
            'ec2:runinstances': "EC2 Compute",
            'ec2:*': "EC2 Compute",
            'ecs:runtask': "ECS Task Execution",
            'ecs:*': "ECS Task Execution",
            'cloudformation:createstack': "CloudFormation Deployment",
            'cloudformation:*': "CloudFormation Deployment"
        }

        if has_pass_role:
            for path, mechanism in escalation_paths.items():
                if path in actions:
                    findings.append(self.generate_finding(
                        role_arn=role_arn,
                        severity="CRITICAL",
                        risk_score=9.7,
                        issue=f"Privilege Escalation via {mechanism}",
                        details=f"Toxic Combination: 'iam:PassRole' combined with '{path}' detected in policy '{policy_name}'. Attacker can pass highly privileged roles to compute resources they control.",
                        recommendation=f"Remove '{path}' or 'iam:PassRole', or strictly constrain the resource ARNs that can be passed.",
                        policy_name=policy_name
                    ))
                    break  # Emit one primary escalation finding per policy to reduce noise

    def generate_finding(self, role_arn: str, severity: str, risk_score: float, issue: str, details: str, recommendation: str, policy_name: str) -> Dict[str, Any]:
        """Standardizes the output JSON for the risk scoring engine and storage pipeline."""
        finding_id = f"SEC-IAM-{str(uuid.uuid4())[:8].upper()}"
        return {
            "finding_id": finding_id,
            "scanner": "iam_misconfiguration",
            "severity": severity,
            "risk_score": risk_score,
            "resource_arn": role_arn,
            "issue": issue,
            "details": details,
            "remediation": {
                "action": f"Review and modify policy: {policy_name}",
                "recommendation": recommendation
            }
        }

    def run_scan(self) -> List[Dict[str, Any]]:
        """Main execution loop for scanning."""
        logger.info("Initializing IAM misconfiguration scan...")
        all_findings = []

        roles = self.get_all_roles()
        logger.info(f"Discovered {len(roles)} IAM roles.")

        for role in roles:
            role_arn = role['Arn']
            role_name = role['RoleName']

            # Skip AWS service roles to avoid false positives on inherent platform mechanics
            if 'aws-service-role' in role_arn:
                continue

            policies = self.get_role_policies(role_name)

            for policy in policies:
                policy_doc = policy['PolicyDocument']
                policy_name = policy['PolicyName']
                policy_type = policy['PolicyType']

                role_findings = self.analyze_policy(policy_doc, role_arn, policy_name, policy_type)
                
                # Deduplicate exact same findings for cleanliness
                for finding in role_findings:
                    if finding not in all_findings:
                        all_findings.append(finding)

        logger.info(f"IAM scan complete. {len(all_findings)} high-impact findings discovered.")
        return all_findings


if __name__ == "__main__":
    # Internal validation/local run
    # Expects AWS credentials to be configured in environment (e.g., standard Lambda execution role context)
    scanner = IAMScanner()
    results = scanner.run_scan()
    print(json.dumps(results, indent=2))
