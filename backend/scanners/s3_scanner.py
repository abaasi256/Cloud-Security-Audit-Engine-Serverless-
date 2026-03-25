"""
s3_scanner.py

Scans all S3 buckets for public exposure vectors (Block Public Access bypass,
permissive bucket policies, legacy ACLs), missing encryption, absent versioning,
and disabled access logging — the core misconfiguration surface attackers probe first.
"""

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# IAM actions that are dangerous when granted publicly
DANGEROUS_POLICY_ACTIONS = {
    "s3:putobject",
    "s3:deleteobject",
    "s3:putbucketpolicy",
    "s3:putbucketacl",
    "s3:deletebucket",
    "s3:*",
    "*",
}


class S3Scanner:
    """
    Audits S3 buckets against a hardened security baseline:
    - Block Public Access configuration
    - Bucket policies exposing data to public principals
    - Legacy ACL grants to AllUsers / AuthenticatedUsers
    - Server-side encryption (SSE-KMS preferred over SSE-S3)
    - Versioning and MFA-delete for forensic integrity
    - Access logging for audit trail completeness
    """

    def __init__(self, session: boto3.Session = None):
        sess = session or boto3.session.Session()
        self.s3 = sess.client('s3')

    # ─── Discovery ────────────────────────────────────────────────────────────

    def get_all_buckets(self) -> List[Dict[str, Any]]:
        try:
            response = self.s3.list_buckets()
            return response.get('Buckets', [])
        except ClientError as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            return []

    def _get_bucket_region(self, bucket_name: str) -> str:
        try:
            response = self.s3.get_bucket_location(Bucket=bucket_name)
            return response.get('LocationConstraint') or 'us-east-1'
        except ClientError:
            return 'unknown'

    # ─── Individual Checks ────────────────────────────────────────────────────

    def _check_public_access_block(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """BPA configuration is the single most important S3 guard."""
        try:
            bpa = self.s3.get_public_access_block(Bucket=bucket_name)
            config = bpa.get('PublicAccessBlockConfiguration', {})

            all_blocked = all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False),
            ])

            if not all_blocked:
                disabled = [k for k, v in config.items() if not v]
                return {
                    "severity": "CRITICAL",
                    "risk_score": 9.4,
                    "issue": "Block Public Access Not Fully Enabled",
                    "details": f"Block Public Access has partial coverage. Disabled settings: {', '.join(disabled)}. This allows public ACLs or policies to take effect.",
                    "action": "Enable all four Block Public Access settings on the bucket.",
                    "recommendation": "Run: aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                }
        except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            return {
                "severity": "CRITICAL",
                "risk_score": 9.4,
                "issue": "Block Public Access Not Configured",
                "details": "No Block Public Access configuration exists. The bucket can be exposed publicly via bucket policies or ACLs.",
                "action": "Configure Block Public Access for the bucket.",
                "recommendation": "Default-apply BPA at the account level via aws s3control put-public-access-block --account-id <ID>."
            }
        except ClientError as e:
            logger.warning(f"Could not check BPA for {bucket_name}: {e}")
        return None

    def _check_bucket_policy(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Detect policies granting access to '*' (everyone) or dangerous actions."""
        try:
            response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(response['Policy'])
        except self.s3.exceptions.NoSuchBucketPolicy:
            return None
        except ClientError as e:
            logger.warning(f"Could not read bucket policy for {bucket_name}: {e}")
            return None

        for stmt in policy_doc.get('Statement', []):
            effect = stmt.get('Effect')
            principal = stmt.get('Principal')
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            is_public_principal = principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*')
            has_dangerous_action = any(a.lower() in DANGEROUS_POLICY_ACTIONS for a in actions)

            if effect == 'Allow' and is_public_principal:
                if has_dangerous_action:
                    return {
                        "severity": "CRITICAL",
                        "risk_score": 9.6,
                        "issue": "Bucket Policy Grants Dangerous Actions to Public (*)",
                        "details": f"Bucket policy allows '{', '.join(actions)}' to Principal: '*'. Any unauthenticated actor can perform these operations.",
                        "action": "Remove public principal from policy statements or add restrictive conditions.",
                        "recommendation": "Replace Principal: '*' with specific principal ARNs. Add an aws:SourceVpc or aws:SourceAccount condition as minimum scoping."
                    }
                else:
                    return {
                        "severity": "HIGH",
                        "risk_score": 8.0,
                        "issue": "Bucket Policy Grants Read Access to Public (*)",
                        "details": "Bucket policy allows unauthenticated read access. Anyone can enumerate objects if they know the bucket name.",
                        "action": "Restrict the Principal to authenticated identities.",
                        "recommendation": "Replace Principal: '*' with specific IAM role ARNs. Verify whether public read is intentional."
                    }
        return None

    def _check_acls(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Legacy ACLs granting AllUsers or AuthenticatedUsers are a persistent risk."""
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
        except ClientError as e:
            logger.warning(f"Could not read ACL for {bucket_name}: {e}")
            return None

        risky_grantees = {
            'http://acs.amazonaws.com/groups/global/AllUsers': ('AllUsers (Public)', 'CRITICAL', 9.5),
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': ('AuthenticatedUsers (Any AWS Account)', 'HIGH', 7.8),
        }

        for grant in acl.get('Grants', []):
            grantee_uri = grant.get('Grantee', {}).get('URI', '')
            permission = grant.get('Permission', '')
            if grantee_uri in risky_grantees:
                label, severity, score = risky_grantees[grantee_uri]
                return {
                    "severity": severity,
                    "risk_score": score,
                    "issue": f"Legacy ACL Grants '{permission}' to {label}",
                    "details": f"Bucket ACL contains a grant for {label} with {permission} permission. This bypasses IAM and is exploitable without credentials.",
                    "action": f"Remove the ACL grant for {label}.",
                    "recommendation": "Migrate to bucket policies for access control. Set BPA/IgnorePublicAcls to neutralize existing ACLs."
                }
        return None

    def _check_encryption(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        try:
            enc = self.s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            for rule in rules:
                algo = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')
                if algo == 'aws:kms':
                    return None  # Best practice — KMS
                if algo == 'AES256':
                    return {
                        "severity": "MEDIUM",
                        "risk_score": 5.5,
                        "issue": "Bucket Uses SSE-S3 Instead of SSE-KMS",
                        "details": "SSE-S3 uses AWS-managed keys with no audit trail, key rotation control, or cross-account isolation.",
                        "action": "Migrate to SSE-KMS with a Customer Managed Key (CMK).",
                        "recommendation": "Set encryption to aws:kms with a CMK that has a key policy limiting access to specific roles."
                    }
        except self.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            return {
                "severity": "HIGH",
                "risk_score": 7.2,
                "issue": "Default Encryption Not Enabled",
                "details": "Objects uploaded without specifying encryption will be stored in plaintext.",
                "action": "Enable default SSE-KMS on the bucket.",
                "recommendation": "aws s3api put-bucket-encryption --bucket {bucket} with SSEAlgorithm=aws:kms and the KMS key ARN."
            }
        except ClientError as e:
            logger.warning(f"Could not check encryption for {bucket_name}: {e}")
        return None

    def _check_versioning(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        try:
            v = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = v.get('Status', '')
            mfa_delete = v.get('MFADelete', 'Disabled')

            if status != 'Enabled':
                return {
                    "severity": "MEDIUM",
                    "risk_score": 5.8,
                    "issue": "Object Versioning Not Enabled",
                    "details": "Without versioning, ransomware or an attacker deleting objects cannot be reversed.",
                    "action": "Enable versioning on the bucket.",
                    "recommendation": "aws s3api put-bucket-versioning --versioning-configuration Status=Enabled. Pair with S3 Object Lock for WORM compliance."
                }
            if mfa_delete != 'Enabled':
                return {
                    "severity": "MEDIUM",
                    "risk_score": 6.0,
                    "issue": "MFA Delete Not Enabled on Versioned Bucket",
                    "details": "Without MFA delete, a compromised IAM key can permanently delete versioned objects — erasing the forensic trail.",
                    "action": "Enable MFA Delete on the bucket.",
                    "recommendation": "Requires root account + MFA device: aws s3api put-bucket-versioning with MFADelete=Enabled."
                }
        except ClientError as e:
            logger.warning(f"Could not check versioning for {bucket_name}: {e}")
        return None

    def _check_logging(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        try:
            logging_conf = self.s3.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging_conf:
                return {
                    "severity": "MEDIUM",
                    "risk_score": 5.2,
                    "issue": "S3 Access Logging Not Enabled",
                    "details": "Without access logs, there is no audit trail for object reads (GetObject), deletes, or policy changes — critical gaps during incident response.",
                    "action": "Enable S3 server access logging to a dedicated audit bucket.",
                    "recommendation": "aws s3api put-bucket-logging to a separate, locked-down log bucket with object lock enabled."
                }
        except ClientError as e:
            logger.warning(f"Could not check logging for {bucket_name}: {e}")
        return None

    # ─── Finding Schema ────────────────────────────────────────────────────────

    def _generate_finding(self, bucket_arn: str, check_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "finding_id": f"SEC-S3-{str(uuid.uuid4())[:8].upper()}",
            "scanner": "s3_misconfiguration",
            "severity": check_result["severity"],
            "risk_score": check_result["risk_score"],
            "resource_arn": bucket_arn,
            "issue": check_result["issue"],
            "details": check_result["details"],
            "remediation": {
                "action": check_result["action"],
                "recommendation": check_result["recommendation"]
            }
        }

    # ─── Entry Point ──────────────────────────────────────────────────────────

    def run_scan(self) -> List[Dict[str, Any]]:
        logger.info("Initializing S3 misconfiguration scan...")
        all_findings = []
        buckets = self.get_all_buckets()
        logger.info(f"Discovered {len(buckets)} S3 buckets.")

        checks = [
            self._check_public_access_block,
            self._check_bucket_policy,
            self._check_acls,
            self._check_encryption,
            self._check_versioning,
            self._check_logging,
        ]

        for bucket in buckets:
            bucket_name = bucket['Name']
            bucket_arn = f"arn:aws:s3:::{bucket_name}"

            for check in checks:
                result = check(bucket_name)
                if result:
                    all_findings.append(self._generate_finding(bucket_arn, result))

        logger.info(f"S3 scan complete. {len(all_findings)} findings discovered.")
        return all_findings


if __name__ == "__main__":
    scanner = S3Scanner()
    results = scanner.run_scan()
    print(json.dumps(results, indent=2))
