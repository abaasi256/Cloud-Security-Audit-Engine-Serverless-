# Cloud Security Audit Engine (Serverless)

> A high-signal, execution-focused security scanning engine designed to detect, score, and simulate realistic abuse paths in AWS environments.

## Overview

Traditional CSPMs generate massive volumes of low-impact, compliance-driven alerts. This project takes an attacker-driven approach, functioning as an internal security engine that directly models impact and exploitability across cloud-native (serverless) infrastructure.

## 1. The Problem

Enterprise cloud environments accumulate misconfigurations daily. Off-the-shelf scanners are noisy, slow, and expensive, delivering thousands of alerts while missing the critical, multi-step abuse paths that attackers actually leverage. Security engineering teams need pragmatism—high-signal detection mapped to exploitability (e.g., API exposure, over-permissive IAM roles, weak serverless boundaries) before a breach can occur.

## 2. What It Does

The Engine continuously scans AWS environments, detects real-world risks, calculates a risk score based on exploitability, and delivers actionable, programmatic remediation.

**Core Capabilities:**

- **Asynchronous Execution:** Triggered via EventBridge schedules or API Gateway for ad-hoc validation.
- **Targeted Detection Modules:** Specifically hunt for privilege escalation (IAM), unauthorized unauthenticated access (API), and credential leakage.
- **Abuse Simulation:** Proactively tests endpoints and policies (e.g., rate limit saturation, STS `AssumeRole` validation) to confirm vulnerabilities and eliminate false positives.
- **Dynamic Risk Engine:** Applies pragmatic scoring (`Risk Score = Impact × Exploitability × Exposure`) rather than generic High/Medium/Low labels.

## 3. Example Findings (Real Output)

The engine produces raw, machine-readable intelligence designed for immediate routing to Jira, Slack, or automated pipelines.

```json
{
  "finding_id": "SEC-IAM-0042",
  "scanner": "iam_misconfiguration",
  "severity": "CRITICAL",
  "risk_score": 9.5,
  "resource_arn": "arn:aws:iam::123456789012:role/ci-deployment-role",
  "issue": "Privilege Escalation Path Detected: iam:PassRole over wildcard resources",
  "details": "The role possesses 'iam:PassRole' with Resource: '*'. An attacker compromising the CI pipeline could pass admin-level roles to an arbitrary EC2 instance and extract credentials via the metadata service.",
  "abuse_simulation": "FAILED: Successfully simulated passing an Admin role to a sandboxed compute resource.",
  "remediation": {
    "action": "Restrict PassRole to specific required ARNs",
    "policy_snippet": {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/specific-execution-role"
    }
  }
}
```

```json
{
  "finding_id": "SEC-API-0012",
  "scanner": "api_exposure",
  "severity": "HIGH",
  "risk_score": 8.8,
  "resource_arn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123",
  "issue": "Public API lacks Authentication and Rate Limiting",
  "details": "Endpoint '/v1/users/lookup' is exposed without a Custom Authorizer or Cognito. Rate limit simulation achieved 500 req/sec without triggering rejection.",
  "remediation": {
    "action": "Attach AWS WAF rate-limiting rule sets and enforce API Gateway Authorizer."
  }
}
```

## 4. Architecture

At its core, the tool is a purely serverless, event-driven engine engineered for strict internal least-privilege computing.

```text
[ Target App Environment ]
       ↓ (Scan Triggers via EventBridge / API Gateway)
+-------------------------------------------------------------+
|                     Scan Engine (Lambda)                    |
|  [IAM Scanner]  [API Scanner]  [Config/Secrets Scanner]     |
+-------------------------------------------------------------+
       ↓ (Raw Vulnerability Intelligence)
[ Risk Scoring Engine ] → Calculates: Impact × Exploitability
       ↓ (Prioritized Data)
[ Secure Storage ] → DynamoDB (Customer Managed KMS Encrypted)
       ↓
[ API Layer ] → API Gateway (Strict IAM Auth + WAF Protected)
       ↓
[ Operations Dashboard ] → React (Visibility into Critical Risks)
```

## 5. Security Philosophy & Abuse Focus

Most scanners tell you what is "open." This engine tells you *how it can be abused*.

- **Assume Breach:** We assume the attacker already has initial access (e.g., leaked limited credentials) and is looking to pivot laterally.
- **IAM Toxic Combinations:** Focuses heavily on identifying chains of permissions (e.g., `lambda:UpdateFunctionCode` + `iam:PassRole`) rather than just flagging `AdministratorAccess`.
- **Active Verification:** The API scanner doesn't just read the API Gateway config; it attempts a short burst of rapid requests to verify if WAF thresholds successfully drop the traffic.
- **Zero Trust Operations:** The scanner infrastructure itself runs with strict execution boundaries, ensuring a compromised scanner cannot be leveraged to pivot into the target environment.

---
*Built to demonstrate practical, attacker-informed cloud security engineering.*
