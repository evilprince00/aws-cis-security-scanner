# AWS CIS Benchmark Scanner v3.0
## CIS Amazon Web Services Foundations Benchmark **v5.0.0**
### (Latest — Recommended by AWS Security Hub, October 2025)

---

## ⚠️ Important: Versioning Clarification

> **"CIS AWS Foundations Benchmark v7.0.0" does not exist.**
>
> The CIS Amazon Web Services Foundations Benchmark uses its own version numbering:
> `v1.2 → v1.4 → v3.0 → v4.0 → v5.0 (current)`
>
> Do **not** confuse this with **CIS Controls v7** (previously "CIS Critical Security Controls"),
> which is a completely separate, organisation-wide framework — not AWS-specific.
>
> This scanner implements **v5.0.0**, the current version certified by CIS and
> recommended by AWS Security Hub as of October 2025.

---

## What's New in v5.0.0 vs v1.5

| New Control | Description |
|------------|-------------|
| Account.1 | Security contact information must be configured |
| IAM.2 | IAM users should not have policies directly attached |
| IAM.6 | **Hardware** MFA (not just virtual) required on root |
| IAM.22 | Unused credentials threshold tightened: **45 days** (was 90) |
| IAM.26 | Expired SSL/TLS certificates in IAM must be removed |
| IAM.27 | AWSCloudShellFullAccess policy must not be attached to any identity |
| IAM.28 | IAM Access Analyzer must be enabled in every region |
| KMS.4 | Customer-managed KMS key rotation must be enabled |
| EC2.8 | EC2 instances must use **IMDSv2** (HttpTokens=required) |
| EC2.54 | Security groups: no open admin ports from **::/0** (IPv6) |
| EC2.21 | NACLs: no ingress from 0.0.0.0/0 on port 22 or 3389 |
| EFS.1 | EFS file systems must be KMS-encrypted at rest |
| EFS.8 | EFS file systems must be encrypted at rest |
| RDS.2 | RDS instances must not be publicly accessible |
| RDS.5 | RDS instances should be Multi-AZ |
| RDS.13 | RDS automatic minor version upgrades must be enabled |
| RDS.15 | RDS clusters should be Multi-AZ |
| S3.20 | S3 buckets should have MFA Delete enabled |
| S3.22 | S3 buckets should log object-level **write** events |
| S3.23 | S3 buckets should log object-level **read** events |

---

## Sections Covered (8 sections, 70+ checks)

| Section | Controls |
|---------|----------|
| **1. Account** | Account.1 — Security contact information |
| **2. IAM** | IAM.2,3,4,5,6,9,15,16,18,22,26,27,28 |
| **3. Storage (S3)** | S3.1,5,8,20,22,23 |
| **4. Logging** | CloudTrail.1,2,4,7 + Config.1 |
| **5. Monitoring** | CloudWatch alarms × 14 |
| **6. Networking** | EC2.2,6,8,21,53,54 |
| **7. Encryption** | EC2.7, EFS.1, EFS.8, KMS.4 |
| **8. Database** | RDS.2,3,5,13,15 |

---

## Quick Start

```bash
pip install -r requirements.txt

# Default credentials
python3 aws_cis_v5_scanner.py

# Named profile
python3 aws_cis_v5_scanner.py --profile audit-readonly

# Cross-account role assumption
python3 aws_cis_v5_scanner.py --role-arn arn:aws:iam::123456789012:role/CISAuditor

# Specific regions + custom outputs
python3 aws_cis_v5_scanner.py --profile prod --regions us-east-1,eu-west-1,ap-southeast-1 \
  --output-html cis_v5_report.html --output-json cis_v5_report.json
```

---

## Required IAM Policy (Read-Only)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CISv5ScannerReadOnly",
      "Effect": "Allow",
      "Action": [
        "account:GetAlternateContact",

        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:GetLoginProfile",
        "iam:GetPolicyVersion",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ListPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:ListEntitiesForPolicy",
        "iam:ListServerCertificates",
        "iam:GetAccountAuthorizationDetails",

        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetBucketPolicy",

        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",

        "logs:DescribeMetricFilters",

        "cloudwatch:DescribeAlarms",

        "config:DescribeConfigurationRecorderStatus",

        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeInstances",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeNetworkAcls",
        "ec2:GetEbsEncryptionByDefault",

        "efs:DescribeFileSystems",

        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",

        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",

        "accessanalyzer:ListAnalyzers",

        "sts:GetCallerIdentity",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## CIS v5.0.0 Control Reference

| Check ID | Control ID | Title | Level | Severity |
|----------|-----------|-------|-------|----------|
| 1.1 | Account.1 | Security contact information | L1 | MEDIUM |
| 2.1 | IAM.4 | No root access keys | L1 | CRITICAL |
| 2.2 | IAM.9 | Root MFA enabled | L1 | CRITICAL |
| 2.3 | IAM.6 | Root hardware MFA | L2 | HIGH |
| 2.4 | IAM.5 | MFA for all console users | L1 | HIGH |
| 2.5 | IAM.2 | No direct user policy attachments | L1 | MEDIUM |
| 2.6 | IAM.3 | Access key rotation ≤90 days | L1 | HIGH |
| 2.7 | IAM.22 | Unused credentials removed in 45 days | L1 | HIGH |
| 2.8 | IAM.15 | Password min length ≥14 | L1 | MEDIUM |
| 2.9 | IAM.16 | Password reuse prevention ≥24 | L1 | MEDIUM |
| 2.10 | IAM.18 | Support role exists | L1 | LOW |
| 2.11 | IAM.26 | No expired SSL/TLS certs in IAM | L1 | HIGH |
| 2.12 | IAM.27 | No CloudShellFullAccess attached | L1 | MEDIUM |
| 2.13 | IAM.28 | Access Analyzer enabled all regions | L1 | HIGH |
| 3.1 | S3.1/S3.8 | Block public access on buckets | L1 | CRITICAL |
| 3.2 | S3.5 | SSL-only bucket policy | L1 | HIGH |
| 3.3 | S3.20 | MFA Delete enabled | L2 | MEDIUM |
| 3.4 | S3.22 | Object-level write event logging | L2 | MEDIUM |
| 3.5 | S3.23 | Object-level read event logging | L2 | MEDIUM |
| 4.1 | CloudTrail.1 | Multi-region trail with management events | L1 | CRITICAL |
| 4.2 | CloudTrail.2 | CloudTrail KMS encryption | L2 | HIGH |
| 4.3 | CloudTrail.4 | Log file validation | L1 | LOW |
| 4.4 | CloudTrail.7 | Access logging on CloudTrail S3 bucket | L1 | LOW |
| 4.5 | Config.1 | AWS Config enabled all regions | L1 | MEDIUM |
| 5.1–5.14 | CloudWatch.1–14 | CloudWatch metric filter/alarm checks | L1 | VARIES |
| 6.1 | EC2.2 | Default SG allows no traffic | L1 | HIGH |
| 6.2 | EC2.6 | VPC flow logs enabled | L1 | MEDIUM |
| 6.3 | EC2.8 | IMDSv2 required on EC2 instances | L1 | HIGH |
| 6.4 | EC2.21 | NACL no open SSH/RDP from 0.0.0.0/0 | L1 | HIGH |
| 6.5 | EC2.53 | SG no open admin ports from 0.0.0.0/0 | L1 | HIGH |
| 6.6 | EC2.54 | SG no open admin ports from ::/0 | L1 | HIGH |
| 7.1 | EC2.7 | EBS default encryption enabled | L1 | HIGH |
| 7.2 | EFS.1 | EFS KMS encryption | L1 | HIGH |
| 7.3 | EFS.8 | EFS at-rest encryption | L1 | HIGH |
| 7.4 | KMS.4 | KMS key rotation enabled | L2 | MEDIUM |
| 8.1 | RDS.2 | RDS not publicly accessible | L1 | CRITICAL |
| 8.2 | RDS.3 | RDS encryption at rest | L1 | HIGH |
| 8.3 | RDS.5 | RDS Multi-AZ | L2 | MEDIUM |
| 8.4 | RDS.13 | RDS auto minor version upgrades | L1 | HIGH |
| 8.5 | RDS.15 | RDS cluster Multi-AZ | L2 | MEDIUM |
