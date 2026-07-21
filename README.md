# AWS IAM Security Scanner

A Python CLI tool that scans your AWS account for IAM misconfigurations and over-permissive access. Outputs a security grade (A–F), a rich terminal report, and a JSON file with full finding details and remediation steps.

---

## What it checks

| Check | Severity | What it flags |
|---|---|---|
| **Wildcard Policies** | HIGH | `Action: "*"` or `Action: "service:*"` in managed/inline policies |
| **Admin Policy Attachments** | HIGH | `AdministratorAccess` or `IAMFullAccess` attached to any user or role |
| **Root Access Keys** | HIGH | Active access keys on the root account (should never exist) |
| **Stale Access Keys** | MEDIUM | Active keys older than threshold days or unused for threshold days |
| **Never-Used Keys** | MEDIUM | Active keys that have never been used (30+ days old) |
| **Direct Policy Attachments** | MEDIUM | Users with policies attached directly instead of via groups |
| **Inline Policies** | MEDIUM | Inline policies on users, roles, or groups (harder to audit) |
| **Permissive Trust Policies** | HIGH / MEDIUM | `Principal: "*"`, wildcard account IDs, cross-account without ExternalId |
| **Unused Roles** | LOW | Roles not assumed in threshold days, or never assumed (30+ days old) |
| **MFA Enforcement** | HIGH / LOW | Console users with no MFA (HIGH), programmatic users with no MFA (LOW), root with no MFA (HIGH) |
| **S3 Public Access** | HIGH / MEDIUM | Public ACL grants, public bucket policies, Block Public Access disabled at account or bucket level |

---

## Setup

**Requirements:** Python 3.11+, AWS credentials configured

```bash
git clone <repo>
cd aws-iam-scanner
pip install -r requirements.txt
```

---

## Required IAM permissions

The identity running this scanner needs read-only IAM access. Attach this policy to the user or role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMScannerReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListGroups",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListEntitiesForPolicy",
        "iam:GetRole",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:GetAccountSummary",
        "iam:ListMFADevices",
        "iam:GetLoginProfile",
        "cloudtrail:LookupEvents",
        "s3:GetPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicyStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Usage

```bash
# Use default AWS credentials / profile
python -m scanner

# Use a named profile
python -m scanner --profile dev

# Different region and custom output path
python -m scanner --region us-west-2 --output results.json

# Flag keys/roles unused for 60+ days instead of 90
python -m scanner --days 60

# Show remediation steps for every finding
python -m scanner --verbose

# Skip specific checks
python -m scanner --skip roles attachments mfa s3
```

---

## CloudTrail Least-Privilege Analyzer

The analyzer pulls CloudTrail event history for any IAM user, extracts every API call they actually made, and generates a minimal policy with exactly those permissions — nothing more.

This is conceptually what AWS IAM Access Analyzer's "Generate policy" feature does under the hood.

```bash
# Analyze an IAM user over the last 90 days (default)
python -m scanner.analyze --entity deploy-admin

# Shorter window, save output
python -m scanner.analyze --entity ci-runner --days 30 --output ci-policy.json

# With a named profile
python -m scanner.analyze --entity my-user --profile dev
```

**Example output:**
```
Analysis — deploy-admin
  CloudTrail events scanned:  847
  Denied events (excluded):   12
  Unique actions observed:    23
  Distinct services used:     4

Service        Actions used                                    #
s3             GetObject, ListBucket, PutObject               3
ec2            DescribeInstances, DescribeSecurityGroups       2
iam            GetUser, ListAttachedUserPolicies               2
sts            GetCallerIdentity                               1

Generated least-privilege policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3LeastPrivilege",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
      "Resource": "*"
    },
    ...
  ]
}
```
```

---

## Output

**CLI — summary table (always):**
```
╔══════════════════════════════════════╗
║   AWS IAM Security Scanner v1.0      ║
╚══════════════════════════════════════╝

✓ Connected  account=123456789012  caller=arn:aws:iam::123456789012:user/scanner

  ✓ Wildcard policies                    0 finding(s)
  ! Stale / unrotated access keys        3 finding(s)
  ! Direct policy attachments            1 finding(s)
  ✓ Permissive trust policies            0 finding(s)
  ! Unused roles                         5 finding(s)

  Grade: C  (Moderate risk)
  Score: 21  [3 MEDIUM]  [5 LOW]  (9 total)
```

**JSON — full finding detail:**
```json
{
  "generated_at": "2026-07-21T14:32:00+00:00",
  "account_id": "123456789012",
  "grade": "C",
  "score": 21,
  "summary": { "total": 9, "high": 0, "medium": 3, "low": 5 },
  "findings": [
    {
      "check": "unused_keys",
      "severity": "MEDIUM",
      "resource_type": "AccessKey",
      "resource_name": "deploy-user → key_1",
      "resource_arn": "arn:aws:iam::user/deploy-user/key_1",
      "issues": ["Key not rotated in 127 days (threshold: 90)"],
      "description": "Access key 1 for user 'deploy-user' may be stale.",
      "remediation": "Rotate the key if still needed, or deactivate and delete it."
    }
  ]
}
```

---

## GitHub Actions — automated scanning

The scanner runs automatically and posts findings directly to your repo.

**Triggers:**
- Every Monday at 9am UTC (scheduled)
- Every push to `main`
- Manually from the Actions tab with configurable `--days` and `--skip` options

**What happens each run:**
1. Full scanner runs against your AWS account
2. JSON report uploaded as a downloadable artifact (kept 90 days)
3. Formatted summary written to the GitHub Actions job summary page
4. If HIGH findings exist — opens a GitHub Issue tagged `iam-scanner` and `security`, or updates the existing one with a comment

**Setup:**

1. Push this repo to GitHub

2. Add AWS credentials as repository secrets:
   `Settings → Secrets and variables → Actions → New repository secret`
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`

3. Optionally set `AWS_REGION` as a repository variable (default: `us-east-1`)

4. Go to `Actions → IAM Security Scan → Run workflow` to trigger your first manual scan

> **Recommended for production:** Use OIDC instead of long-lived keys — GitHub can assume an IAM role directly without storing credentials. See the [GitHub OIDC guide for AWS](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services).

---

## Grading

| Grade | Score | Meaning |
|---|---|---|
| A | 0 | Clean — no findings |
| B | 1–15 | Minor issues |
| C | 16–40 | Moderate risk |
| D | 41–80 | Significant risk |
| F | 81+ | Critical — immediate action needed |

Score = HIGH findings × 10 + MEDIUM findings × 5 + LOW findings × 2

---

## Roadmap (v2)

- [ ] CloudTrail analyzer for IAM roles (not just users — role sessions are trickier to query)
- [ ] Resource-level ARN extraction from CloudTrail events (narrow Resource: * to specific ARNs)
- [ ] GitHub Actions integration — run scanner on PRs to catch IAM drift before it merges
- [ ] Password policy check (min length, MFA required, rotation)
- [ ] Multi-account support via AWS Organizations
