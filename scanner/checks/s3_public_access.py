"""
Check: S3 Public Access Misconfiguration

S3 bucket misconfigs are responsible for some of the biggest data breaches
in cloud history (Capital One, Twitch, etc.). Four layers to check:

  1. Block Public Access settings (account-level and bucket-level)
  2. Bucket ACL — public grants to AllUsers / AuthenticatedUsers
  3. Bucket policy status — AWS's own IsPublic flag
  4. Account-level Block Public Access (if all four settings are off, flag once)

Severity:
  - Bucket ACL grants to AllUsers → HIGH (anyone on the internet)
  - Bucket policy IsPublic → HIGH
  - Block Public Access disabled → MEDIUM (permissive, but not necessarily exposed)
  - AuthenticatedUsers ACL grants → MEDIUM (any AWS account)
"""

from typing import Any


# Canonical AllUsers / AuthenticatedUsers group URIs
ALL_USERS_URI  = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def check_s3_public_access(session) -> list[dict[str, Any]]:
    findings = []
    s3 = session.client("s3")

    # --- Account-level Block Public Access ---
    try:
        control = s3.get_public_access_block()["PublicAccessBlockConfiguration"]
        account_bpa_issues = _check_bpa_config(control)
        if account_bpa_issues:
            findings.append({
                "check": "s3_public_access",
                "severity": "MEDIUM",
                "resource_type": "S3/AccountBPA",
                "resource_name": "Account-level Block Public Access",
                "resource_arn": "arn:aws:s3:::*",
                "issues": account_bpa_issues,
                "description": (
                    "Account-level S3 Block Public Access is not fully enabled. "
                    "This is the first line of defense against accidental public exposure."
                ),
                "remediation": (
                    "In the S3 console → Block Public Access (account settings), "
                    "enable all four settings. This is a one-click fix and should be "
                    "enabled on all accounts that don't intentionally serve public content."
                ),
            })
    except Exception as e:
        if "NoSuchPublicAccessBlockConfiguration" in str(e):
            findings.append({
                "check": "s3_public_access",
                "severity": "MEDIUM",
                "resource_type": "S3/AccountBPA",
                "resource_name": "Account-level Block Public Access",
                "resource_arn": "arn:aws:s3:::*",
                "issues": ["Account-level Block Public Access is not configured at all"],
                "description": (
                    "No account-level S3 Block Public Access configuration found. "
                    "Without this, individual bucket settings are the only protection."
                ),
                "remediation": (
                    "Enable all four Block Public Access settings at the account level "
                    "in the S3 console under 'Block Public Access settings for this account'."
                ),
            })
        # Other errors (permissions, regional issues) — skip silently

    # --- Per-bucket checks ---
    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name       = bucket["Name"]
        bucket_arn = f"arn:aws:s3:::{name}"

        # 1. Bucket-level Block Public Access
        try:
            bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            bpa_issues = _check_bpa_config(bpa)
            if bpa_issues:
                findings.append({
                    "check": "s3_public_access",
                    "severity": "MEDIUM",
                    "resource_type": "S3/Bucket",
                    "resource_name": name,
                    "resource_arn": bucket_arn,
                    "issues": bpa_issues,
                    "description": f"Bucket '{name}' has Block Public Access settings disabled.",
                    "remediation": (
                        f"In S3 → {name} → Permissions → Block public access, "
                        "enable all four settings unless this bucket intentionally serves public content."
                    ),
                })
        except Exception as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                findings.append({
                    "check": "s3_public_access",
                    "severity": "MEDIUM",
                    "resource_type": "S3/Bucket",
                    "resource_name": name,
                    "resource_arn": bucket_arn,
                    "issues": ["Bucket has no Block Public Access configuration"],
                    "description": (
                        f"Bucket '{name}' has no Block Public Access configuration. "
                        "Relies entirely on ACL and policy controls."
                    ),
                    "remediation": (
                        f"Enable Block Public Access on bucket '{name}' "
                        "unless it intentionally serves public content."
                    ),
                })
            # Other errors — skip

        # 2. Bucket ACL — check for public grants
        try:
            acl      = s3.get_bucket_acl(Bucket=name)
            acl_issues = []
            for grant in acl.get("Grants", []):
                grantee    = grant.get("Grantee", {})
                uri        = grantee.get("URI", "")
                permission = grant.get("Permission", "")
                if uri == ALL_USERS_URI:
                    acl_issues.append(f"ACL grants '{permission}' to AllUsers (public internet)")
                elif uri == AUTH_USERS_URI:
                    acl_issues.append(f"ACL grants '{permission}' to AuthenticatedUsers (any AWS account)")
            if acl_issues:
                findings.append({
                    "check": "s3_public_access",
                    "severity": "HIGH",
                    "resource_type": "S3/Bucket",
                    "resource_name": name,
                    "resource_arn": bucket_arn,
                    "issues": acl_issues,
                    "description": f"Bucket '{name}' has a public ACL grant — anyone can access this bucket.",
                    "remediation": (
                        f"Remove public ACL grants on bucket '{name}'. "
                        "Use bucket policies for controlled public access instead of ACLs. "
                        "Consider enabling 'Block public ACLs' in Block Public Access settings."
                    ),
                })
        except Exception:
            pass

        # 3. Bucket policy public status
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            if policy_status.get("PolicyStatus", {}).get("IsPublic", False):
                findings.append({
                    "check": "s3_public_access",
                    "severity": "HIGH",
                    "resource_type": "S3/Bucket",
                    "resource_name": name,
                    "resource_arn": bucket_arn,
                    "issues": ["Bucket policy is flagged as public by AWS"],
                    "description": (
                        f"Bucket '{name}' has a bucket policy that AWS has determined allows public access."
                    ),
                    "remediation": (
                        f"Review the bucket policy on '{name}' and restrict the Principal "
                        "to specific accounts or roles. Remove any 'Principal: *' statements "
                        "unless intentional public hosting."
                    ),
                })
        except Exception as e:
            if "NoSuchBucketPolicy" in str(e):
                pass  # No policy — fine
            # Other errors — skip

    return findings


def _check_bpa_config(config: dict) -> list[str]:
    """Return list of disabled Block Public Access settings."""
    issues = []
    settings = {
        "BlockPublicAcls":      "Block public ACLs",
        "IgnorePublicAcls":     "Ignore public ACLs",
        "BlockPublicPolicy":    "Block public bucket policies",
        "RestrictPublicBuckets":"Restrict public buckets",
    }
    for key, label in settings.items():
        if not config.get(key, False):
            issues.append(f"{label} is disabled")
    return issues