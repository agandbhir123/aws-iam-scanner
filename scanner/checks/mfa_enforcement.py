"""
Check: MFA Enforcement

Users with AWS console access (password enabled) and no MFA device
are one compromised password away from a full account breach.

Flags:
  - Users with console access and no MFA (HIGH)
  - Users with no MFA at all, even if programmatic-only (MEDIUM)
  - Root account with no MFA (HIGH — critical)
"""

from typing import Any


def check_mfa_enforcement(session) -> list[dict[str, Any]]:
    findings = []
    iam = session.client("iam")

    # --- Check root account MFA via account summary ---
    summary = iam.get_account_summary()["SummaryMap"]
    root_mfa_enabled = summary.get("AccountMFAEnabled", 0)
    if not root_mfa_enabled:
        findings.append({
            "check": "mfa_enforcement",
            "severity": "HIGH",
            "resource_type": "Root",
            "resource_name": "root",
            "resource_arn": "arn:aws:iam::root",
            "issues": ["Root account does not have MFA enabled"],
            "description": (
                "The AWS root account does not have MFA enabled. "
                "Root account compromise is catastrophic — there is no recovery path."
            ),
            "remediation": (
                "Enable MFA on the root account immediately using a hardware key or "
                "virtual MFA device. Go to IAM → Security credentials → MFA."
            ),
        })

    # --- Check all IAM users ---
    user_paginator = iam.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            user_arn = user["Arn"]

            # Check if user has console access (login profile exists)
            has_console_access = _has_login_profile(iam, username)

            # Check if user has any MFA device enrolled
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            has_mfa = len(mfa_devices) > 0

            if has_console_access and not has_mfa:
                findings.append({
                    "check": "mfa_enforcement",
                    "severity": "HIGH",
                    "resource_type": "User",
                    "resource_name": username,
                    "resource_arn": user_arn,
                    "issues": [
                        "User has console (password) access but NO MFA device enrolled"
                    ],
                    "description": (
                        f"User '{username}' can log into the AWS console with just a password. "
                        "A single phished or leaked password grants full console access."
                    ),
                    "remediation": (
                        "Require MFA immediately. In IAM, go to the user → Security credentials "
                        "→ Assign MFA device. Consider enforcing MFA via an IAM policy that "
                        "denies all actions unless aws:MultiFactorAuthPresent is true."
                    ),
                })

            elif not has_console_access and not has_mfa:
                # Programmatic-only user with no MFA — lower severity but still worth noting
                findings.append({
                    "check": "mfa_enforcement",
                    "severity": "LOW",
                    "resource_type": "User",
                    "resource_name": username,
                    "resource_arn": user_arn,
                    "issues": [
                        "User has no MFA device enrolled (programmatic-only access)"
                    ],
                    "description": (
                        f"User '{username}' has no MFA enrolled. "
                        "While this user has no console access, enrolling MFA is still best practice "
                        "in case a login profile is added later."
                    ),
                    "remediation": (
                        "Prefer IAM roles over long-lived IAM users for programmatic access. "
                        "If this user must exist, consider adding MFA and enforcing it via policy."
                    ),
                })

    return findings


def _has_login_profile(iam, username: str) -> bool:
    """Return True if the user has a console password set."""
    try:
        iam.get_login_profile(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False
