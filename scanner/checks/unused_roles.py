"""
Check: Unused IAM Roles

Unused roles represent unnecessary standing access — if compromised,
they give an attacker permissions that serve no business purpose.

Uses the RoleLastUsed field (populated by IAM when a role is assumed).

Flags:
  - Roles never used that are older than 30 days
  - Roles not used in more than `days` days
"""

from datetime import datetime, timezone
from typing import Any


def check_unused_roles(session, days: int = 90) -> list[dict[str, Any]]:
    findings = []
    iam = session.client("iam")
    now = datetime.now(timezone.utc)

    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            created_str = role.get("CreateDate")

            # Skip AWS service-linked roles
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue

            # Get full role details for RoleLastUsed
            role_detail = iam.get_role(RoleName=role_name)["Role"]
            last_used_info = role_detail.get("RoleLastUsed", {})
            last_used_date = last_used_info.get("LastUsedDate")

            create_date = role.get("CreateDate")
            if hasattr(create_date, "tzinfo") and create_date.tzinfo is None:
                create_date = create_date.replace(tzinfo=timezone.utc)

            if last_used_date is None:
                # Role has NEVER been assumed
                if create_date:
                    age_days = (now - create_date).days
                    if age_days > 30:
                        findings.append({
                            "check": "unused_role",
                            "severity": "LOW",
                            "resource_type": "Role",
                            "resource_name": role_name,
                            "resource_arn": role_arn,
                            "issues": [
                                f"Role has NEVER been assumed ({age_days} days since creation)"
                            ],
                            "description": (
                                f"Role '{role_name}' has existed for {age_days} days "
                                "but has never been assumed."
                            ),
                            "remediation": (
                                "Verify this role is still needed. If not, delete it to reduce "
                                "your attack surface. If it's new, this is expected."
                            ),
                        })
            else:
                # Normalize timezone
                if hasattr(last_used_date, "tzinfo") and last_used_date.tzinfo is None:
                    last_used_date = last_used_date.replace(tzinfo=timezone.utc)

                unused_days = (now - last_used_date).days
                if unused_days > days:
                    findings.append({
                        "check": "unused_role",
                        "severity": "LOW",
                        "resource_type": "Role",
                        "resource_name": role_name,
                        "resource_arn": role_arn,
                        "issues": [
                            f"Role not assumed in {unused_days} days (threshold: {days})"
                        ],
                        "description": (
                            f"Role '{role_name}' has not been assumed in {unused_days} days."
                        ),
                        "remediation": (
                            "Confirm this role is still needed. If inactive, consider deleting it. "
                            "If it's a break-glass / emergency role, document this and suppress the finding."
                        ),
                    })

    return findings
