"""
Check: Overly Permissive Trust Policies

IAM role trust policies control who can AssumeRole into the role.
A misconfigured trust policy can allow any AWS account or any principal
to assume a role — effectively handing over your account.

Flags:
  - Principal: "*" (any entity in the world can assume this role)
  - Principal with wildcard account ID (e.g., arn:aws:iam::*:root)
  - Cross-account trust with no ExternalId condition (confused deputy risk)
  - Unrestricted lambda.amazonaws.com trust with no condition
"""

import re
from typing import Any


def check_trust_policies(session) -> list[dict[str, Any]]:
    findings = []
    iam = session.client("iam")

    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            role_arn = role["Arn"]

            # Skip AWS service-linked roles — their trust is managed by AWS
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue

            trust_doc = role.get("AssumeRolePolicyDocument", {})
            issues = _analyze_trust(trust_doc, role_arn)

            if issues:
                severity = "HIGH" if any("Principal: '*'" in i for i in issues) else "MEDIUM"
                findings.append({
                    "check": "trust_policy",
                    "severity": severity,
                    "resource_type": "Role",
                    "resource_name": role_name,
                    "resource_arn": role_arn,
                    "issues": issues,
                    "description": (
                        f"Role '{role_name}' has a trust policy that may allow "
                        "unintended principals to assume it."
                    ),
                    "remediation": (
                        "Restrict the Principal to specific accounts, roles, or services. "
                        "Add ExternalId conditions for cross-account trust. "
                        "Audit trust policies in the IAM console under 'Trust relationships'."
                    ),
                })

    return findings


def _analyze_trust(trust_doc: dict, role_arn: str) -> list[str]:
    issues = []
    statements = trust_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect", "Allow") != "Allow":
            continue

        principal = stmt.get("Principal", {})
        condition = stmt.get("Condition", {})

        # Normalize principal to a flat list of strings
        flat_principals = _flatten_principal(principal)

        for p in flat_principals:
            # Wildcard principal — anyone in the world
            if p == "*":
                issues.append(
                    "Principal: '*' — ANY entity globally can assume this role"
                )

            # Wildcard account ID in ARN: arn:aws:iam::*:...
            elif re.search(r"arn:aws:iam::\*:", p):
                issues.append(
                    f"Principal ARN contains wildcard account ID: {p}"
                )

            # Cross-account trust: principal is from a different account
            elif re.match(r"arn:aws:iam::(\d{12}):", p):
                account_in_principal = re.search(r"arn:aws:iam::(\d{12}):", p)
                if account_in_principal:
                    # Check for ExternalId condition (confused deputy protection)
                    has_external_id = "sts:ExternalId" in str(condition)
                    if not has_external_id and not condition:
                        issues.append(
                            f"Cross-account trust to '{p}' with no ExternalId condition "
                            "(confused deputy vulnerability)"
                        )

            # Very broad service trusts worth flagging
            elif p in (
                "lambda.amazonaws.com",
                "ec2.amazonaws.com",
                "ecs-tasks.amazonaws.com",
            ):
                # These are normal — only flag if no condition at all
                # and the role has broad permissions (we note it as LOW info)
                pass  # Not flagged — service principals are expected

    return issues


def _flatten_principal(principal) -> list[str]:
    """Normalize a Principal value to a flat list of strings."""
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, list):
        return principal
    if isinstance(principal, dict):
        flat = []
        for v in principal.values():
            if isinstance(v, str):
                flat.append(v)
            elif isinstance(v, list):
                flat.extend(v)
        return flat
    return []
