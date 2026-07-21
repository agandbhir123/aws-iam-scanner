"""
Check: Wildcard Actions / Resources in IAM Policies

Scans:
  - Customer-managed policies (attached to anything)
  - Inline policies on users, groups, and roles

Flags:
  - Action: "*" (full admin)
  - Action: "service:*" (full service admin)
  - Resource: "*" combined with broad actions
"""

from typing import Any


# AWS-managed admin policies worth flagging when attached
ADMIN_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}


def check_wildcard_policies(session) -> list[dict[str, Any]]:
    findings = []
    iam = session.client("iam")

    # --- Customer-managed policies ---
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            arn = policy["Arn"]
            name = policy["PolicyName"]
            version_id = policy["DefaultVersionId"]

            version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            doc = version["PolicyVersion"]["Document"]
            issues = _scan_document(doc)

            if issues:
                findings.append({
                    "check": "wildcard_policy",
                    "severity": "HIGH",
                    "resource_type": "ManagedPolicy",
                    "resource_name": name,
                    "resource_arn": arn,
                    "issues": issues,
                    "description": f"Managed policy '{name}' grants overly broad permissions.",
                    "remediation": (
                        "Restrict to only the specific actions and resources this policy needs. "
                        "Use IAM Access Analyzer to generate a least-privilege policy from CloudTrail activity."
                    ),
                })

    # --- Check for AWS managed admin policies attached to users/roles ---
    for admin_arn in ADMIN_MANAGED_POLICIES:
        try:
            policy_name = admin_arn.split("/")[-1]
            entity_paginator = iam.get_paginator("list_entities_for_policy")
            for page in entity_paginator.paginate(PolicyArn=admin_arn):
                for user in page.get("PolicyUsers", []):
                    findings.append({
                        "check": "wildcard_policy",
                        "severity": "HIGH",
                        "resource_type": "User",
                        "resource_name": user["UserName"],
                        "resource_arn": f"arn:aws:iam::user/{user['UserName']}",
                        "issues": [f"Has AWS managed policy '{policy_name}' directly attached"],
                        "description": (
                            f"User '{user['UserName']}' has the AWS managed "
                            f"'{policy_name}' policy attached — full admin access."
                        ),
                        "remediation": "Remove this policy. Grant only the permissions needed for this user's role.",
                    })
                for role in page.get("PolicyRoles", []):
                    findings.append({
                        "check": "wildcard_policy",
                        "severity": "HIGH",
                        "resource_type": "Role",
                        "resource_name": role["RoleName"],
                        "resource_arn": f"arn:aws:iam::role/{role['RoleName']}",
                        "issues": [f"Has AWS managed policy '{policy_name}' directly attached"],
                        "description": (
                            f"Role '{role['RoleName']}' has the AWS managed "
                            f"'{policy_name}' policy attached — full admin access."
                        ),
                        "remediation": "Scope down permissions to what this role actually needs.",
                    })
        except iam.exceptions.NoSuchEntityException:
            pass

    # --- Inline policies on users ---
    user_paginator = iam.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            ip_paginator = iam.get_paginator("list_user_policies")
            for ip_page in ip_paginator.paginate(UserName=username):
                for policy_name in ip_page["PolicyNames"]:
                    doc = iam.get_user_policy(
                        UserName=username, PolicyName=policy_name
                    )["PolicyDocument"]
                    issues = _scan_document(doc)
                    if issues:
                        findings.append({
                            "check": "wildcard_policy",
                            "severity": "HIGH",
                            "resource_type": "InlinePolicy/User",
                            "resource_name": f"{username} → {policy_name}",
                            "resource_arn": f"inline:user/{username}/{policy_name}",
                            "issues": issues,
                            "description": (
                                f"Inline policy '{policy_name}' on user '{username}' "
                                "grants overly broad permissions."
                            ),
                            "remediation": (
                                "Convert to a managed policy and scope down to "
                                "specific actions and resources."
                            ),
                        })

    # --- Inline policies on roles ---
    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            # Skip AWS service-linked roles
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            ip_paginator = iam.get_paginator("list_role_policies")
            for ip_page in ip_paginator.paginate(RoleName=role_name):
                for policy_name in ip_page["PolicyNames"]:
                    doc = iam.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )["PolicyDocument"]
                    issues = _scan_document(doc)
                    if issues:
                        findings.append({
                            "check": "wildcard_policy",
                            "severity": "HIGH",
                            "resource_type": "InlinePolicy/Role",
                            "resource_name": f"{role_name} → {policy_name}",
                            "resource_arn": f"inline:role/{role_name}/{policy_name}",
                            "issues": issues,
                            "description": (
                                f"Inline policy '{policy_name}' on role '{role_name}' "
                                "grants overly broad permissions."
                            ),
                            "remediation": (
                                "Scope down to specific actions and resources needed by this role."
                            ),
                        })

    # --- Inline policies on groups ---
    group_paginator = iam.get_paginator("list_groups")
    for page in group_paginator.paginate():
        for group in page["Groups"]:
            group_name = group["GroupName"]
            ip_paginator = iam.get_paginator("list_group_policies")
            for ip_page in ip_paginator.paginate(GroupName=group_name):
                for policy_name in ip_page["PolicyNames"]:
                    doc = iam.get_group_policy(
                        GroupName=group_name, PolicyName=policy_name
                    )["PolicyDocument"]
                    issues = _scan_document(doc)
                    if issues:
                        findings.append({
                            "check": "wildcard_policy",
                            "severity": "HIGH",
                            "resource_type": "InlinePolicy/Group",
                            "resource_name": f"{group_name} → {policy_name}",
                            "resource_arn": f"inline:group/{group_name}/{policy_name}",
                            "issues": issues,
                            "description": (
                                f"Inline policy '{policy_name}' on group '{group_name}' "
                                "grants overly broad permissions."
                            ),
                            "remediation": (
                                "Scope down to specific actions and resources needed by this group."
                            ),
                        })

    return findings


def _scan_document(document: dict) -> list[str]:
    """Return list of wildcard issues found in a policy document."""
    issues = []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        # Only care about Allow statements
        if stmt.get("Effect", "Allow") != "Allow":
            continue

        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])

        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        # Full admin: Action: * with Resource: *
        if "*" in action and "*" in resource:
            issues.append("Action '*' on Resource '*' — full administrator access")
        elif "*" in action:
            issues.append(f"Action '*' on Resource {resource}")
        else:
            # Service wildcards like "s3:*", "iam:*", "ec2:*"
            service_wildcards = [a for a in action if a.endswith(":*")]
            if service_wildcards:
                if "*" in resource:
                    issues.append(
                        f"Service wildcard(s) {service_wildcards} on Resource '*'"
                    )
                else:
                    issues.append(f"Service wildcard(s) {service_wildcards}")

    return issues
