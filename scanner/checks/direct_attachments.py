"""
Check: Direct Policy Attachments to Users

Best practice: IAM users should get permissions via group membership only.
Attaching policies directly to users is harder to audit and manage at scale.

Flags:
  - Users with any managed policies attached directly
  - Users with inline policies (always direct, always flagged)
"""

from typing import Any


def check_direct_attachments(session) -> list[dict[str, Any]]:
    findings = []
    iam = session.client("iam")

    user_paginator = iam.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            user_arn = user["Arn"]

            # Check directly attached managed policies
            attached = []
            attached_paginator = iam.get_paginator("list_attached_user_policies")
            for ap in attached_paginator.paginate(UserName=username):
                attached.extend(ap["AttachedPolicies"])

            if attached:
                policy_names = [p["PolicyName"] for p in attached]
                findings.append({
                    "check": "direct_attachment",
                    "severity": "MEDIUM",
                    "resource_type": "User",
                    "resource_name": username,
                    "resource_arn": user_arn,
                    "issues": [
                        f"Has {len(policy_names)} managed policy(ies) attached directly: "
                        f"{', '.join(policy_names)}"
                    ],
                    "description": (
                        f"User '{username}' has managed policies attached directly rather than via a group."
                    ),
                    "remediation": (
                        "Create an IAM group with these policies, add the user to the group, "
                        "then detach the policies from the user directly."
                    ),
                })

            # Check inline policies
            inline = []
            inline_paginator = iam.get_paginator("list_user_policies")
            for ip in inline_paginator.paginate(UserName=username):
                inline.extend(ip["PolicyNames"])

            if inline:
                findings.append({
                    "check": "direct_attachment",
                    "severity": "MEDIUM",
                    "resource_type": "User",
                    "resource_name": username,
                    "resource_arn": user_arn,
                    "issues": [
                        f"Has {len(inline)} inline policy(ies): {', '.join(inline)}"
                    ],
                    "description": (
                        f"User '{username}' has inline policies, which are harder to audit and reuse."
                    ),
                    "remediation": (
                        "Convert inline policies to managed policies and attach via groups. "
                        "Inline policies are invisible in the policy list and harder to audit."
                    ),
                })

    return findings
