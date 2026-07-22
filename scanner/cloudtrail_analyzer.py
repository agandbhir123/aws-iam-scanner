from __future__ import annotations

"""
CloudTrail Least-Privilege Analyzer — with Resource-Level ARN Narrowing

For each CloudTrail event, extracts the actual resource ARN from
requestParameters (not just the action). The generated policy uses
specific ARNs where possible, falling back to * only where the resource
can't be determined.

This is the key differentiator from AWS IAM Access Analyzer's basic mode
and every open-source IAM scanner — specific resource narrowing means the
output is genuinely least-privilege, not just least-action.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Any


# ── Service → IAM action prefix ───────────────────────────────────────────────
EVENT_SOURCE_TO_PREFIX: dict[str, str] = {
    "s3.amazonaws.com":                    "s3",
    "ec2.amazonaws.com":                   "ec2",
    "iam.amazonaws.com":                   "iam",
    "lambda.amazonaws.com":                "lambda",
    "dynamodb.amazonaws.com":              "dynamodb",
    "rds.amazonaws.com":                   "rds",
    "cloudformation.amazonaws.com":        "cloudformation",
    "cloudwatch.amazonaws.com":            "cloudwatch",
    "logs.amazonaws.com":                  "logs",
    "sns.amazonaws.com":                   "sns",
    "sqs.amazonaws.com":                   "sqs",
    "kms.amazonaws.com":                   "kms",
    "sts.amazonaws.com":                   "sts",
    "secretsmanager.amazonaws.com":        "secretsmanager",
    "ssm.amazonaws.com":                   "ssm",
    "elasticloadbalancing.amazonaws.com":  "elasticloadbalancing",
    "autoscaling.amazonaws.com":           "autoscaling",
    "codecommit.amazonaws.com":            "codecommit",
    "codebuild.amazonaws.com":             "codebuild",
    "codedeploy.amazonaws.com":            "codedeploy",
    "codepipeline.amazonaws.com":          "codepipeline",
    "ecr.amazonaws.com":                   "ecr",
    "ecs.amazonaws.com":                   "ecs",
    "eks.amazonaws.com":                   "eks",
    "elasticache.amazonaws.com":           "elasticache",
    "route53.amazonaws.com":               "route53",
    "cloudfront.amazonaws.com":            "cloudfront",
    "apigateway.amazonaws.com":            "execute-api",
    "firehose.amazonaws.com":              "firehose",
    "kinesis.amazonaws.com":               "kinesis",
    "athena.amazonaws.com":                "athena",
    "glue.amazonaws.com":                  "glue",
    "redshift.amazonaws.com":              "redshift",
    "states.amazonaws.com":                "states",
    "events.amazonaws.com":                "events",
    "cognito-idp.amazonaws.com":           "cognito-idp",
    "acm.amazonaws.com":                   "acm",
    "config.amazonaws.com":                "config",
    "cloudtrail.amazonaws.com":            "cloudtrail",
    "backup.amazonaws.com":                "backup",
    "sagemaker.amazonaws.com":             "sagemaker",
    "bedrock.amazonaws.com":               "bedrock",
}


# ── Per-service resource extractors ──────────────────────────────────────────
# Each returns: list[str] of ARNs if found, None if unknown (fall back to *)
# An empty list means "no specific resource needed" (e.g., list-all operations)

def _s3(params: dict, action: str, account: str, region: str) -> list[str] | None:
    bucket = params.get("bucketName")
    if not bucket:
        return None  # Can't determine → *
    key = params.get("key") or params.get("prefix") or ""
    if key:
        # Object-level access — scope to the key prefix
        prefix = key.rsplit("/", 1)[0] + "/*" if "/" in key else "*"
        return [
            f"arn:aws:s3:::{bucket}",
            f"arn:aws:s3:::{bucket}/{prefix}",
        ]
    else:
        # Bucket-level access
        return [
            f"arn:aws:s3:::{bucket}",
            f"arn:aws:s3:::{bucket}/*",
        ]


def _iam(params: dict, action: str, account: str, region: str) -> list[str] | None:
    # Try most specific fields first
    if "policyArn" in params:
        return [params["policyArn"]]
    if "roleArn" in params:
        return [params["roleArn"]]
    if "roleName" in params:
        return [f"arn:aws:iam::{account}:role/{params['roleName']}"]
    if "userName" in params:
        return [f"arn:aws:iam::{account}:user/{params['userName']}"]
    if "groupName" in params:
        return [f"arn:aws:iam::{account}:group/{params['groupName']}"]
    if "instanceProfileName" in params:
        return [f"arn:aws:iam::{account}:instance-profile/{params['instanceProfileName']}"]
    # List operations and account-level calls have no specific resource
    list_actions = {
        "iam:ListRoles", "iam:ListUsers", "iam:ListGroups",
        "iam:ListPolicies", "iam:GetAccountSummary",
        "iam:GenerateCredentialReport", "iam:GetCredentialReport",
    }
    if action in list_actions:
        return []  # No specific resource — wildcard is correct
    return None


def _lambda(params: dict, action: str, account: str, region: str) -> list[str] | None:
    name = params.get("functionName")
    if not name:
        return None
    if name.startswith("arn:"):
        return [name]
    return [f"arn:aws:lambda:{region}:{account}:function:{name}"]


def _dynamodb(params: dict, action: str, account: str, region: str) -> list[str] | None:
    name = params.get("tableName")
    if not name:
        return None
    if name.startswith("arn:"):
        return [name]
    return [f"arn:aws:dynamodb:{region}:{account}:table/{name}"]


def _sqs(params: dict, action: str, account: str, region: str) -> list[str] | None:
    url = params.get("queueUrl")
    if not url:
        arn = params.get("queueArn")
        return [arn] if arn else None
    # Parse queue URL: https://sqs.REGION.amazonaws.com/ACCOUNT/QUEUE_NAME
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        queue_name = parts[-1]
        acct = parts[-2] if parts[-2].isdigit() else account
        return [f"arn:aws:sqs:{region}:{acct}:{queue_name}"]
    return None


def _sns(params: dict, action: str, account: str, region: str) -> list[str] | None:
    arn = params.get("topicArn") or params.get("subscriptionArn")
    return [arn] if arn else None


def _kms(params: dict, action: str, account: str, region: str) -> list[str] | None:
    key_id = params.get("keyId")
    if not key_id:
        return None
    if key_id.startswith("arn:"):
        return [key_id]
    if "-" in key_id and len(key_id) == 36:
        return [f"arn:aws:kms:{region}:{account}:key/{key_id}"]
    # Alias — use as-is
    return [f"arn:aws:kms:{region}:{account}:alias/{key_id.lstrip('alias/')}"]


def _logs(params: dict, action: str, account: str, region: str) -> list[str] | None:
    group = params.get("logGroupName")
    if not group:
        return None
    stream = params.get("logStreamName")
    if stream:
        return [
            f"arn:aws:logs:{region}:{account}:log-group:{group}:log-stream:{stream}",
        ]
    return [
        f"arn:aws:logs:{region}:{account}:log-group:{group}",
        f"arn:aws:logs:{region}:{account}:log-group:{group}:*",
    ]


def _secretsmanager(params: dict, action: str, account: str, region: str) -> list[str] | None:
    secret = params.get("secretId")
    if not secret:
        return None
    if secret.startswith("arn:"):
        return [secret]
    return [f"arn:aws:secretsmanager:{region}:{account}:secret:{secret}"]


def _sts(params: dict, action: str, account: str, region: str) -> list[str] | None:
    role = params.get("roleArn")
    if role:
        return [role]
    # GetCallerIdentity and similar have no resource
    return []


def _rds(params: dict, action: str, account: str, region: str) -> list[str] | None:
    db = params.get("dBInstanceIdentifier") or params.get("dbInstanceIdentifier")
    if db:
        return [f"arn:aws:rds:{region}:{account}:db:{db}"]
    cluster = params.get("dBClusterIdentifier")
    if cluster:
        return [f"arn:aws:rds:{region}:{account}:cluster:{cluster}"]
    return None


def _ssm(params: dict, action: str, account: str, region: str) -> list[str] | None:
    name = params.get("name") or params.get("parameterName")
    if not name:
        return None
    if name.startswith("arn:"):
        return [name]
    return [f"arn:aws:ssm:{region}:{account}:parameter/{name.lstrip('/')}"]


def _states(params: dict, action: str, account: str, region: str) -> list[str] | None:
    arn = params.get("stateMachineArn") or params.get("executionArn")
    return [arn] if arn else None


def _ecr(params: dict, action: str, account: str, region: str) -> list[str] | None:
    name = params.get("repositoryName")
    if not name:
        return None
    return [f"arn:aws:ecr:{region}:{account}:repository/{name}"]


RESOURCE_EXTRACTORS = {
    "s3":             _s3,
    "iam":            _iam,
    "lambda":         _lambda,
    "dynamodb":       _dynamodb,
    "sqs":            _sqs,
    "sns":            _sns,
    "kms":            _kms,
    "logs":           _logs,
    "secretsmanager": _secretsmanager,
    "sts":            _sts,
    "rds":            _rds,
    "ssm":            _ssm,
    "states":         _states,
    "ecr":            _ecr,
}


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_user(session, username: str, days: int = 90) -> dict[str, Any]:
    """
    Analyze CloudTrail events for an IAM user and generate a least-privilege
    policy with resource-level ARN narrowing where possible.

    Returns:
      username, days_analyzed, event_count, denied_count,
      unique_actions, service_breakdown,
      action_resources (action → specific ARNs or None),
      narrowed_count, wildcarded_count, narrowed_pct,
      suggested_policy
    """
    cloudtrail = session.client("cloudtrail")
    sts        = session.client("sts")

    # Get account ID and region for ARN construction
    identity   = sts.get_caller_identity()
    account_id = identity["Account"]
    region     = session.region_name or "us-east-1"

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    # action → set of specific ARN strings (or None sentinel for wildcard)
    action_resources: dict[str, set[str] | None] = {}
    event_count  = 0
    denied_count = 0

    paginator = cloudtrail.get_paginator("lookup_events")
    pages = paginator.paginate(
        LookupAttributes=[{
            "AttributeKey": "Username",
            "AttributeValue": username,
        }],
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"PageSize": 50},
    )

    for page in pages:
        for event in page.get("Events", []):
            event_count += 1

            raw = event.get("CloudTrailEvent", "{}")
            try:
                parsed     = json.loads(raw)
                error_code = parsed.get("errorCode", "")
                if error_code in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"):
                    denied_count += 1
                    continue
            except (json.JSONDecodeError, AttributeError):
                parsed = {}

            source = event.get("EventSource", "")
            name   = event.get("EventName", "")
            prefix = _source_to_prefix(source)
            if not (prefix and name):
                continue

            action = f"{prefix}:{name}"
            params = parsed.get("requestParameters") or {}

            # Try to extract specific resource ARN(s)
            extractor = RESOURCE_EXTRACTORS.get(prefix)
            arns: list[str] | None = None
            if extractor:
                try:
                    arns = extractor(params, action, account_id, region)
                except Exception:
                    arns = None

            # Merge into action_resources
            if action not in action_resources:
                # First time seeing this action
                if arns is None:
                    action_resources[action] = None  # Mark as wildcard
                else:
                    action_resources[action] = set(arns)
            else:
                existing = action_resources[action]
                if existing is None:
                    pass  # Already marked wildcard — stays wildcard
                elif arns is None:
                    action_resources[action] = None  # Upgrade to wildcard
                else:
                    existing.update(arns)

    # ── Build per-service breakdown ───────────────────────────────────────────
    service_breakdown: dict[str, list[str]] = {}
    for action in action_resources:
        svc, act = action.split(":", 1)
        service_breakdown.setdefault(svc, []).append(act)
    for svc in service_breakdown:
        service_breakdown[svc].sort()

    # ── Count narrowed vs wildcarded ──────────────────────────────────────────
    narrowed   = [a for a, r in action_resources.items() if r is not None]
    wildcarded = [a for a, r in action_resources.items() if r is None]
    total      = len(action_resources)
    narrowed_pct = round(len(narrowed) / total * 100) if total else 0

    # ── Generate policy ───────────────────────────────────────────────────────
    suggested_policy = _generate_policy(action_resources)

    # Serializable version of action_resources
    action_resources_out = {
        action: sorted(resources) if resources is not None else None
        for action, resources in action_resources.items()
    }

    return {
        "username":           username,
        "days_analyzed":      days,
        "start_time":         start_time.isoformat(),
        "end_time":           end_time.isoformat(),
        "event_count":        event_count,
        "denied_count":       denied_count,
        "actual_actions":     sorted(action_resources.keys()),
        "unique_actions":     total,
        "service_breakdown":  dict(sorted(service_breakdown.items())),
        "action_resources":   action_resources_out,
        "narrowed_count":     len(narrowed),
        "wildcarded_count":   len(wildcarded),
        "narrowed_pct":       narrowed_pct,
        "suggested_policy":   suggested_policy,
    }


# ── Policy generator with resource narrowing ──────────────────────────────────

def _generate_policy(action_resources: dict[str, set[str] | None]) -> dict:
    """
    Build an IAM policy from action → resource set mapping.

    Strategy:
      1. Group actions that have the exact same specific resource set into
         one statement (minimises statement count).
      2. Actions with no specific resources (empty set, e.g. list operations)
         get Resource: "*" with a clear Sid noting why.
      3. Actions where resource extraction failed (None) also get Resource: "*"
         in a separate fallback statement.
    """
    if not action_resources:
        return {"Version": "2012-10-17", "Statement": []}

    # Bucket: frozenset(ARNs) → list of actions
    resource_to_actions: dict[frozenset, list[str]] = {}
    wildcard_actions: list[str] = []       # Resource unknown → *
    no_resource_actions: list[str] = []    # List-all / account-level → *

    for action, resources in sorted(action_resources.items()):
        if resources is None:
            wildcard_actions.append(action)
        elif len(resources) == 0:
            no_resource_actions.append(action)
        else:
            key = frozenset(resources)
            resource_to_actions.setdefault(key, []).append(action)

    statements = []

    # Specific-resource statements
    for resource_set, actions in sorted(
        resource_to_actions.items(),
        key=lambda kv: sorted(kv[1])[0]
    ):
        arns = sorted(resource_set)
        services = sorted({a.split(":")[0] for a in actions})
        sid = "".join(s.capitalize() for s in services) + "NarrowedAccess"
        statements.append({
            "Sid":      sid,
            "Effect":   "Allow",
            "Action":   sorted(actions),
            "Resource": arns[0] if len(arns) == 1 else arns,
            "_narrowed": True,   # metadata — strip before applying
        })

    # Account / list-level actions (correctly need Resource: *)
    if no_resource_actions:
        statements.append({
            "Sid":      "AccountLevelActions",
            "Effect":   "Allow",
            "Action":   sorted(no_resource_actions),
            "Resource": "*",
            "_note":    "These actions operate at the account level and correctly require Resource: *",
        })

    # Fallback wildcard — resource couldn't be determined
    if wildcard_actions:
        statements.append({
            "Sid":      "FallbackWildcard",
            "Effect":   "Allow",
            "Action":   sorted(wildcard_actions),
            "Resource": "*",
            "_note":    (
                "Resource could not be determined for these actions. "
                "Review CloudTrail requestParameters manually to narrow further."
            ),
        })

    return {
        "Version":   "2012-10-17",
        "Statement": statements,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _source_to_prefix(event_source: str) -> str | None:
    if not event_source:
        return None
    if event_source in EVENT_SOURCE_TO_PREFIX:
        return EVENT_SOURCE_TO_PREFIX[event_source]
    base = event_source.split(".")[0]
    return base or None