"""
CloudTrail Least-Privilege Analyzer

Pulls CloudTrail event history for an IAM user, extracts every API call
they actually made, and generates a minimal least-privilege IAM policy
based on real usage — not what's currently allowed.

This is conceptually what AWS IAM Access Analyzer's "Generate IAM policy"
feature does under the hood.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Any


# CloudTrail eventSource → IAM action prefix
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
    "es.amazonaws.com":                    "es",
    "states.amazonaws.com":                "states",
    "events.amazonaws.com":                "events",
    "cognito-idp.amazonaws.com":           "cognito-idp",
    "acm.amazonaws.com":                   "acm",
    "waf.amazonaws.com":                   "waf",
    "shield.amazonaws.com":                "shield",
    "config.amazonaws.com":                "config",
    "cloudtrail.amazonaws.com":            "cloudtrail",
    "backup.amazonaws.com":                "backup",
    "transfer.amazonaws.com":              "transfer",
    "lightsail.amazonaws.com":             "lightsail",
    "batch.amazonaws.com":                 "batch",
    "emr.amazonaws.com":                   "elasticmapreduce",
    "sagemaker.amazonaws.com":             "sagemaker",
    "bedrock.amazonaws.com":               "bedrock",
}


def analyze_user(session, username: str, days: int = 90) -> dict[str, Any]:
    """
    Analyze CloudTrail events for an IAM user and generate a least-privilege policy.

    Returns:
      username, days_analyzed, event_count, denied_count,
      actual_actions (sorted list), unique_actions (count),
      service_breakdown (service → [actions]),
      suggested_policy (IAM policy dict)
    """
    cloudtrail = session.client("cloudtrail")

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    actual_actions: set[str] = set()
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

            # Skip access-denied events — they don't reflect actual successful usage
            raw = event.get("CloudTrailEvent", "{}")
            try:
                parsed     = json.loads(raw)
                error_code = parsed.get("errorCode", "")
                if error_code in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"):
                    denied_count += 1
                    continue
            except (json.JSONDecodeError, AttributeError):
                pass

            source = event.get("EventSource", "")
            name   = event.get("EventName", "")
            prefix = _source_to_prefix(source)

            if prefix and name:
                actual_actions.add(f"{prefix}:{name}")

    # Build per-service breakdown
    service_breakdown: dict[str, list[str]] = {}
    for action in actual_actions:
        svc, act = action.split(":", 1)
        service_breakdown.setdefault(svc, []).append(act)
    for svc in service_breakdown:
        service_breakdown[svc].sort()

    return {
        "username":          username,
        "days_analyzed":     days,
        "start_time":        start_time.isoformat(),
        "end_time":          end_time.isoformat(),
        "event_count":       event_count,
        "denied_count":      denied_count,
        "actual_actions":    sorted(actual_actions),
        "unique_actions":    len(actual_actions),
        "service_breakdown": dict(sorted(service_breakdown.items())),
        "suggested_policy":  _generate_policy(actual_actions),
    }


def _source_to_prefix(event_source: str) -> str | None:
    """Map a CloudTrail eventSource to an IAM action prefix."""
    if not event_source:
        return None
    if event_source in EVENT_SOURCE_TO_PREFIX:
        return EVENT_SOURCE_TO_PREFIX[event_source]
    # Best-effort fallback: strip .amazonaws.com suffix
    base = event_source.split(".")[0]
    return base if base else None


def _generate_policy(actions: set[str]) -> dict:
    """
    Build a minimal IAM policy from a set of 'service:Action' strings.
    Groups actions into one statement per service for readability.
    Resource is * — a future version could extract specific ARNs from events.
    """
    if not actions:
        return {
            "Version": "2012-10-17",
            "Statement": [],
        }

    by_service: dict[str, list[str]] = {}
    for action in sorted(actions):
        svc, _ = action.split(":", 1)
        by_service.setdefault(svc, []).append(action)

    statements = []
    for svc in sorted(by_service.keys()):
        sid = svc.replace("-", "").capitalize() + "LeastPrivilege"
        statements.append({
            "Sid":      sid,
            "Effect":   "Allow",
            "Action":   sorted(by_service[svc]),
            "Resource": "*",
        })

    return {
        "Version":   "2012-10-17",
        "Statement": statements,
    }
