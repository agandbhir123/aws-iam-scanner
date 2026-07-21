"""
Check: Stale / Unrotated Access Keys

Uses the IAM credential report (CSV) to flag:
  - Active access keys older than `days` days (rotation risk)
  - Active access keys never used (unnecessary standing access)
  - Active access keys unused for `days` days
"""

import csv
import io
import time
from datetime import datetime, timezone
from typing import Any


def check_unused_keys(session, days: int = 90) -> list[dict[str, Any]]:
    findings = []
    iam = session.client("iam")

    report_csv = _get_credential_report(iam)
    reader = csv.DictReader(io.StringIO(report_csv))
    now = datetime.now(timezone.utc)

    for row in reader:
        username = row["user"]

        # Skip the root account row (handled separately)
        if username == "<root_account>":
            # Root access keys are always a HIGH finding if active
            for key_num in ("1", "2"):
                if row.get(f"access_key_{key_num}_active", "false").lower() == "true":
                    findings.append({
                        "check": "unused_keys",
                        "severity": "HIGH",
                        "resource_type": "AccessKey/Root",
                        "resource_name": f"root → key_{key_num}",
                        "resource_arn": "arn:aws:iam::root",
                        "issues": ["Root account has an active access key"],
                        "description": (
                            "The root account has an active access key. "
                            "Root keys should never exist — use IAM users or roles instead."
                        ),
                        "remediation": (
                            "Delete root access keys immediately. "
                            "Use IAM users or assume-role for all programmatic access."
                        ),
                    })
            continue

        for key_num in ("1", "2"):
            active = row.get(f"access_key_{key_num}_active", "false").lower() == "true"
            if not active:
                continue

            last_rotated_str = row.get(f"access_key_{key_num}_last_rotated", "N/A")
            last_used_str = row.get(f"access_key_{key_num}_last_used_date", "N/A")

            key_issues = []
            severity = "MEDIUM"

            # Check key age (rotation)
            if last_rotated_str not in ("N/A", "no_information", ""):
                last_rotated = _parse_iso(last_rotated_str)
                if last_rotated:
                    age_days = (now - last_rotated).days
                    if age_days > days:
                        key_issues.append(
                            f"Key not rotated in {age_days} days (threshold: {days})"
                        )

            # Check last used
            if last_used_str in ("N/A", "no_information", ""):
                # Key has never been used — flag if older than 30 days
                if last_rotated_str not in ("N/A", "no_information", ""):
                    last_rotated = _parse_iso(last_rotated_str)
                    if last_rotated:
                        age_days = (now - last_rotated).days
                        if age_days > 30:
                            key_issues.append(
                                f"Key is active but has NEVER been used ({age_days} days old)"
                            )
            else:
                last_used = _parse_iso(last_used_str)
                if last_used:
                    unused_days = (now - last_used).days
                    if unused_days > days:
                        key_issues.append(
                            f"Key not used in {unused_days} days (threshold: {days})"
                        )

            if key_issues:
                findings.append({
                    "check": "unused_keys",
                    "severity": severity,
                    "resource_type": "AccessKey",
                    "resource_name": f"{username} → key_{key_num}",
                    "resource_arn": f"arn:aws:iam::user/{username}/key_{key_num}",
                    "issues": key_issues,
                    "description": (
                        f"Access key {key_num} for user '{username}' may be stale or unnecessary."
                    ),
                    "remediation": (
                        "Rotate the key if still needed, or deactivate and delete it. "
                        "Prefer short-lived credentials (IAM roles, STS) over long-lived access keys."
                    ),
                })

    return findings


def _get_credential_report(iam) -> str:
    """Generate and download the IAM credential report. Polls until ready."""
    # Kick off report generation
    while True:
        response = iam.generate_credential_report()
        state = response.get("State", "")
        if state == "COMPLETE":
            break
        elif state in ("STARTED", "INPROGRESS"):
            time.sleep(2)
        else:
            # Unexpected state — try downloading anyway
            break

    report = iam.get_credential_report()
    return report["Content"].decode("utf-8")


def _parse_iso(date_str: str):
    """Parse an ISO 8601 datetime string, return None on failure."""
    try:
        # Handle both with and without timezone
        if date_str.endswith("Z"):
            date_str = date_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None
