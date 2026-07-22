"""
Report generation: security grade, rich CLI table, JSON file output.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text


console = Console()

SEVERITY_WEIGHTS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}

SEVERITY_COLORS = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
}

CHECK_LABELS = {
    "wildcard_policy": "Wildcard Policy",
    "unused_keys": "Stale Access Keys",
    "direct_attachment": "Direct Attachment",
    "trust_policy": "Trust Policy",
    "unused_role": "Unused Role",
    "mfa_enforcement": "MFA Enforcement",
    "s3_public_access": "S3 Public Access",
}


def generate_report(
    findings: list[dict[str, Any]],
    output_path: str,
    verbose: bool,
    account_id: str,
) -> None:
    """Print CLI report and write JSON file."""
    risk_score = _compute_score(findings)
    score      = _compute_rating(risk_score)
    grade, grade_color, grade_desc = _compute_grade(score)

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    # --- Grade Panel ---
    grade_text = Text()
    grade_text.append(f"  Grade: ", style="bold white")
    grade_text.append(f"{grade}  ", style=f"bold {grade_color}")
    grade_text.append(f"({grade_desc})\n", style="dim")
    grade_text.append(f"  Security rating: {score}/100  ", style="bold white")
    grade_text.append(
        f"[red]{high} HIGH[/red]  [yellow]{medium} MEDIUM[/yellow]  [blue]{low} LOW[/blue]  "
        f"({len(findings)} total)",
        style="",
    )

    console.print(
        Panel(
            grade_text,
            title=f"[bold cyan]IAM Security Report — Account {account_id}[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    if not findings:
        console.print("\n[bold green]No findings — your IAM config looks clean![/bold green]\n")
        _write_json(findings, output_path, account_id, grade, score)
        return

    # --- Findings Table ---
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=True,
        title=f"\n[bold]Findings ({len(findings)})[/bold]",
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Check", width=20)
    table.add_column("Resource", width=35)
    table.add_column("Issue", width=55)

    # Sort: HIGH first, then MEDIUM, then LOW
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f["severity"], 3))

    for f in sorted_findings:
        severity = f["severity"]
        color = SEVERITY_COLORS.get(severity, "white")
        check_label = CHECK_LABELS.get(f["check"], f["check"])
        resource = f["resource_name"]
        first_issue = f["issues"][0] if f["issues"] else ""

        table.add_row(
            Text(severity, style=color),
            check_label,
            resource,
            first_issue,
        )

        # If verbose or multiple issues, show the rest
        if verbose or len(f["issues"]) > 1:
            for extra_issue in f["issues"][1:]:
                table.add_row("", "", "", f"  ↳ {extra_issue}")
            if verbose:
                table.add_row(
                    "", "", "",
                    Text(f"  Fix: {f['remediation']}", style="dim italic"),
                )

    console.print(table)

    # --- Summary by check ---
    console.print("\n[bold]Findings by check:[/bold]")
    check_counts: dict[str, dict[str, int]] = {}
    for f in findings:
        check = CHECK_LABELS.get(f["check"], f["check"])
        sev = f["severity"]
        if check not in check_counts:
            check_counts[check] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        check_counts[check][sev] += 1

    for check_name, counts in check_counts.items():
        parts = []
        if counts["HIGH"]:
            parts.append(f"[red]{counts['HIGH']} HIGH[/red]")
        if counts["MEDIUM"]:
            parts.append(f"[yellow]{counts['MEDIUM']} MEDIUM[/yellow]")
        if counts["LOW"]:
            parts.append(f"[blue]{counts['LOW']} LOW[/blue]")
        console.print(f"  {check_name}: {', '.join(parts)}")

    # --- Write JSON ---
    _write_json(sorted_findings, output_path, account_id, grade, score)
    console.print(f"\n[green]✓[/green] JSON report written to [bold]{output_path}[/bold]\n")

    if not verbose and findings:
        console.print(
            "[dim]Tip: Run with --verbose to see remediation steps for each finding.[/dim]\n"
        )


def _compute_score(findings: list[dict]) -> int:
    """Compute raw risk score (internal only). Higher = more risk."""
    return sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)


def _compute_rating(risk_score: int) -> int:
    """Convert risk score to 1-100 security rating. Higher = safer."""
    return max(1, min(100, 100 - risk_score))


def _compute_grade(rating: int) -> tuple[str, str, str]:
    if rating == 100:
        return "A", "green", "No issues found"
    elif rating >= 85:
        return "B", "green", "Minor issues"
    elif rating >= 60:
        return "C", "yellow", "Moderate risk"
    elif rating >= 20:
        return "D", "red", "Significant risk"
    else:
        return "F", "bold red", "Critical — immediate action needed"


def _write_json(
    findings: list[dict],
    output_path: str,
    account_id: str,
    grade: str,
    score: int,
) -> None:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "grade": grade,
        "score": score,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "findings": findings,
    }
    Path(output_path).write_text(json.dumps(report, indent=2, default=str))