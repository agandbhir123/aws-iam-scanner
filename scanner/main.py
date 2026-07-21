"""
AWS IAM Misconfiguration & Least-Privilege Scanner
Entry point: python -m scanner [options]
"""

import argparse
import sys

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .client import get_session
from .checks.wildcard_policies import check_wildcard_policies
from .checks.unused_keys import check_unused_keys
from .checks.direct_attachments import check_direct_attachments
from .checks.trust_policies import check_trust_policies
from .checks.unused_roles import check_unused_roles
from .checks.mfa_enforcement import check_mfa_enforcement
from .checks.s3_public_access import check_s3_public_access
from .report import generate_report

console = Console()


def main():
    parser = argparse.ArgumentParser(
        prog="python -m scanner",
        description="AWS IAM Misconfiguration & Least-Privilege Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python -m scanner
  python -m scanner --profile dev --region us-west-2
  python -m scanner --output results.json --days 60
  python -m scanner --verbose
        """,
    )
    parser.add_argument(
        "--profile",
        help="AWS CLI named profile (default: uses environment / default profile)",
        default=None,
    )
    parser.add_argument(
        "--region",
        help="AWS region for STS validation (default: us-east-1)",
        default="us-east-1",
    )
    parser.add_argument(
        "--output",
        help="Path to write JSON report (default: iam_scan_report.json)",
        default="iam_scan_report.json",
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Days threshold for flagging unused keys and roles (default: 90)",
        default=90,
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show remediation steps for every finding",
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        choices=["wildcard", "keys", "attachments", "trust", "roles", "mfa", "s3"],
        help="Skip specific checks",
        default=[],
    )

    args = parser.parse_args()

    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║   AWS IAM Security Scanner v1.0      ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════╝[/bold cyan]")
    console.print()

    # --- Connect ---
    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), transient=True
    ) as progress:
        progress.add_task("Connecting to AWS...", total=None)
        try:
            session, identity = get_session(args.profile, args.region)
        except RuntimeError as e:
            console.print(f"[bold red]✗ Connection failed:[/bold red] {e}")
            sys.exit(1)

    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    console.print(
        f"[green]✓[/green] Connected  "
        f"account=[bold]{account_id}[/bold]  "
        f"caller=[dim]{caller_arn}[/dim]"
    )
    console.print(
        f"[dim]  Threshold: {args.days} days  |  "
        f"Output: {args.output}[/dim]\n"
    )

    # --- Run checks ---
    checks = [
        ("wildcard",     "Wildcard policies",              check_wildcard_policies,  [session]),
        ("keys",         "Stale / unrotated access keys",  check_unused_keys,        [session, args.days]),
        ("attachments",  "Direct policy attachments",      check_direct_attachments, [session]),
        ("trust",        "Permissive trust policies",      check_trust_policies,     [session]),
        ("roles",        "Unused roles",                   check_unused_roles,       [session, args.days]),
        ("mfa",          "MFA enforcement",                check_mfa_enforcement,    [session]),
        ("s3",           "S3 public access",               check_s3_public_access,   [session]),
    ]

    all_findings = []

    for skip_key, label, check_fn, check_args in checks:
        if skip_key in args.skip:
            console.print(f"[dim]  — Skipping {label}[/dim]")
            continue

        with Progress(
            SpinnerColumn(), TextColumn(f"  Scanning: {label}..."), transient=True
        ) as progress:
            progress.add_task("", total=None)
            try:
                findings = check_fn(*check_args)
                all_findings.extend(findings)
                count = len(findings)
                icon = "[green]✓[/green]" if count == 0 else "[yellow]![/yellow]"
                console.print(f"  {icon} {label:<35} [bold]{count}[/bold] finding(s)")
            except Exception as e:
                console.print(
                    f"  [red]✗[/red] {label:<35} [red]Error: {e}[/red]"
                )

    console.print()

    # --- Generate report ---
    generate_report(all_findings, args.output, args.verbose, account_id)


if __name__ == "__main__":
    main()
