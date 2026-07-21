"""
CloudTrail Least-Privilege Analyzer CLI

Usage:
  python -m scanner.analyze --entity <iam-username> [options]

Examples:
  python -m scanner.analyze --entity deploy-admin
  python -m scanner.analyze --entity ci-runner --days 30 --output ci-policy.json
  python -m scanner.analyze --entity my-user --profile dev --region us-west-2
"""

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn

from .client import get_session
from .cloudtrail_analyzer import analyze_user

console = Console()


def main():
    parser = argparse.ArgumentParser(
        prog="python -m scanner.analyze",
        description="Generate a least-privilege IAM policy from CloudTrail event history",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
What it does:
  Pulls up to <days> days of CloudTrail events for an IAM user, extracts
  every AWS API call they actually made (skipping denied requests), and
  generates a minimal IAM policy containing exactly those permissions.

  This is conceptually what AWS IAM Access Analyzer's 'Generate policy'
  feature does — but built from scratch on top of the CloudTrail API.

examples:
  python -m scanner.analyze --entity deploy-admin
  python -m scanner.analyze --entity ci-runner --days 30
  python -m scanner.analyze --entity my-user --output my-policy.json
  python -m scanner.analyze --entity my-user --profile dev --region us-west-2
        """,
    )
    parser.add_argument(
        "--entity",
        required=True,
        metavar="USERNAME",
        help="IAM username to analyze",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=90,
        metavar="N",
        help="Days of CloudTrail history to analyze (default: 90, max: 90)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI named profile",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Write the generated policy + metadata to a JSON file",
    )

    args = parser.parse_args()

    # Cap days at 90 — CloudTrail lookup_events limit
    if args.days > 90:
        console.print("[yellow]Warning:[/yellow] CloudTrail lookup_events supports up to 90 days. Capping at 90.")
        args.days = 90

    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║  CloudTrail Least-Privilege Analyzer     ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════════╝[/bold cyan]")
    console.print()

    # Connect
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("Connecting to AWS...", total=None)
        try:
            session, identity = get_session(args.profile, args.region)
        except RuntimeError as e:
            console.print(f"[bold red]✗ Connection failed:[/bold red] {e}")
            sys.exit(1)

    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    console.print(f"[green]✓[/green] Connected  account=[bold]{account_id}[/bold]  caller=[dim]{caller_arn}[/dim]")
    console.print(f"[dim]  Analyzing [bold]{args.entity}[/bold] over the last {args.days} days ...[/dim]\n")
    console.print("  [dim]Scanning CloudTrail events — this usually takes 30–90 seconds[/dim]\n")

    # Analyze
    with Progress(SpinnerColumn(), TextColumn("  Pulling CloudTrail events..."), transient=True) as p:
        p.add_task("", total=None)
        try:
            result = analyze_user(session, args.entity, args.days)
        except session.client("cloudtrail").exceptions.TrailNotFoundException as e:
            console.print(f"[bold red]Error:[/bold red] CloudTrail trail not found: {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error during analysis:[/bold red] {e}")
            sys.exit(1)

    # ── Summary panel ─────────────────────────────────────────────────────
    if result["event_count"] == 0:
        console.print(
            f"[yellow]No CloudTrail events found for user '{args.entity}' "
            f"in the last {args.days} days.[/yellow]\n"
            "  This could mean:\n"
            "  • The username is incorrect (check spelling, case-sensitive)\n"
            "  • The user has not made any API calls in this period\n"
            "  • CloudTrail is not enabled in this region\n"
        )
        sys.exit(0)

    console.print(Panel(
        f"  [white]CloudTrail events scanned:[/white]  [bold]{result['event_count']}[/bold]\n"
        f"  [white]Denied events (excluded):[/white]   [dim]{result['denied_count']}[/dim]\n"
        f"  [white]Unique actions observed:[/white]    [bold cyan]{result['unique_actions']}[/bold cyan]\n"
        f"  [white]Distinct services used:[/white]     [bold]{len(result['service_breakdown'])}[/bold]",
        title=f"[bold cyan]Analysis — {args.entity}[/bold cyan]",
        border_style="cyan",
        expand=False,
    ))

    # ── Per-service breakdown table ────────────────────────────────────────
    if result["service_breakdown"]:
        console.print()
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold dim",
            expand=False,
        )
        table.add_column("Service",      style="bold cyan", min_width=24)
        table.add_column("Actions used", min_width=56)
        table.add_column("#", justify="right", min_width=4)

        for svc, actions in result["service_breakdown"].items():
            preview = ", ".join(actions[:5])
            if len(actions) > 5:
                preview += f" [dim]+{len(actions) - 5} more[/dim]"
            table.add_row(svc, preview, str(len(actions)))

        console.print(table)

    # ── Generated policy ───────────────────────────────────────────────────
    policy_json = json.dumps(result["suggested_policy"], indent=2)
    console.print()
    console.print("[bold]Generated least-privilege policy:[/bold]")
    console.print(Syntax(policy_json, "json", theme="monokai", line_numbers=True))

    # ── Write output file ──────────────────────────────────────────────────
    if args.output:
        out = {
            "meta": {
                "entity":        result["username"],
                "account_id":    account_id,
                "days_analyzed": result["days_analyzed"],
                "start_time":    result["start_time"],
                "end_time":      result["end_time"],
                "event_count":   result["event_count"],
                "denied_count":  result["denied_count"],
                "unique_actions": result["unique_actions"],
            },
            "service_breakdown": result["service_breakdown"],
            "all_actions":       result["actual_actions"],
            "suggested_policy":  result["suggested_policy"],
        }
        Path(args.output).write_text(json.dumps(out, indent=2))
        console.print(f"\n[green]✓[/green] Full output written to [bold]{args.output}[/bold]")

    # ── Footer note ────────────────────────────────────────────────────────
    console.print()
    console.print(
        "[dim]This policy reflects observed API usage in the past "
        f"{args.days} days only. Review before applying:\n"
        "  • Infrequent but legitimate actions may be missing\n"
        "  • All resources are set to '*' — narrow for production use\n"
        "  • Denied events were excluded — fix those separately[/dim]"
    )
    console.print()


if __name__ == "__main__":
    main()
