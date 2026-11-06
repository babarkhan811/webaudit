"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from webaudit import __version__
from webaudit.checks import REGISTRY, select_checks
from webaudit.config import AuditConfig
from webaudit.engine import Engine
from webaudit.models import SEVERITY_ORDER, Severity, SiteReport
from webaudit.reporting import (
    build_summary,
    create_run_dir,
    write_site_report,
    write_summary,
)
from webaudit.targets import InvalidTarget, Target, load_targets, parse_lines

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130

GRADE_STYLES = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def _non_negative_float(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return number


def _names(value: str) -> list[str]:
    return [name.strip() for name in value.split(",") if name.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webaudit",
        description="Audit website health and security configuration.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list-checks", help="show the available checks")

    gui = commands.add_parser("gui", help="launch the web dashboard in your browser")
    gui.add_argument("-o", "--output", type=Path, default=Path("reports"), help="report folder (default: reports)")
    gui.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, local only)")
    gui.add_argument("--port", type=int, default=8765, help="port (default: 8765)")
    gui.add_argument("--no-browser", action="store_true", help="don't open a browser window")

    scan = commands.add_parser("scan", help="audit a list of websites")
    scan.add_argument("targets_file", nargs="?", type=Path, help="text file, one site per line")
    scan.add_argument("-u", "--url", action="append", default=[], help="add one site (repeatable)")
    scan.add_argument("-c", "--concurrency", type=_positive_int, default=3, help="sites at a time (default: 3)")
    scan.add_argument("-o", "--output", type=Path, default=Path("reports"), help="report folder (default: reports)")
    scan.add_argument("--timeout", type=_positive_float, default=10.0, help="seconds per network operation (default: 10)")
    scan.add_argument("--check-timeout", type=_positive_float, default=90.0, help="seconds per check (default: 90)")
    scan.add_argument("--site-timeout", type=_positive_float, default=180.0, help="seconds per site (default: 180)")
    scan.add_argument("--retries", type=_non_negative_int, default=1, help="extra homepage attempts (default: 1)")
    scan.add_argument("--per-site-requests", type=_positive_int, default=5, help="simultaneous requests per site (default: 5)")
    scan.add_argument("--delay", type=_non_negative_float, default=0.0, help="seconds to wait before each request (default: 0)")
    scan.add_argument("--max-pages", type=_positive_int, default=5, help="pages crawled per site (default: 5)")
    scan.add_argument("--max-links", type=_positive_int, default=100, help="links verified per site (default: 100)")
    scan.add_argument("--only", type=_names, default=[], help="comma-separated checks to run")
    scan.add_argument("--skip", type=_names, default=[], help="comma-separated checks to leave out")
    scan.add_argument("--traceroute", action="store_true", help="also run the slow traceroute check")
    scan.add_argument("--ca-bundle", type=Path, help="extra CA file for private certificates")
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in SEVERITY_ORDER],
        help="exit with code 1 if any finding is at this severity or worse",
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="hide the progress display")
    return parser


def _collect_targets(args: argparse.Namespace, console: Console) -> tuple[list[Target], list[str]] | None:
    lines = list(args.url)
    if args.targets_file:
        try:
            targets, rejected = load_targets(args.targets_file)
        except (OSError, UnicodeError) as exc:
            console.print(f"[red]Can't read {escape(str(args.targets_file))}: {escape(str(exc))}[/red]")
            return None
    else:
        targets, rejected = [], []
    extra, extra_rejected = parse_lines(lines)
    seen = {t.url for t in targets}
    targets += [t for t in extra if t.url not in seen]
    return targets, rejected + extra_rejected


def _print_results(console: Console, reports: list[SiteReport]) -> None:
    table = Table(title="Audit results")
    table.add_column("Grade")
    table.add_column("Score", justify="right")
    table.add_column("Site", overflow="fold")
    table.add_column("Status")
    for name in ("Crit", "High", "Med", "Low"):
        table.add_column(name, justify="right")
    for report in sorted(reports, key=lambda r: (r.score is None, r.score or 0)):
        counts = report.severity_counts
        table.add_row(
            f"[{GRADE_STYLES.get(report.grade, 'white')}]{report.grade}[/]",
            "-" if report.score is None else str(report.score),
            escape(report.url),
            report.status,
            *(str(counts.get(s, 0)) for s in ("critical", "high", "medium", "low")),
        )
    console.print(table)


def _meets_threshold(reports: list[SiteReport], fail_on: str) -> bool:
    limit = SEVERITY_ORDER.index(Severity(fail_on))
    return any(
        SEVERITY_ORDER.index(finding.severity) <= limit
        for report in reports
        for finding in report.findings
    )


async def _scan(
    args: argparse.Namespace,
    console: Console,
    config: AuditConfig,
    checks: list,
    targets: list[Target],
    rejected: list[str],
    run_dir: Path,
) -> tuple[list[SiteReport], bool]:
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    progress = Progress(
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=args.quiet,
    )
    bar = progress.add_task("Auditing", total=len(targets))

    def on_finish(target: Target, report: SiteReport) -> None:
        write_site_report(report, run_dir)  # saved now, so Ctrl-C keeps finished sites
        progress.advance(bar)
        if not args.quiet:
            style = GRADE_STYLES.get(report.grade, "white")
            progress.console.print(
                f"[{style}]{report.grade}[/] {escape(target.url)} "
                f"[dim]{report.status}, {report.duration_s:.1f}s[/dim]"
            )

    engine = Engine(config, checks, on_finish=on_finish)
    with progress:
        reports = await engine.run(targets)

    finished = {report.url for report in reports}
    summary = build_summary(
        reports,
        started_at=started_at,
        finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
        rejected=rejected,
        interrupted=engine.interrupted,
        not_run=[t.url for t in targets if t.url not in finished],
    )
    write_summary(summary, run_dir)
    return reports, engine.interrupted


def _run_scan(args: argparse.Namespace, console: Console) -> int:
    try:
        checks = select_checks(args.only, args.skip, args.traceroute)
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        return EXIT_USAGE
    if not checks:
        console.print("[red]No checks selected.[/red]")
        return EXIT_USAGE
    if args.ca_bundle and not args.ca_bundle.is_file():
        console.print(f"[red]CA file not found: {escape(str(args.ca_bundle))}[/red]")
        return EXIT_USAGE

    collected = _collect_targets(args, console)
    if collected is None:
        return EXIT_USAGE
    targets, rejected = collected
    for message in rejected:
        console.print(f"[yellow]Skipped target: {escape(message)}[/yellow]")
    if not targets:
        console.print("[red]No valid targets. Give a targets file or use --url.[/red]")
        return EXIT_USAGE

    config = AuditConfig(
        concurrency=args.concurrency,
        request_timeout=args.timeout,
        check_timeout=args.check_timeout,
        site_timeout=args.site_timeout,
        retries=args.retries,
        per_site_requests=args.per_site_requests,
        delay=args.delay,
        max_pages=args.max_pages,
        max_links=args.max_links,
        ca_bundle=args.ca_bundle,
    )
    run_dir = create_run_dir(args.output)

    if not args.quiet:
        console.print(
            f"Auditing {len(targets)} site(s), {config.concurrency} at a time. "
            f"Checks: {', '.join(c.name for c in checks)}"
        )
        if any(c.name == "exposure" for c in checks):
            console.print(
                "[dim]The exposure check requests sensitive paths and will show up in "
                "server logs. Only scan sites you own or are authorized to test.[/dim]"
            )

    reports, interrupted = asyncio.run(
        _scan(args, console, config, checks, targets, rejected, run_dir)
    )

    if reports:
        _print_results(console, reports)
    console.print(f"Summary: {escape(str(run_dir / 'summary.html'))}")
    if interrupted:
        console.print(f"[yellow]Interrupted after {len(reports)} of {len(targets)} sites.[/yellow]")
        return EXIT_INTERRUPTED
    if args.fail_on and _meets_threshold(reports, args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def _list_checks(console: Console) -> int:
    table = Table(title="Available checks")
    table.add_column("Name")
    table.add_column("Default")
    table.add_column("Description")
    for spec in REGISTRY.values():
        table.add_row(spec.name, "yes" if spec.default else "no", spec.description)
    console.print(table)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    # Never crash on a console that can't encode a character from a scanned site.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    args = build_parser().parse_args(argv)
    console = Console()
    if args.command == "list-checks":
        return _list_checks(console)
    if args.command == "gui":
        from webaudit.web.server import run_gui

        try:
            run_gui(
                reports_root=args.output,
                host=args.host,
                port=args.port,
                open_browser=not args.no_browser,
            )
        except KeyboardInterrupt:
            console.print("\nDashboard stopped.")
        return EXIT_OK
    return _run_scan(args, console)
