"""CLI interface for chaos-qa built with Typer and Rich."""

import anyio
import json
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import typer

from src.core.runner import ChaosRunner

app = typer.Typer(
    name="chaos-qa",
    help="Local chaos monkey and stress-testing tool for AI-generated HTTP endpoints.",
    no_args_is_help=True,
)
console = Console()


def _parse_json_payload(json_str: Optional[str]) -> dict | list | None:
    """Safely parses JSON string from CLI flag."""
    if not json_str:
        return None
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        console.print(f"[bold yellow]Warning:[/bold yellow] Invalid JSON string provided: {e}. Using raw payload.")
        return {"raw": json_str}


def _render_score_panel(score: int, grade: str) -> None:
    """Renders the resilience score panel."""
    color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
    bar_len = 30
    filled = int((score / 100) * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)

    content = Text()
    content.append(f"\n  Resilience Score: ", style="bold")
    content.append(f"{score}/100\n", style=f"bold {color}")
    content.append(f"  Rating Grade:     ", style="bold")
    content.append(f"{grade}\n", style=f"bold {color}")
    content.append(f"  Health Gauge:     [{bar}]\n", style=f"{color}")

    panel = Panel(
        content,
        title="[bold cyan]🛡️ Resilience Evaluation[/bold cyan]",
        border_style=color,
        expand=False,
    )
    console.print(panel)


def _render_recommendations(recommendations: list[str]) -> None:
    """Renders actionable remediation steps."""
    if not recommendations:
        return

    text = Text()
    for idx, rec in enumerate(recommendations, 1):
        text.append(f"\n{idx}. ", style="bold yellow")
        text.append(f"{rec}\n", style="white")

    console.print(
        Panel(
            text,
            title="[bold yellow]💡 Concrete Remediation Steps for AI Code[/bold yellow]",
            border_style="yellow",
        )
    )


@app.command("attack")
def attack(
    url: str = typer.Argument(..., help="Target HTTP URL to attack"),
    method: str = typer.Option("POST", "--method", "-m", help="HTTP method (POST, GET, PUT)"),
    concurrency: int = typer.Option(20, "--concurrency", "-c", help="Number of concurrent requests for race hammer"),
    json_payload: Optional[str] = typer.Option(
        None, "--json", "-j", help="JSON payload template (e.g. '{\"amount\": 100}')"
    ),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Timeout per request in seconds"),
) -> None:
    """Runs the complete chaos test suite: race conditions, payload fuzzing, and TCP socket disruption."""
    console.print(
        Panel(
            f"[bold red]💥 Launching Full Chaos Attack Suite[/bold red]\n"
            f"[dim]Target:[/dim] {url} | [dim]Method:[/dim] {method} | [dim]Concurrency:[/dim] {concurrency}",
            border_style="red",
        )
    )

    parsed_json = _parse_json_payload(json_payload)
    runner = ChaosRunner(
        url=url,
        method=method,
        concurrency=concurrency,
        json_payload=parsed_json,
        timeout=timeout,
    )

    report = anyio.run(runner.run_full_suite)

    # 1. Race Hammer Table
    if report.race_result:
        r_table = Table(title="🏎️ Race Condition Hammer Results", border_style="cyan")
        r_table.add_column("Metric", style="bold cyan")
        r_table.add_column("Value", style="white")

        r_table.add_row("Concurrency Burst", str(report.race_result.concurrency))
        r_table.add_row("Status Codes Distribution", str(report.race_result.status_distribution))
        r_table.add_row(
            "Latency (Min / Avg / Max)",
            f"{report.race_result.min_latency_ms}ms / {report.race_result.avg_latency_ms}ms / {report.race_result.max_latency_ms}ms",
        )
        r_table.add_row("Latency Spike Ratio", f"{report.race_result.latency_spike_ratio}x")
        r_table.add_row(
            "Collisions / Lost Updates",
            "[red]DETECTED[/red]" if report.race_result.collision_detected else "[green]CLEAN[/green]",
        )
        r_table.add_row(
            "Status Inconsistency (2xx vs 5xx)",
            "[red]DETECTED[/red]" if report.race_result.inconsistent_status_codes else "[green]CLEAN[/green]",
        )
        console.print(r_table)

    # 2. Payload Fuzzer Table
    if report.fuzz_result:
        f_table = Table(title="🧪 Payload Fuzzer Results", border_style="magenta")
        f_table.add_column("Category", style="bold magenta")
        f_table.add_column("Count", style="white")
        f_table.add_column("Status Assessment", style="white")

        f_table.add_row("Total Mutations Tested", str(report.fuzz_result.total_mutations), "Complete")
        f_table.add_row(
            "HANDLED_4XX (Expected)",
            str(report.fuzz_result.handled_4xx_count),
            "[green]Properly rejected malformed payload[/green]",
        )
        f_table.add_row(
            "CRASH_500 (Unhandled)",
            str(report.fuzz_result.crash_500_count),
            f"[red]FAIL: Unhandled exception in server code[/red]"
            if report.fuzz_result.crash_500_count > 0
            else "[green]None[/green]",
        )
        f_table.add_row(
            "SILENT_SWALLOW_200",
            str(report.fuzz_result.silent_swallow_200_count),
            f"[yellow]WARN: Accepted broken data without validation[/yellow]"
            if report.fuzz_result.silent_swallow_200_count > 0
            else "[green]None[/green]",
        )
        console.print(f_table)

    # 3. Socket Chaos Table
    if report.socket_result:
        s_table = Table(title="🔌 Socket Chaos Results", border_style="blue")
        s_table.add_column("Check", style="bold blue")
        s_table.add_column("Value", style="white")

        s_table.add_row("Abrupt TCP Disconnects", str(report.socket_result.abrupt_disconnects_sent))
        s_table.add_row(
            "Server Survived Disruptions",
            "[green]YES[/green]" if report.socket_result.server_survived else "[bold red]SERVER CRASHED / HUNG[/bold red]",
        )
        s_table.add_row("Baseline Latency", f"{report.socket_result.baseline_latency_ms:.2f} ms")
        s_table.add_row("Post-Attack Latency", f"{report.socket_result.post_attack_latency_ms:.2f} ms")
        s_table.add_row("Latency Degradation", f"+{report.socket_result.latency_degradation_pct:.1f}%")
        console.print(s_table)

    # 4. Resilience Score and Recommendations
    _render_score_panel(report.resilience_score, report.grade)
    _render_recommendations(report.recommendations)

    if not report.passed:
        raise typer.Exit(code=1)


@app.command("race")
def race(
    url: str = typer.Argument(..., help="Target HTTP URL to attack"),
    method: str = typer.Option("POST", "--method", "-m", help="HTTP method (POST, GET, PUT)"),
    concurrency: int = typer.Option(30, "--concurrency", "-c", help="Number of concurrent requests"),
    json_payload: Optional[str] = typer.Option(
        None, "--json", "-j", help="JSON payload template (e.g. '{\"amount\": 100}')"
    ),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Timeout per request in seconds"),
) -> None:
    """Targeted strike against race conditions using simultaneous requests via asyncio.Barrier."""
    console.print(
        Panel(
            f"[bold cyan]🏎️ Running Race Condition Hammer[/bold cyan]\n"
            f"[dim]Target:[/dim] {url} | [dim]Method:[/dim] {method} | [dim]Concurrency:[/dim] {concurrency}",
            border_style="cyan",
        )
    )

    parsed_json = _parse_json_payload(json_payload)
    runner = ChaosRunner(
        url=url,
        method=method,
        concurrency=concurrency,
        json_payload=parsed_json,
        timeout=timeout,
    )

    result = anyio.run(runner.run_race)

    table = Table(title="Race Condition Attack Analysis", border_style="cyan")
    table.add_column("Property", style="bold cyan")
    table.add_column("Result", style="white")

    table.add_row("Concurrency Burst", str(result.concurrency))
    table.add_row("Status Codes Distribution", str(result.status_distribution))
    table.add_row("Successful Requests (2xx)", f"[green]{result.successful_requests}[/green]")
    table.add_row("Failed Requests", f"[red]{result.failed_requests}[/red]" if result.failed_requests else "0")
    table.add_row(
        "Latencies (Min / Avg / Max)",
        f"{result.min_latency_ms}ms / {result.avg_latency_ms}ms / {result.max_latency_ms}ms",
    )
    table.add_row(
        "Collisions / Inconsistencies",
        "[red]DETECTED[/red]" if result.collision_detected else "[green]NONE[/green]",
    )
    table.add_row(
        "Inconsistent Status Codes",
        "[red]DETECTED[/red]" if result.inconsistent_status_codes else "[green]CLEAN[/green]",
    )
    console.print(table)

    if result.vulnerabilities:
        text = Text()
        for v in result.vulnerabilities:
            text.append(f"• {v}\n", style="red")
        console.print(Panel(text, title="[bold red]Vulnerabilities Found[/bold red]", border_style="red"))
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]✅ No race condition collisions detected![/bold green]")


@app.command("fuzz")
def fuzz(
    url: str = typer.Argument(..., help="Target HTTP URL to attack"),
    method: str = typer.Option("POST", "--method", "-m", help="HTTP method (POST, GET, PUT)"),
    json_payload: Optional[str] = typer.Option(
        None, "--json", "-j", help="JSON payload template (e.g. '{\"amount\": 100}')"
    ),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Timeout per request in seconds"),
) -> None:
    """Fuzzes target endpoint with mutated JSON payloads to verify input validation."""
    console.print(
        Panel(
            f"[bold magenta]🧪 Running Payload Fuzzer[/bold magenta]\n"
            f"[dim]Target:[/dim] {url} | [dim]Method:[/dim] {method}",
            border_style="magenta",
        )
    )

    parsed_json = _parse_json_payload(json_payload)
    runner = ChaosRunner(
        url=url,
        method=method,
        json_payload=parsed_json,
        timeout=timeout,
    )

    result = anyio.run(runner.run_fuzz)

    table = Table(title="Payload Fuzzing Classification", border_style="magenta")
    table.add_column("Category", style="bold magenta")
    table.add_column("Count", style="white")
    table.add_column("Verdict", style="white")

    table.add_row("Total Mutations", str(result.total_mutations), "Done")
    table.add_row(
        "HANDLED_4XX",
        str(result.handled_4xx_count),
        "[green]Valid 4xx rejection (safe)[/green]",
    )
    table.add_row(
        "CRASH_500",
        str(result.crash_500_count),
        "[red]Crashed with 5xx (unsafe)[/red]" if result.crash_500_count > 0 else "[green]0[/green]",
    )
    table.add_row(
        "SILENT_SWALLOW_200",
        str(result.silent_swallow_200_count),
        "[yellow]Missing validation (unsafe)[/yellow]" if result.silent_swallow_200_count > 0 else "[green]0[/green]",
    )
    console.print(table)

    if result.crash_items:
        crash_table = Table(title="CRASH_500 Mutation Details", border_style="red")
        crash_table.add_column("Mutation", style="bold red")
        crash_table.add_column("Description", style="white")
        crash_table.add_column("Status", style="red")
        for item in result.crash_items[:8]:
            crash_table.add_row(item.mutation.name, item.mutation.description, str(item.status_code))
        console.print(crash_table)

    if result.swallowed_items:
        swallow_table = Table(title="SILENT_SWALLOW_200 Mutation Details", border_style="yellow")
        swallow_table.add_column("Mutation", style="bold yellow")
        swallow_table.add_column("Description", style="white")
        swallow_table.add_column("Status", style="green")
        for item in result.swallowed_items[:8]:
            swallow_table.add_row(item.mutation.name, item.mutation.description, str(item.status_code))
        console.print(swallow_table)

    if not result.passed:
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]✅ All mutated payloads handled cleanly![/bold green]")


if __name__ == "__main__":
    app()
