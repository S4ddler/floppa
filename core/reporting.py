import csv
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


def save_reports(meta: dict, result: dict, out_dir: str, formats: list[str]):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    base = Path(out_dir) / f"{meta['module']}_{meta['target']}"
    payload = {"meta": meta, "result": result}

    if "json" in formats:
        with open(str(base) + ".json", "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    if "csv" in formats:
        csv_path = str(base) + ".csv"
        _save_csv(result, csv_path)
    if "md" in formats:
        md_path = str(base) + ".md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(render_markdown(meta, result))


def _save_csv(result: dict, path: str):
    # Flatten common shapes; best-effort
    rows = []
    if result.get("accounts"):
        for r in result["accounts"]:
            rows.append({"site": r.get("site"), "url": r.get("url"), "status": r.get("status")})
    if result.get("dns", {}).get("records"):
        for rtype, values in result["dns"]["records"].items():
            for v in values:
                rows.append({"rtype": rtype, "value": v})
    with open(path, "w", newline="", encoding="utf-8") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=sorted({k for row in rows for k in row.keys()}))
            writer.writeheader()
            for row in rows:
                writer.writerow(row)


def render_markdown(meta: dict, result: dict) -> str:
    md = [f"# OSINT Report — {meta['module']} :: {meta['target']}", ""]
    if meta:
        md.append("## Metadata")
        for k, v in meta.items():
            md.append(f"- **{k}**: {v}")
        md.append("")
    if result.get("summary"):
        md.append("## Summary")
        for k, v in result["summary"].items():
            md.append(f"- **{k}**: {v}")
        md.append("")
    if result.get("accounts"):
        md.append("## Accounts Found")
        for a in result["accounts"]:
            md.append(f"- {a['site']}: {a['url']}")
        md.append("")
    if result.get("dns"):
        md.append("## DNS Records")
        for rtype, vals in result["dns"].get("records", {}).items():
            md.append(f"### {rtype}")
            for v in vals:
                md.append(f"- {v}")
        md.append("")
    if result.get("whois"):
        md.append("## WHOIS")
        for k, v in result["whois"].items():
            md.append(f"- **{k}**: {v}")
        md.append("")
    if result.get("subdomains"):
        md.append("## Subdomains")
        for s in result["subdomains"]:
            md.append(f"- {s}")
        md.append("")
    return "\n".join(md)


def print_table_summary(meta: dict, result: dict):
    if meta["module"] == "username":
        tbl = Table(
            title=f"[bold yellow]Username Results for [cyan]{meta['target']}[/cyan][/bold yellow]",
            show_header=True,
            header_style="bold green",
            border_style="blue",
            expand=True
        )
        tbl.add_column("🌐 Site", style="cyan")
        tbl.add_column("🔗 URL", style="magenta")
        found = result.get("accounts", [])
        for r in found:
            tbl.add_row(
                f"[bold]{r.get('site', '')}[/bold]",
                f"[link]{r.get('url', '')}[/link]"
            )
        if not found:
            console.print(Panel(
                "[bold red]No accounts found for this username![/bold red]",
                border_style="red",
                title="❌ Results"
            ))
            return
        console.print(Panel(tbl, border_style="green", title="✅ Found Accounts"))
    elif meta["module"] == "domain":
        tbl = Table(
            title=f"[bold yellow]Domain Analysis for [cyan]{meta['target']}[/cyan][/bold yellow]",
            show_header=True,
            header_style="bold green",
            border_style="blue",
            expand=True
        )
        tbl.add_column("📊 Metric", style="cyan")
        tbl.add_column("📈 Value", style="magenta")
        summary = result.get("summary") or {}
        
        # Enhanced display for domain results
        if summary.get("a_records"):
            tbl.add_row("DNS Records", f"[green]✓[/green] {summary['a_records']} A records found")
        if summary.get("subdomains"):
            tbl.add_row("Subdomains", f"[green]✓[/green] {summary['subdomains']} subdomains discovered")
        if summary.get("dnssec"):
            tbl.add_row("DNSSEC", "[green]✓[/green] Enabled" if summary['dnssec'] else "[red]✗[/red] Disabled")
        if summary.get("open_services"):
            tbl.add_row("Open Services", f"[yellow]⚠[/yellow] {summary['open_services']} services detected")
        if summary.get("whois_registrar"):
            tbl.add_row("Registrar", f"[blue]ℹ[/blue] {summary['whois_registrar']}")
            
        console.print(Panel(tbl, border_style="green", title="🎯 Domain Analysis Results"))
