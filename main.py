import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from modules.username_osint import UsernameScanner
from modules.domain_osint import DomainScanner
from core.reporting import save_reports, print_table_summary
from core.utils import ensure_dir

console = Console()

BANNER = """
    ███████╗██╗      ██████╗ ██████╗ ██████╗  █████╗ 
    ██╔════╝██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
    █████╗  ██║     ██║   ██║██████╔╝██████╔╝███████║
    ██╔══╝  ██║     ██║   ██║██╔═══╝ ██╔═══╝ ██╔══██║
    ██║     ███████╗╚██████╔╝██║     ██║     ██║  ██║
    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝
           OSINT Framework - By Ahmad Bilaidi (S4ddler)
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="OSINT Mega Tool — username & domain reconnaissance",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--type", required=True, choices=["username", "domain"], help="OSINT module to run")
    p.add_argument("--target", required=True, help="Target value (username or domain)")
    p.add_argument("--output", default="out", help="Output directory for reports")
    p.add_argument("--format", default="table,json", help="Comma-separated output formats: table,json,csv,md")
    p.add_argument("--proxy", default=None, help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--timeout", type=int, default=15, help="Per-request timeout seconds")
    p.add_argument("--concurrency", type=int, default=50, help="Concurrent tasks (username scans)")
    p.add_argument("--retries", type=int, default=2, help="Retries for transient errors")
    p.add_argument("--wordlist", default="sub.txt", help="(Domain) Subdomain wordlist path for brute add-on")
    p.add_argument("--top-ports", default="80,443,22,25,53,110,143,587,993,995,2083,2087,3306,3389,444,465,8080,8443",
                   help="(Domain) Comma-separated TCP ports to test")
    p.add_argument("--no-scan-ports", action="store_true", help="(Domain) Disable TCP port scan phase")
    p.add_argument("--no-axfr", action="store_true", help="(Domain) Skip AXFR zone-transfer attempts")
    p.add_argument("--dns-server", default=None, help="(Domain) Specific DNS server for dig/dns queries")
    return p.parse_args()


def main():
    # Show fancy banner
    banner_text = Text(BANNER)
    banner_text.stylize("bold magenta")
    console.print(Panel(
        banner_text,
        border_style="cyan",
        padding=(1, 2),
        title="[bold yellow]Welcome to FLOPPA[/bold yellow]"
    ))
    
    args = parse_args()
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    ensure_dir(args.output)
    
    # Show target info
    console.print(f"\n[bold green]Target Type:[/bold green] {args.type}")
    console.print(f"[bold green]Target Value:[/bold green] {args.target}")
    console.print(f"[bold green]Output Directory:[/bold green] {args.output}\n")

    result = None
    meta = {
        "module": args.type,
        "target": args.target,
        "timestamp_utc": ts,
        "tool": "osint-mega-tool",
        "version": "0.1.0",
    }

    if args.type == "username":
        scanner = UsernameScanner(timeout=args.timeout,
                                  concurrency=args.concurrency,
                                  retries=args.retries,
                                  proxy=args.proxy)
        result = scanner.scan(args.target)
    elif args.type == "domain":
        scanner = DomainScanner(timeout=args.timeout,
                                proxy=args.proxy,
                                no_axfr=args.no_axfr,
                                no_scan_ports=args.no_scan_ports,
                                top_ports=args.top_ports,
                                wordlist=args.wordlist,
                                dns_server=args.dns_server)
        result = scanner.scan(args.target)

    # Reporting
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    print_table_summary(meta, result)
    save_reports(meta, result, out_dir=args.output, formats=formats)


if __name__ == "__main__":
    sys.exit(main())
