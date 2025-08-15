# FLOPPA OSINT Tool

A powerful and beautiful OSINT command line tool for reconnaissance.

```
    ███████╗██╗      ██████╗ ██████╗ ██████╗  █████╗ 
    ██╔════╝██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
    █████╗  ██║     ██║   ██║██████╔╝██████╔╝███████║
    ██╔══╝  ██║     ██║   ██║██╔═══╝ ██╔═══╝ ██╔══██║
    ██║     ███████╗╚██████╔╝██║     ██║     ██║  ██║
    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝
           OSINT Framework - By Ahmad Bilaidi (S4ddler)
```

## Features
- **Username OSINT (Sherlock-level and beyond):**
  - Massive sites catalog (JSON), async scans, adaptive detection rules, retries, proxy & user-agent rotation,
    rate-limit handling, colored TUI, JSON/CSV/Markdown reports.
- **Domain OSINT (Professional):**
  - WHOIS (registrar, dates, contacts),
  - DNS with `dig` (A/AAAA/MX/NS/TXT/SOA/CNAME/CAA/DS/DNSKEY) + fallback to `dnspython`,
  - Reverse DNS for A/AAAA targets,
  - DNSSEC presence & validation hints,
  - Zone transfer checks (AXFR) against NS, safely and read-only,
  - Subdomain enumeration from crt.sh + wordlist brute (optional),
  - GeoIP and ASN lookup,
  - Port scan (top/common ports + banner grabs),
  - TLS certificate fetch & parse (issuer/SAN/expiry),
  - HTTP fingerprint (Server header, redirects),
  - Consolidated summary report.

## Quickstart
```bash
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Username scan
python main.py --type username --target "ahmad" --output out --format table,json,md

# Domain scan
python main.py --type domain --target "example.com" --output out --format table,json,md
```

## System Requirements
- Python 3.9+
- `dig` (bind9-dnsutils). Fallback to dnspython is included when `dig` missing.

## Notes
- Only passive techniques are implemented by default except optional lightweight
  port scanning (TCP connect) and AXFR **read-only attempt**. Use responsibly.
