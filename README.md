<div align="center">
  <img src=".github/assets/banner.png" alt="FLOPPA Tool Banner" width="800"/>
  
  # FLOPPA OSINT Tool

  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python Version">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20macOS-brightgreen" alt="OS Support">
    <a href="https://twitter.com/7_8_z"><img src="https://img.shields.io/twitter/follow/S4ddler?style=social" alt="Twitter Follow"></a>
  </p>

  <p align="center">🔍 A powerful and beautiful OSINT command line tool for reconnaissance.</p>
</div>

```
    ███████╗██╗      ██████╗ ██████╗ ██████╗  █████╗ 
    ██╔════╝██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
    █████╗  ██║     ██║   ██║██████╔╝██████╔╝███████║
    ██╔══╝  ██║     ██║   ██║██╔═══╝ ██╔═══╝ ██╔══██║
    ██║     ███████╗╚██████╔╝██║     ██║     ██║  ██║
    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝
           OSINT Framework - By Ahmad Bilaidi (S4ddler)
```

## ✨ Features
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

## 🚀 Quickstart
```bash
# Create and activate virtual environment
python -m venv venv && source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Username OSINT scan
python main.py --type username --target "ahmad" --output out --format table,json,md

# Domain reconnaissance
python main.py --type domain --target "example.com" --output out --format table,json,md
```

## 📋 Example Output

<details>
<summary>Click to see example username scan output</summary>

![Username Scan](.github/assets/username-scan)
</details>

<details>
<summary>Click to see example domain scan output</summary>

![Domain Scan](.github/assets/domain-scan)
</details>

## 🛠️ System Requirements
- Python 3.9+
- `dig` (bind9-dnsutils) - Will fallback to dnspython if not available

## 🔒 Security Notes
- Only passive techniques are implemented by default except optional lightweight
  port scanning (TCP connect) and AXFR **read-only attempt**. Use responsibly.

