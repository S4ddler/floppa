import concurrent.futures
import ipaddress
import json
import socket
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

import dns.resolver
import requests
import whois
from rich.console import Console
from rich.table import Table

from core.utils import which, run_cmd, grab_banner, fetch_tls_cert, extract_cert_summary

console = Console()

SUPPORTED_RRTYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DS", "DNSKEY",
]


@dataclass
class DomainScanner:
    timeout: int = 15
    proxy: Optional[str] = None
    no_axfr: bool = False
    no_scan_ports: bool = False
    top_ports: str = "80,443,22,25,53,110,143,587,993,995,2083,2087,3306,3389,444,465,8080,8443"
    wordlist: Optional[str] = None
    dns_server: Optional[str] = None

    def scan(self, domain: str) -> dict:
        result: Dict = {"dns": {"records": {}}, "whois": {}, "subdomains": []}

        try:
            w = whois.whois(domain)
            result["whois"] = {
                "domain_name": self._safe(w.domain_name),
                "registrar": self._safe(w.registrar),
                "creation_date": self._safe(w.creation_date),
                "expiration_date": self._safe(w.expiration_date),
                "updated_date": self._safe(w.updated_date),
                "name_servers": list(sorted(set([str(x) for x in (w.name_servers or [])]))),
                "status": self._safe(w.status),
            }
        except Exception as e:
            result["whois_error"] = str(e)
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            resolver.nameservers = [self.dns_server]
        for rr in SUPPORTED_RRTYPES:
            recs = self._dig(domain, rr)
            if not recs:
                recs = self._dns_query(resolver, domain, rr)
            result["dns"]["records"][rr] = recs

        # Reverse DNS for A/AAAA
        ips = set(result["dns"]["records"].get("A", []) + result["dns"]["records"].get("AAAA", []))
        rev = {}
        for ip in ips:
            try:
                rev[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                rev[ip] = None
        result["dns"]["reverse"] = rev

        # DNSSEC presence (DS/DNSKEY as hint)
        dnssec_present = bool(result["dns"]["records"].get("DS") or result["dns"]["records"].get("DNSKEY"))
        result["dns"]["dnssec_present"] = dnssec_present

        # AXFR attempts against NS
        axfr_findings = []
        if not self.no_axfr:
            for ns in result["dns"]["records"].get("NS", []) or []:
                host = ns.split()[0].strip(".") if " " in ns else ns.strip(".")
                ok, out = self._try_axfr(host, domain)
                if ok:
                    axfr_findings.append({"ns": host, "lines": out.splitlines()[:200]})  # cap
        result["dns"]["axfr"] = axfr_findings

        # Subdomains via crt.sh
        subdomains = self._enum_crtsh(domain)
        result["subdomains"] = sorted(set(subdomains))

        # Optional: brute force with wordlist
        if self.wordlist:
            subs = self._brute_subdomains(domain, self.wordlist, resolver)
            result["subdomains"] = sorted(set(result["subdomains"] + subs))

        # GeoIP & ASN via ipapi.co for each A/AAAA
        geo = {}
        for ip in ips:
            g = self._geoip(ip)
            if g:
                geo[ip] = g
        result["geoip"] = geo

        # Port scan & banners & TLS certs
        service_map = {}
        if not self.no_scan_ports and ips:
            ports = [int(p) for p in self.top_ports.split(",") if p.strip().isdigit()]
            for ip in ips:
                service_map[ip] = self._scan_ports(ip, ports)
        result["services"] = service_map

        # TLS cert on domain:443 if applicable
        try:
            cert = fetch_tls_cert(domain, 443, timeout=8)
            result["tls"] = extract_cert_summary(cert)
        except Exception:
            result["tls"] = {}

        # HTTP fingerprint for domain
        http_fp = self._http_fingerprint(domain)
        result["http"] = http_fp

        # Summary
        result["summary"] = {
            "a_records": len(result["dns"]["records"].get("A", []) or []),
            "subdomains": len(result["subdomains"]),
            "dnssec": dnssec_present,
            "open_services": sum(len(v) for v in result.get("services", {}).values()),
            "whois_registrar": (result.get("whois", {}) or {}).get("registrar"),
        }
        return result

    # Helpers
    def _safe(self, v):
        if isinstance(v, (list, tuple, set)):
            return [self._safe(x) for x in v]
        return str(v) if v is not None else None

    def _dig(self, domain: str, rr: str) -> List[str]:
        if not which("dig"):
            return []
        cmd = ["dig", "+short", rr, domain]
        if self.dns_server:
            cmd = ["dig", f"@{self.dns_server}", rr, domain, "+short"]
        code, out, _ = run_cmd(cmd)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        return lines

    def _dns_query(self, resolver: dns.resolver.Resolver, domain: str, rr: str) -> List[str]:
        try:
            answers = resolver.resolve(domain, rr, lifetime=self.timeout)
            vals = []
            for r in answers:
                vals.append(r.to_text())
            return vals
        except Exception:
            return []

    def _try_axfr(self, ns_host: str, domain: str):
        if not which("dig"):
            return False, ""
        cmd = ["dig", f"@{ns_host}", domain, "AXFR", "+time=5", "+tries=1"]
        code, out, err = run_cmd(cmd)
        if code == 0 and out and "XFR size" in out:
            return True, out
        return False, out or err

    def _enum_crtsh(self, domain: str) -> List[str]:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return []
            data = r.json()
            subs = []
            for e in data:
                name = e.get("name_value", "")
                for part in name.split("\n"):
                    part = part.strip().lstrip("*.")
                    if part.endswith(domain):
                        subs.append(part)
            return subs
        except Exception:
            return []

    def _brute_subdomains(self, domain: str, wordlist_path: str, resolver: dns.resolver.Resolver) -> List[str]:
        subs = []
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip()]
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                futures = {ex.submit(self._resolve_sub, resolver, f"{w}.{domain}"): w for w in words}
                for fut in concurrent.futures.as_completed(futures):
                    val = fut.result()
                    if val:
                        subs.append(val)
        except Exception:
            pass
        return subs

    def _resolve_sub(self, resolver: dns.resolver.Resolver, fqdn: str) -> Optional[str]:
        try:
            resolver.resolve(fqdn, "A", lifetime=min(self.timeout, 5))
            return fqdn
        except Exception:
            return None

    def _geoip(self, ip: str) -> Optional[dict]:
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
            if r.status_code == 200:
                data = r.json()
                return {
                    "ip": ip,
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "asn": data.get("asn"),
                    "org": data.get("org"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                }
        except Exception:
            return None
        return None

    def _scan_ports(self, ip: str, ports: List[int]) -> Dict[int, dict]:
        findings = {}
        for p in ports:
            try:
                banner = None
                import socket as _s
                s = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((ip, p)) == 0:
                    # Try small banner
                    try:
                        s.sendall(b"\r\n")
                        data = s.recv(256)
                        banner = data.decode(errors="ignore") if data else None
                    except Exception:
                        pass
                    findings[p] = {"status": "open", "banner": banner}
                s.close()
            except Exception:
                continue
        return findings

    def _http_fingerprint(self, domain: str) -> dict:
        out = {"http": {}, "https": {}}
        try:
            r = requests.get(f"http://{domain}", timeout=6, allow_redirects=True)
            out["http"] = {
                "status": r.status_code,
                "final_url": r.url,
                "server": r.headers.get("Server"),
                "powered_by": r.headers.get("X-Powered-By"),
            }
        except Exception:
            pass
        try:
            r = requests.get(f"https://{domain}", timeout=8, allow_redirects=True)
            out["https"] = {
                "status": r.status_code,
                "final_url": r.url,
                "server": r.headers.get("Server"),
                "powered_by": r.headers.get("X-Powered-By"),
            }
        except Exception:
            pass
        return out
