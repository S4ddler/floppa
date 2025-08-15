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
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn

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
    top_ports: str = "21,22,23,25,26,53,80,81,110,111,135,139,143,443,445,465,587,995,1723,3306,3389,5900,8080,8443,995,993,5432,3306,2222,2087,2086,2083,2082,2095,2096,8443,8880,8081,8888,9090,1025,1433,1434,1521,3128,3306,4242,4243,4567,5222,5223,5432,6379,7000,7001,8000,8008,8080,8443,8888,9092,9200,9300,10000,11211,27017,28017,49152,49153,49154,49155,49156,49157,50000,6379,2375,2376,6000,13306,3000,4444,5000,5555,5672,5984,6082,8009,8010,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8443,9000,9001,9042,9160,9042,9200,9300,11211,11214,11215,27017,27018,27019,28017,50000,50030,50070"
    wordlist: Optional[str] = None
    dns_server: Optional[str] = None

    def scan(self, domain: str) -> dict:
        result: Dict = {"dns": {"records": {}}, "whois": {}, "subdomains": []}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
        ) as progress:
            scan_task = progress.add_task("🔍 Starting domain reconnaissance...", total=8)
            
            try:
                progress.update(scan_task, description="📑 Fetching WHOIS information...")
                w = whois.whois(domain)
                whois_info = {
                    "domain_name": self._safe(w.domain_name),
                    "registrar": self._safe(w.registrar),
                    "creation_date": self._safe(w.creation_date),
                    "expiration_date": self._safe(w.expiration_date),
                    "updated_date": self._safe(w.updated_date),
                    "name_servers": list(sorted(set([str(x) for x in (w.name_servers or [])]))),
                    "status": self._safe(w.status),
                }
                result["whois"] = whois_info
                
                # Display immediate results
                console.print("\n[bold green]WHOIS Information:[/bold green]")
                whois_table = Table(show_header=True, header_style="bold blue")
                whois_table.add_column("Field", style="bold cyan")
                whois_table.add_column("Value")
                for key, value in whois_info.items():
                    if value:
                        if isinstance(value, list):
                            whois_table.add_row(key.replace('_', ' ').title(), "\n".join(value))
                        else:
                            whois_table.add_row(key.replace('_', ' ').title(), str(value))
                console.print(whois_table)
                
            except Exception as e:
                result["whois_error"] = str(e)
                console.print("\n[bold red]❌ Error fetching WHOIS information[/bold red]")
            progress.update(scan_task, advance=1)

            progress.update(scan_task, description="🌐 Gathering DNS records...")
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            
            console.print("\n[bold green]DNS Records:[/bold green]")
            dns_table = Table(show_header=True, header_style="bold blue")
            dns_table.add_column("Record Type", style="bold cyan")
            dns_table.add_column("Values")
            
            for rr in SUPPORTED_RRTYPES:
                recs = self._dig(domain, rr)
                if not recs:
                    recs = self._dns_query(resolver, domain, rr)
                if recs:
                    result["dns"]["records"][rr] = recs
                    dns_table.add_row(rr, "\n".join(recs))
            
            console.print(dns_table)
            progress.update(scan_task, advance=1)

            progress.update(scan_task, description="🔄 Performing reverse DNS lookups...")
            ips = set(result["dns"]["records"].get("A", []) + result["dns"]["records"].get("AAAA", []))
            rev = {}
            for ip in ips:
                try:
                    rev[ip] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    rev[ip] = None
            result["dns"]["reverse"] = rev
            progress.update(scan_task, advance=1)

            dnssec_present = bool(result["dns"]["records"].get("DS") or result["dns"]["records"].get("DNSKEY"))
            result["dns"]["dnssec_present"] = dnssec_present

            if not self.no_axfr:
                progress.update(scan_task, description="🔍 Checking zone transfer...")
                axfr_findings = []
                for ns in result["dns"]["records"].get("NS", []) or []:
                    host = ns.split()[0].strip(".") if " " in ns else ns.strip(".")
                    ok, out = self._try_axfr(host, domain)
                    if ok:
                        axfr_findings.append({"ns": host, "lines": out.splitlines()[:200]})
                result["dns"]["axfr"] = axfr_findings
            progress.update(scan_task, advance=1)

            progress.update(scan_task, description="🌍 Enumerating subdomains...")
            subdomains = self._enum_crtsh(domain)
            result["subdomains"] = sorted(set(subdomains))

            if self.wordlist:
                progress.update(scan_task, description="🔍 Bruteforcing subdomains...")
                subs = self._brute_subdomains(domain, self.wordlist, resolver)
                result["subdomains"] = sorted(set(result["subdomains"] + subs))
            progress.update(scan_task, advance=1)

            progress.update(scan_task, description="📍 Looking up GeoIP information...")
            geo = {}
            for ip in ips:
                g = self._geoip(ip)
                if g:
                    geo[ip] = g
            result["geoip"] = geo
            progress.update(scan_task, advance=1)

            if not self.no_scan_ports and ips:
                progress.update(scan_task, description="🔌 Scanning ports...")
                service_map = {}
                ports = [int(p) for p in self.top_ports.split(",") if p.strip().isdigit()]
                
                for ip in ips:
                    console.print(f"\n[bold green]Scanning ports for IP: [cyan]{ip}[/cyan][/bold green]")
                    port_table = Table(show_header=True, header_style="bold blue")
                    port_table.add_column("Port", style="bold cyan")
                    port_table.add_column("Service")
                    port_table.add_column("Version")
                    port_table.add_column("Banner")
                    
                    services = self._scan_ports(ip, ports)
                    service_map[ip] = services
                    
                    for port, info in services.items():
                        version = info.get('version', '')
                        banner = info.get('banner', '')
                        if banner and len(banner) > 50:
                            banner = banner[:50] + '...'
                        port_table.add_row(
                            str(port),
                            info.get('service', 'unknown'),
                            version or '',
                            banner or ''
                        )
                    
                    console.print(port_table)
                result["services"] = service_map
            progress.update(scan_task, advance=1)

            progress.update(scan_task, description="🔒 Checking TLS and HTTP...")
            try:
                cert = fetch_tls_cert(domain, 443, timeout=8)
                result["tls"] = extract_cert_summary(cert)
            except Exception:
                result["tls"] = {}

            http_fp = self._http_fingerprint(domain)
            result["http"] = http_fp
            progress.update(scan_task, advance=1)

            result["summary"] = {
                "a_records": len(result["dns"]["records"].get("A", []) or []),
                "subdomains": len(result["subdomains"]),
                "dnssec": dnssec_present,
                "open_services": sum(len(v) for v in result.get("services", {}).values()),
                "whois_registrar": (result.get("whois", {}) or {}).get("registrar"),
            }
            
            progress.update(scan_task, description="✅ Scan completed!")

        return result

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
        
        # Common service signatures
        SERVICE_PROBES = {
            21: b"220",  # FTP
            22: b"SSH",  # SSH
            25: b"SMTP",  # SMTP
            80: b"GET / HTTP/1.0\r\n\r\n",  # HTTP
            443: b"GET / HTTP/1.0\r\n\r\n",  # HTTPS
            3306: b"\x0a",  # MySQL
            5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL
            6379: b"INFO\r\n",  # Redis
            27017: b"\x41\x00\x00\x00",  # MongoDB
        }
        
        # Common service names
        SERVICE_NAMES = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            3389: "RDP",
            5900: "VNC",
        }

        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                
                if s.connect_ex((ip, p)) == 0:
                    service_info = {
                        "status": "open",
                        "service": SERVICE_NAMES.get(p, "unknown"),
                        "banner": None,
                        "version": None
                    }
                    
                    # Try to get service banner
                    try:
                        if p in SERVICE_PROBES:
                            s.send(SERVICE_PROBES[p])
                        else:
                            s.send(b"\\r\\n")
                        
                        banner = s.recv(1024)
                        decoded_banner = banner.decode(errors='ignore').strip()
                        
                        service_info["banner"] = decoded_banner
                        
                        # Try to extract version information
                        version_info = self._extract_version_info(p, decoded_banner)
                        if version_info:
                            service_info["version"] = version_info
                            
                        # Enhanced HTTP detection
                        if p in [80, 443, 8080, 8443]:
                            try:
                                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s2.settimeout(3)
                                s2.connect((ip, p))
                                s2.send(b"HEAD / HTTP/1.1\\r\\nHost: " + ip.encode() + b"\\r\\n\\r\\n")
                                http_resp = s2.recv(1024).decode(errors='ignore')
                                server = self._extract_http_server(http_resp)
                                if server:
                                    service_info["server"] = server
                                s2.close()
                            except:
                                pass
                            
                    except socket.timeout:
                        pass
                    except Exception as e:
                        service_info["error"] = str(e)
                    
                    findings[p] = service_info
                s.close()
            except:
                continue
                
        return findings
        
    def _extract_version_info(self, port: int, banner: str) -> Optional[str]:
        # SSH Version
        if port == 22 and "SSH" in banner:
            ssh_version = banner.split("\\n")[0].strip()
            return ssh_version
            
        # FTP Version
        if port == 21 and "220" in banner:
            ftp_version = banner.split("\\n")[0].strip()
            return ftp_version
            
        # SMTP Version
        if port == 25 and ("SMTP" in banner or "220" in banner):
            smtp_version = banner.split("\\n")[0].strip()
            return smtp_version
            
        # HTTP Server
        if port in [80, 443, 8080, 8443]:
            if "Server:" in banner:
                return banner.split("Server:")[1].split("\\n")[0].strip()
                
        # MySQL Version
        if port == 3306 and banner:
            try:
                return f"MySQL {banner.split('\\x00')[1].split('-')[1].split('\\n')[0]}"
            except:
                pass
                
        # PostgreSQL Version
        if port == 5432 and banner:
            try:
                return f"PostgreSQL {banner.split('\\x00')[1]}"
            except:
                pass
                
        return None
        
    def _extract_http_server(self, response: str) -> Optional[str]:
        if "Server:" in response:
            server_line = [line for line in response.split("\\n") if "Server:" in line][0]
            return server_line.split("Server:")[1].strip()
        return None

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
