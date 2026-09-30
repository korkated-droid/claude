#!/usr/bin/env python3
"""
infra.py — Real Infrastructure Enumeration Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Discovers the REAL attack surface behind the target:
  • Port scanning (common + full range) via nmap/masscan or raw async sockets
  • ASN / CIDR range enumeration (bgp.he.net, ipinfo, whois)
  • Cloud provider detection (AWS, GCP, Azure, Cloudflare, Fastly, Akamai)
  • IP range cross-scanning to find unlisted subdomains/services
  • Certificate transparency mining (crt.sh, certspotter, Facebook CT)
  • DNS zone walking + NSEC enumeration
  • Reverse DNS mass lookup across CIDR
  • Shodan InternetDB (free API — no key needed)
  • FOFA / Censys / BinaryEdge (with API keys from env)
  • GitHub org secret scanning (public repos)
  • S3 / GCS / Azure Blob permutation brute
  • Favicon hash → Shodan/FOFA pivot
  • HTTP/HTTPS service detection across found IPs
  • Tech stack fingerprinting on every live host
  • Security headers audit on every live host

For AUTHORIZED bug bounty programs and owned targets ONLY.
"""

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    import aiohttp
except ImportError:
    print("[!] pip install aiohttp"); sys.exit(1)

R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


# ──────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    ip: str
    port: int
    protocol: str        # tcp / udp
    state: str           # open / filtered / closed
    service: str = ""    # http, https, ssh, ftp, …
    version: str = ""
    banner: str = ""

@dataclass
class HostInfo:
    ip: str
    hostnames: List[str] = field(default_factory=list)
    asn: str = ""
    org: str = ""
    country: str = ""
    cloud_provider: str = ""   # aws, gcp, azure, cloudflare, fastly, akamai, …
    cloud_region: str = ""
    open_ports: List[PortResult] = field(default_factory=list)
    http_services: List[Dict] = field(default_factory=list)  # {url, title, server, tech, headers}
    certs: List[Dict] = field(default_factory=list)
    shodan_data: Dict = field(default_factory=dict)

@dataclass
class InfraResult:
    target: str
    primary_ips: List[str] = field(default_factory=list)
    asn_cidrs: List[str] = field(default_factory=list)
    cloud_provider: str = ""
    hosts: List[HostInfo] = field(default_factory=list)
    ct_domains: List[str] = field(default_factory=list)
    storage_buckets: List[Dict] = field(default_factory=list)
    github_secrets: List[Dict] = field(default_factory=list)
    interesting_ports: List[PortResult] = field(default_factory=list)
    security_issues: List[Dict] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# CLOUD IP RANGES  (kept in-process, no API key needed)
# ──────────────────────────────────────────────────────────────────────────────

CLOUD_RANGES_URLS = {
    "aws":         "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp":         "https://www.gstatic.com/ipranges/cloud.json",
    "azure":       "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public.json",
    "cloudflare":  "https://www.cloudflare.com/ips-v4",
    "fastly":      "https://api.fastly.com/public-ip-list",
}

# Hard-coded known ranges as fallback (updated 2026)
CLOUD_HARDCODED = {
    "cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
        "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
    ],
    "fastly": [
        "23.235.32.0/20",  "43.249.72.0/22",  "103.244.50.0/24",
        "103.245.222.0/23","103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
        "151.101.0.0/16",  "157.52.64.0/18",  "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22",  "199.27.72.0/21",
        "199.232.0.0/16",  "202.21.128.0/24", "203.57.145.0/24",
    ],
}

async def detect_cloud_provider(ip: str, session: aiohttp.ClientSession) -> Tuple[str, str]:
    """Returns (provider_name, region) for an IP, or ('unknown', '')."""
    # Check Cloudflare hardcoded
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in CLOUD_HARDCODED.get("cloudflare", []):
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return "cloudflare", ""
        for cidr in CLOUD_HARDCODED.get("fastly", []):
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return "fastly", ""
    except Exception:
        pass

    # ipinfo.io (no key for basic lookups)
    try:
        async with session.get(f"https://ipinfo.io/{ip}/json", timeout=aiohttp.ClientTimeout(total=5)) as r:
            if r.status == 200:
                d = await r.json()
                org = d.get("org", "")
                region = d.get("region", "")
                if "amazon" in org.lower() or "aws" in org.lower():
                    return "aws", region
                if "google" in org.lower():
                    return "gcp", region
                if "microsoft" in org.lower() or "azure" in org.lower():
                    return "azure", region
                if "cloudflare" in org.lower():
                    return "cloudflare", region
                if "fastly" in org.lower():
                    return "fastly", region
                if "akamai" in org.lower():
                    return "akamai", region
                return org, region
    except Exception:
        pass
    return "unknown", ""


# ──────────────────────────────────────────────────────────────────────────────
# DNS RESOLUTION + REVERSE DNS
# ──────────────────────────────────────────────────────────────────────────────

async def resolve_all(domain: str) -> List[str]:
    """Resolve domain to all IPs (A + AAAA)."""
    ips = []
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(
            domain, None, proto=socket.IPPROTO_TCP
        )
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


async def reverse_dns(ip: str) -> List[str]:
    """PTR lookup for an IP."""
    try:
        result = await asyncio.get_event_loop().getnameinfo((ip, 0), socket.NI_NAMEREQD)
        return [result[0]] if result else []
    except Exception:
        return []


async def resolve_cidr_reverse(cidr: str, session: aiohttp.ClientSession,
                                concurrency: int = 50) -> List[Tuple[str, List[str]]]:
    """Bulk reverse DNS for all IPs in a CIDR — returns [(ip, [hostnames])]."""
    results = []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 65536:
            print(f"  {Y}[warn]{RST} CIDR {cidr} has {len(hosts)} hosts — limiting to /24 blocks")
            hosts = hosts[:256]
        sem = asyncio.Semaphore(concurrency)

        async def rdns(ip):
            async with sem:
                names = await reverse_dns(str(ip))
                if names:
                    return (str(ip), names)
                return None

        tasks = [rdns(h) for h in hosts]
        results_raw = await asyncio.gather(*tasks)
        results = [r for r in results_raw if r]
    except Exception as e:
        pass
    return results


# ──────────────────────────────────────────────────────────────────────────────
# ASN / CIDR ENUMERATION
# ──────────────────────────────────────────────────────────────────────────────

async def get_asn_info(ip: str, session: aiohttp.ClientSession) -> Dict:
    """Get ASN, org, and all CIDRs belonging to that ASN."""
    info = {"ip": ip, "asn": "", "org": "", "cidrs": [], "country": ""}

    # ipinfo.io
    try:
        async with session.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            if r.status == 200:
                d = await r.json(content_type=None)
                info["asn"] = d.get("org", "").split(" ")[0]  # "AS12345"
                info["org"] = " ".join(d.get("org", "").split(" ")[1:])
                info["country"] = d.get("country", "")
                if "bogon" not in d and info["asn"].startswith("AS"):
                    # fetch all prefixes for this ASN from bgp.he.net
                    asn_num = info["asn"][2:]
                    info["cidrs"] = await get_asn_cidrs(asn_num, session)
    except Exception:
        pass

    return info


async def get_asn_cidrs(asn_num: str, session: aiohttp.ClientSession) -> List[str]:
    """Fetch all IPv4 CIDRs announced by an ASN via bgp.he.net."""
    cidrs = []
    try:
        url = f"https://bgp.he.net/AS{asn_num}#_prefixes"
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                body = await r.text()
                # Extract prefixes from table: /td class="text"/
                cidrs = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', body)
                cidrs = list(set(cidrs))
    except Exception:
        pass

    # Fallback: ipinfo.io/AS<num>
    if not cidrs:
        try:
            async with session.get(
                f"https://ipinfo.io/AS{asn_num}",
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=8),
            ) as r:
                if r.status == 200:
                    d = await r.json(content_type=None)
                    cidrs = d.get("prefixes", [])
        except Exception:
            pass

    return cidrs[:200]  # cap at 200 CIDR blocks


# ──────────────────────────────────────────────────────────────────────────────
# PORT SCANNING
# ──────────────────────────────────────────────────────────────────────────────

# Ports most likely to have web services or be interesting for bug bounty
INTERESTING_PORTS_WEB = [
    80, 81, 443, 591, 593, 832, 981, 1010, 1311, 1433, 2082, 2083, 2086, 2087,
    2095, 2096, 2222, 2480, 3000, 3001, 3306, 3333, 3389, 4243, 4567, 4711,
    4712, 4993, 5000, 5001, 5104, 5108, 5800, 6543, 7000, 7001, 7002, 7396,
    7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8083, 8088, 8090,
    8091, 8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500,
    8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200,
    9294, 9295, 9443, 9800, 9981, 10000, 10443, 11371, 12043, 12443, 15672,
    16080, 18091, 18092, 20720, 28017, 43110, 55440, 55672,
]

ALL_SERVICE_PORTS = [
    21, 22, 23, 25, 53, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 194, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995,
    1080, 1194, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376, 3000, 3306,
    3389, 3690, 4369, 5000, 5432, 5601, 5672, 5900, 6379, 6443, 7001, 7474,
    8080, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 15672, 27017, 27018,
    27019, 28017, 50000, 50070,
]


async def tcp_probe(ip: str, port: int, timeout: float = 2.0) -> Optional[PortResult]:
    """Raw async TCP connect probe — no nmap needed."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        # Try to grab a banner
        banner = ""
        try:
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            banner = data.decode(errors="replace").strip()[:200]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        service = guess_service(port, banner)
        return PortResult(ip=ip, port=port, protocol="tcp", state="open",
                         service=service, banner=banner[:100])
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


def guess_service(port: int, banner: str = "") -> str:
    b = banner.lower()
    if "http" in b or "html" in b:
        return "https" if port in (443, 8443, 4443) else "http"
    port_map = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
        445: "smb", 465: "smtps", 587: "smtp-submission", 636: "ldaps",
        993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        2375: "docker", 2376: "docker-tls", 2181: "zookeeper",
        3000: "http-alt", 3306: "mysql", 3389: "rdp", 3690: "svn",
        4369: "epmd", 5000: "http-alt", 5432: "postgresql", 5601: "kibana",
        5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kubernetes-api",
        7001: "weblogic", 7474: "neo4j", 8080: "http-alt", 8443: "https-alt",
        8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
        9200: "elasticsearch", 9300: "elasticsearch-transport",
        11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
        27018: "mongodb", 27019: "mongodb", 28017: "mongodb-http",
        50000: "db2", 50070: "hdfs-namenode",
    }
    return port_map.get(port, "unknown")


async def scan_ports(ip: str, ports: List[int], concurrency: int = 100,
                     verbose: bool = False) -> List[PortResult]:
    """Async TCP port scan against a single IP."""
    sem = asyncio.Semaphore(concurrency)
    open_ports = []

    async def probe(p):
        async with sem:
            result = await tcp_probe(ip, p)
            if result:
                if verbose:
                    print(f"  {G}[open]{RST} {ip}:{p} ({result.service})")
                open_ports.append(result)

    await asyncio.gather(*[probe(p) for p in ports])
    return sorted(open_ports, key=lambda x: x.port)


async def nmap_scan(target: str, ports: str = None, aggressive: bool = False,
                    outdir: str = ".") -> List[PortResult]:
    """Run nmap if available, parse XML output."""
    results = []
    if not shutil_which("nmap"):
        return results

    port_arg = ports or ("1-65535" if aggressive else "21-23,25,53,80,110,143,443,445,587,993,995,1080,1433,1521,2375,3000,3306,3389,5000,5432,5601,5900,6379,6443,7001,7474,8080,8443,8888,9000,9090,9200,11211,15672,27017")
    out_xml = os.path.join(outdir, f"nmap_{target.replace('/','_')}.xml")

    cmd = ["nmap", "-sV", "--open", "-T4" if aggressive else "-T3",
           "-p", port_arg, "--script", "banner,http-title,ssl-cert",
           "-oX", out_xml, target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    except Exception:
        pass

    if os.path.exists(out_xml):
        results = _parse_nmap_xml(out_xml)
    return results


def _parse_nmap_xml(xml_path: str) -> List[PortResult]:
    """Parse nmap XML output."""
    results = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portnum = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                svc = svc_el.get("name", "") if svc_el is not None else ""
                ver = f"{svc_el.get('product','')} {svc_el.get('version','')}".strip() if svc_el is not None else ""
                banner = ""
                for script in port_el.findall("script"):
                    if script.get("id") in ("banner", "http-title"):
                        banner += script.get("output", "")[:100]
                results.append(PortResult(ip=ip, port=portnum, protocol=proto,
                                          state="open", service=svc, version=ver,
                                          banner=banner[:100]))
    except Exception:
        pass
    return results


def shutil_which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)


# ──────────────────────────────────────────────────────────────────────────────
# HTTP SERVICE DETECTION ON OPEN PORTS
# ──────────────────────────────────────────────────────────────────────────────

TECH_FINGERPRINTS = {
    "nginx":        r"nginx",
    "apache":       r"Apache",
    "iis":          r"IIS|Microsoft-IIS",
    "tomcat":       r"Apache-Coyote|Tomcat",
    "spring":       r"Whitelabel Error|Spring Boot|spring",
    "django":       r"Django|djdt|__debug__",
    "laravel":      r"laravel_session|XSRF-TOKEN|Illuminate\\",
    "rails":        r"_rails_session|Ruby on Rails|rack",
    "express":      r"Express|node\.js|connect\.sid",
    "next.js":      r"__NEXT_DATA__|next-head-count|_next/",
    "react":        r"__REACT_ERROR|react-root|_react",
    "angular":      r"ng-version|angular\.js|NgZone",
    "vue":          r"__vue_app__|Vue\.js",
    "wordpress":    r"wp-content|wp-admin|WordPress",
    "grafana":      r"Grafana|grafana\.boot",
    "jenkins":      r"X-Jenkins|jenkins",
    "kibana":       r"kbn-name|kibana",
    "elasticsearch":r'"cluster_name"',
    "redis":        r"\+PONG|redis_version",
    "mongodb":      r'"ismaster"|"ok"',
    "jira":         r"com\.atlassian\.jira|Jira",
    "confluence":   r"Atlassian Confluence|confluence",
    "gitlab":       r"GitLab|gl-",
    "kubernetes":   r'"apiVersion"|"kind":"',
    "phpmyadmin":   r"phpMyAdmin",
    "adminer":      r"adminer",
    "graphql":      r'"__schema"',
    "swagger":      r"swagger-ui|Swagger UI",
    "strapi":       r"strapi",
    "ghost":        r"Ghost Admin|ghost-sdk",
}


async def fingerprint_http(ip: str, port: int, session: aiohttp.ClientSession,
                            hostname: str = "") -> Optional[Dict]:
    """Probe an IP:port over HTTP and HTTPS, return service info."""
    schemes = ["https"] if port in (443, 8443, 4443) else (["https", "http"] if port == 443 else ["http", "https"])
    if port in (80, 8080, 8000, 8008, 8001, 8081, 8888, 3000):
        schemes = ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}"
        host_header = hostname or ip
        try:
            async with session.get(
                url + "/",
                headers={
                    "Host": host_header,
                    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
                    "Accept": "text/html,*/*",
                },
                timeout=aiohttp.ClientTimeout(total=6),
                allow_redirects=True,
                ssl=False,
            ) as r:
                body = await r.text(errors="replace")
                headers = dict(r.headers)
                title_match = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
                title = title_match.group(1).strip() if title_match else ""

                # Tech detection
                tech_found = []
                combined = body[:4000] + " " + " ".join(f"{k}: {v}" for k,v in headers.items())
                for tech, pattern in TECH_FINGERPRINTS.items():
                    if re.search(pattern, combined, re.I):
                        tech_found.append(tech)

                # Security headers audit
                sec_issues = []
                sh = {k.lower(): v for k, v in headers.items()}
                if "strict-transport-security" not in sh:
                    sec_issues.append("Missing HSTS")
                if "x-frame-options" not in sh and "frame-ancestors" not in sh.get("content-security-policy","").lower():
                    sec_issues.append("Missing X-Frame-Options")
                if "x-content-type-options" not in sh:
                    sec_issues.append("Missing X-Content-Type-Options")
                if "content-security-policy" not in sh:
                    sec_issues.append("Missing CSP")
                if "x-powered-by" in sh:
                    sec_issues.append(f"X-Powered-By: {sh['x-powered-by']}")
                if "server" in sh:
                    sec_issues.append(f"Server: {sh['server']}")

                # CORS check
                cors_h = sh.get("access-control-allow-origin", "")
                if cors_h == "*" or cors_h == "null":
                    sec_issues.append(f"Open CORS: {cors_h}")

                # Interesting content
                interesting = []
                if re.search(r"(api[_-]?key|secret|password|token)\s*[=:]\s*[\"\']?[A-Za-z0-9+/]{20,}", body, re.I):
                    interesting.append("credentials-in-page")
                if re.search(r"stack trace|traceback|exception|error at line", body, re.I):
                    interesting.append("error-disclosure")
                if re.search(r"(<!DOCTYPE|<html)", body[:200], re.I):
                    pass
                if re.search(r"phpinfo\(\)|PHP Version \d", body, re.I):
                    interesting.append("phpinfo")
                if re.search(r'"ismaster"\s*:\s*true|"you are connected"', body, re.I):
                    interesting.append("mongodb-noauth")
                if re.search(r'"cluster_name"\s*:', body, re.I):
                    interesting.append("elasticsearch-noauth")

                return {
                    "url": url,
                    "host": host_header,
                    "status": r.status,
                    "title": title,
                    "server": headers.get("Server", headers.get("server", "")),
                    "tech": tech_found,
                    "security_issues": sec_issues,
                    "interesting": interesting,
                    "content_length": len(body),
                    "redirect": str(r.url) if str(r.url) != url + "/" else "",
                }
        except Exception:
            continue
    return None


# ──────────────────────────────────────────────────────────────────────────────
# CERTIFICATE TRANSPARENCY
# ──────────────────────────────────────────────────────────────────────────────

async def ct_enumerate(domain: str, session: aiohttp.ClientSession) -> List[str]:
    """Query multiple CT sources for all domains/subdomains in certificates."""
    found: Set[str] = set()
    base = domain.lstrip("*.")

    sources = [
        f"https://crt.sh/?q=%.{base}&output=json",
        f"https://api.certspotter.com/v1/issuances?domain={base}&include_subdomains=true&expand=dns_names",
        f"https://api.facebook.com/certificates?query={base}&fields=domains&limit=1000",
    ]

    for url in sources:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    continue
                data = await r.json(content_type=None)
                # crt.sh
                if "crt.sh" in url:
                    for entry in data:
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if base in name:
                                found.add(name)
                # certspotter
                elif "certspotter" in url:
                    for entry in data:
                        for name in entry.get("dns_names", []):
                            name = name.strip().lstrip("*.")
                            if base in name:
                                found.add(name)
                # facebook
                elif "facebook" in url:
                    for entry in data.get("data", []):
                        for name in entry.get("domains", []):
                            name = name.strip().lstrip("*.")
                            if base in name:
                                found.add(name)
        except Exception:
            continue

    return sorted(found)


# ──────────────────────────────────────────────────────────────────────────────
# SHODAN INTERNETDB (free, no API key)
# ──────────────────────────────────────────────────────────────────────────────

async def shodan_internetdb(ip: str, session: aiohttp.ClientSession) -> Dict:
    """Query Shodan InternetDB for known open ports, vulns, CPEs for an IP."""
    try:
        async with session.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            if r.status == 200:
                return await r.json(content_type=None)
    except Exception:
        pass
    return {}


async def shodan_api(ip: str, api_key: str, session: aiohttp.ClientSession) -> Dict:
    """Full Shodan API host info (requires API key from SHODAN_API_KEY env var)."""
    if not api_key:
        return {}
    try:
        async with session.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            if r.status == 200:
                return await r.json(content_type=None)
    except Exception:
        pass
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# CLOUD STORAGE BRUTE (S3 / GCS / Azure Blob)
# ──────────────────────────────────────────────────────────────────────────────

BUCKET_PERMUTATIONS = [
    "{name}", "{name}-backup", "{name}-dev", "{name}-staging", "{name}-prod",
    "{name}-static", "{name}-assets", "{name}-media", "{name}-uploads",
    "{name}-data", "{name}-logs", "{name}-internal", "{name}-private",
    "{name}-public", "{name}-cdn", "{name}-files", "{name}-images",
    "{name}-docs", "{name}-api", "{name}-archive", "{name}-export",
    "{name}-import", "{name}-tmp", "{name}-temp", "{name}-admin",
    "{name}-web", "{name}-app", "{name}-store", "{name}-dump",
    "backup-{name}", "dev-{name}", "staging-{name}", "prod-{name}",
]


async def check_s3_bucket(name: str, session: aiohttp.ClientSession) -> Optional[Dict]:
    urls = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]
    for url in urls:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                body = await r.text()
                if r.status == 200:
                    listing = re.findall(r"<Key>([^<]+)</Key>", body)
                    return {"service": "s3", "url": url, "status": "open",
                            "keys_preview": listing[:10]}
                elif r.status == 403:
                    return {"service": "s3", "url": url, "status": "exists-403",
                            "keys_preview": []}
        except Exception:
            continue
    return None


async def check_gcs_bucket(name: str, session: aiohttp.ClientSession) -> Optional[Dict]:
    url = f"https://storage.googleapis.com/{name}/"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
            body = await r.text()
            if r.status == 200:
                listing = re.findall(r"<Key>([^<]+)</Key>", body)
                return {"service": "gcs", "url": url, "status": "open",
                        "keys_preview": listing[:10]}
            elif r.status == 403:
                return {"service": "gcs", "url": url, "status": "exists-403",
                        "keys_preview": []}
    except Exception:
        pass
    return None


async def check_azure_blob(name: str, session: aiohttp.ClientSession) -> Optional[Dict]:
    url = f"https://{name}.blob.core.windows.net/"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
            body = await r.text()
            if r.status == 200 or (r.status == 400 and "container" in body.lower()):
                return {"service": "azure-blob", "url": url, "status": "exists",
                        "keys_preview": []}
    except Exception:
        pass
    return None


async def brute_buckets(company_name: str, session: aiohttp.ClientSession,
                        verbose: bool = False) -> List[Dict]:
    """Try all cloud storage permutations for a company name."""
    found = []
    names = [
        p.format(name=company_name) for p in BUCKET_PERMUTATIONS
    ] + [
        p.format(name=company_name.replace(".", "-")) for p in BUCKET_PERMUTATIONS
    ]
    names = list(set(names))

    sem = asyncio.Semaphore(30)

    async def check(name):
        async with sem:
            for checker in [check_s3_bucket, check_gcs_bucket, check_azure_blob]:
                result = await checker(name, session)
                if result:
                    if verbose:
                        print(f"  {G}[bucket]{RST} {result['service']} {result['url']} [{result['status']}]")
                    found.append(result)

    await asyncio.gather(*[check(n) for n in names])
    return found


# ──────────────────────────────────────────────────────────────────────────────
# FAVICON HASH → SHODAN PIVOT
# ──────────────────────────────────────────────────────────────────────────────

async def get_favicon_hash(base_url: str, session: aiohttp.ClientSession) -> Optional[str]:
    """Compute Shodan/FOFA mmh3 favicon hash for CDN bypass pivot."""
    for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
        try:
            url = base_url.rstrip("/") + path
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                if r.status == 200 and r.content_type and "text" not in r.content_type:
                    data = await r.read()
                    # Shodan mmh3 hash
                    encoded = base64.encodebytes(data).decode()
                    import ctypes
                    h = _mmh3_32(encoded)
                    return str(h)
        except Exception:
            continue
    return None


def _mmh3_32(data: str) -> int:
    """MurmurHash3 32-bit (Shodan's favicon hash method) — pure Python."""
    b = data.encode() if isinstance(data, str) else data
    length = len(b)
    seed = 0
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h1 = seed
    roundedEnd = (length & 0xfffffffc)
    for i in range(0, roundedEnd, 4):
        k1 = (b[i] & 0xff) | ((b[i+1] & 0xff) << 8) | ((b[i+2] & 0xff) << 16) | ((b[i+3] & 0xff) << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = (k1 << 15 | k1 >> 17) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = (h1 << 13 | h1 >> 19) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 ^= (b[roundedEnd+2] & 0xff) << 16
    if val >= 2:
        k1 ^= (b[roundedEnd+1] & 0xff) << 8
    if val >= 1:
        k1 ^= b[roundedEnd] & 0xff
        k1 = (k1 * c1) & 0xffffffff
        k1 = (k1 << 15 | k1 >> 17) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return ctypes.c_int32(h1).value


# ──────────────────────────────────────────────────────────────────────────────
# GITHUB ORG SECRET SCANNING
# ──────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS = {
    "aws_key":          r"AKIA[0-9A-Z]{16}",
    "aws_secret":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "github_token":     r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
    "stripe_key":       r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_pk":        r"pk_live_[0-9a-zA-Z]{24,}",
    "twilio_sid":       r"AC[0-9a-fA-F]{32}",
    "sendgrid":         r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}",
    "google_api":       r"AIza[0-9A-Za-z\-_]{35}",
    "firebase":         r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "slack_token":      r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "slack_webhook":    r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+",
    "jwt":              r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "private_key_pem":  r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    "postgres_url":     r"postgres(ql)?://[^:]+:[^@]+@",
    "mongodb_url":      r"mongodb(\+srv)?://[^:]+:[^@]+@",
    "heroku_api":       r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "mailgun_api":      r"key-[0-9a-zA-Z]{32}",
    "braintree_key":    r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "paypal_id":        r"A[0-9A-Z]{12}",
    "square_token":     r"sq0atp-[0-9A-Za-z\-_]{22}",
    "plaid_secret":     r"[0-9a-f]{32}",
    "intercom_key":     r"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}",
    "generic_api_key":  r"(?i)(api_key|apikey|api-key|secret_key|access_token|auth_token)['\"\s]*[:=]['\"\s]*[A-Za-z0-9+/]{20,}",
}


async def scan_github_org(org: str, session: aiohttp.ClientSession,
                          verbose: bool = False) -> List[Dict]:
    """Scan public GitHub repos of an org for secrets in code."""
    secrets_found = []
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # List repos
    repos = []
    page = 1
    while len(repos) < 50:
        try:
            async with session.get(
                f"https://api.github.com/orgs/{org}/repos?per_page=50&page={page}&sort=updated",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status != 200:
                    break
                data = await r.json()
                if not data:
                    break
                repos.extend(data)
                page += 1
        except Exception:
            break

    if verbose:
        print(f"  {DIM}GitHub: {len(repos)} public repos for {org}{RST}")

    # Search each repo via GitHub code search
    for repo in repos[:20]:  # cap to avoid rate limit
        repo_name = repo.get("full_name", "")
        for secret_type, pattern in list(SECRET_PATTERNS.items())[:8]:
            try:
                async with session.get(
                    f"https://api.github.com/search/code?q={urllib.parse.quote(pattern[:30])}+repo:{repo_name}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as r:
                    await asyncio.sleep(0.5)  # respect rate limit
                    if r.status == 200:
                        data = await r.json()
                        for item in data.get("items", [])[:3]:
                            secrets_found.append({
                                "repo": repo_name,
                                "file": item.get("path"),
                                "url": item.get("html_url"),
                                "secret_type": secret_type,
                                "pattern": pattern[:50],
                            })
            except Exception:
                continue

    return secrets_found


# ──────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────

async def enumerate_infrastructure(
    target: str,
    outdir: str = ".",
    full_port_scan: bool = False,
    scan_asn_range: bool = False,
    buckets: bool = True,
    github_org: str = "",
    verbose: bool = False,
    concurrency: int = 100,
) -> InfraResult:

    result = InfraResult(target=target)
    parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    domain = parsed.hostname or target

    connector = aiohttp.TCPConnector(ssl=False, limit=200)
    session = aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"},
    )

    print(f"\n{B}{BOLD}[Infra] Resolving {domain}{RST}")

    # 1. Resolve IPs
    ips = await resolve_all(domain)
    result.primary_ips = ips
    print(f"  {G}[+]{RST} Resolved: {', '.join(ips) or 'NONE'}")

    if not ips:
        await session.close()
        return result

    # 2. Favicon hash for Shodan pivot
    fav_hash = await get_favicon_hash(target, session)
    if fav_hash:
        print(f"  {G}[+]{RST} Favicon hash (Shodan: http.favicon.hash:{fav_hash})")

    # 3. CT enumeration
    print(f"\n{B}{BOLD}[Infra] Certificate Transparency{RST}")
    ct_domains = await ct_enumerate(domain, session)
    result.ct_domains = ct_domains
    print(f"  {G}[+]{RST} {len(ct_domains)} domains from CT logs")
    if verbose:
        for d in ct_domains[:20]:
            print(f"    {DIM}{d}{RST}")

    # 4. ASN + CIDR per primary IP
    print(f"\n{B}{BOLD}[Infra] ASN / CIDR Enumeration{RST}")
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    all_cidrs: List[str] = []

    for ip in ips[:3]:
        asn_info = await get_asn_info(ip, session)
        provider, region = await detect_cloud_provider(ip, session)
        result.cloud_provider = provider

        print(f"  {G}[+]{RST} {ip} → ASN {asn_info.get('asn','')} {asn_info.get('org','')} [{provider}]")
        print(f"       {DIM}{len(asn_info.get('cidrs',[]))} CIDR blocks in this ASN{RST}")
        all_cidrs.extend(asn_info.get("cidrs", []))

        # Shodan data
        if shodan_key:
            sd = await shodan_api(ip, shodan_key, session)
        else:
            sd = await shodan_internetdb(ip, session)
        if sd:
            known_ports = sd.get("ports", sd.get("data", []))
            vulns = sd.get("vulns", [])
            print(f"       {G}Shodan:{RST} ports={known_ports} vulns={vulns}")

    result.asn_cidrs = all_cidrs[:100]

    # 5. Port scanning on primary IPs
    print(f"\n{B}{BOLD}[Infra] Port Scanning{RST}")
    all_open_ports: List[PortResult] = []

    ports_to_scan = ALL_SERVICE_PORTS if not full_port_scan else list(range(1, 65536))
    # Always include the extended web ports
    combined_ports = sorted(set(ports_to_scan + INTERESTING_PORTS_WEB))

    for ip in ips[:5]:
        print(f"  {DIM}Scanning {ip} ({len(combined_ports)} ports)…{RST}")
        # Try nmap first
        nmap_results = await nmap_scan(ip, aggressive=full_port_scan, outdir=outdir)
        if nmap_results:
            all_open_ports.extend(nmap_results)
            print(f"  {G}[nmap]{RST} {ip}: {len(nmap_results)} open ports")
        else:
            # Fall back to raw async TCP probe
            port_results = await scan_ports(ip, combined_ports,
                                            concurrency=concurrency, verbose=verbose)
            all_open_ports.extend(port_results)
            print(f"  {G}[tcp]{RST}  {ip}: {len(port_results)} open ports")

    result.interesting_ports = all_open_ports

    # 6. HTTP fingerprinting on all open ports
    print(f"\n{B}{BOLD}[Infra] HTTP Service Detection{RST}")
    web_ports = [p for p in all_open_ports
                 if p.service in ("http","https","http-alt","https-alt","unknown")
                 or p.port in INTERESTING_PORTS_WEB]

    for host_ip in ips[:5]:
        hostnames = [domain] + [d for d in ct_domains[:5] if d != domain]
        for pr in web_ports:
            if pr.ip == host_ip:
                http_info = await fingerprint_http(host_ip, pr.port, session,
                                                   hostname=domain)
                if http_info:
                    result.hosts.append(HostInfo(
                        ip=host_ip,
                        hostnames=hostnames,
                        cloud_provider=result.cloud_provider,
                        open_ports=[pr],
                        http_services=[http_info],
                    ))
                    print(f"  {G}[http]{RST} {http_info['url']} [{http_info['status']}] "
                          f"tech={http_info['tech']} issues={len(http_info['security_issues'])}")
                    if http_info.get("interesting"):
                        print(f"    {R}[!]{RST} INTERESTING: {http_info['interesting']}")

    # 7. ASN range scanning (find unlisted services across org's IP space)
    if scan_asn_range and all_cidrs:
        print(f"\n{B}{BOLD}[Infra] ASN Range Reverse DNS{RST}")
        # Focus on smaller CIDRs to avoid scanning forever
        small_cidrs = [c for c in all_cidrs[:20]
                       if ipaddress.ip_network(c, strict=False).num_addresses <= 256]
        for cidr in small_cidrs[:5]:
            rdns_results = await resolve_cidr_reverse(cidr, session)
            for ip, names in rdns_results:
                org_names = [n for n in names if domain.split(".")[-2] in n]
                if org_names:
                    print(f"  {G}[rdns]{RST} {ip} → {org_names}")

    # 8. Cloud storage brute
    if buckets:
        print(f"\n{B}{BOLD}[Infra] Cloud Storage Enumeration{RST}")
        company = domain.split(".")[0]
        bucket_results = await brute_buckets(company, session, verbose)
        result.storage_buckets = bucket_results
        if bucket_results:
            print(f"  {G}[+]{RST} {len(bucket_results)} buckets found!")
            for b in bucket_results:
                status_color = R if b["status"] == "open" else Y
                print(f"    {status_color}[{b['status']}]{RST} {b['service']} {b['url']}")
        else:
            print(f"  {DIM}No open buckets found{RST}")

    # 9. GitHub secret scanning
    if github_org:
        print(f"\n{B}{BOLD}[Infra] GitHub Secret Scanning → {github_org}{RST}")
        gh_secrets = await scan_github_org(github_org, session, verbose)
        result.github_secrets = gh_secrets
        if gh_secrets:
            print(f"  {R}[!]{RST} {len(gh_secrets)} potential secrets in public repos!")
            for s in gh_secrets[:10]:
                print(f"    {Y}{s['secret_type']}{RST} in {s['repo']} → {s['file']}")

    await session.close()

    # Save JSON
    out_path = os.path.join(outdir, f"infra_{domain}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "domain": domain,
            "primary_ips": result.primary_ips,
            "cloud_provider": result.cloud_provider,
            "asn_cidrs": result.asn_cidrs[:50],
            "ct_domains": result.ct_domains,
            "open_ports": [
                {"ip": p.ip, "port": p.port, "service": p.service,
                 "version": p.version, "banner": p.banner}
                for p in result.interesting_ports
            ],
            "http_services": [
                {"ip": h.ip, "services": h.http_services}
                for h in result.hosts
            ],
            "storage_buckets": result.storage_buckets,
            "github_secrets_count": len(result.github_secrets),
            "favicon_hash": fav_hash,
        }, f, indent=2)
    print(f"\n{G}[+]{RST} Infrastructure report → {out_path}")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="infra.py — Real Infrastructure Enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target domain or URL (e.g. https://app.target.com)")
    parser.add_argument("-o", "--output", default=".", help="Output directory")
    parser.add_argument("--full-ports", action="store_true", help="Full 1-65535 port scan (slow)")
    parser.add_argument("--asn-range", action="store_true", help="Reverse-DNS scan ASN CIDR ranges")
    parser.add_argument("--no-buckets", action="store_true", help="Skip cloud storage brute")
    parser.add_argument("--github-org", help="GitHub org name to scan for secrets")
    parser.add_argument("-c", "--concurrency", type=int, default=100)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(enumerate_infrastructure(
        target=args.target,
        outdir=args.output,
        full_port_scan=args.full_ports,
        scan_asn_range=args.asn_range,
        buckets=not args.no_buckets,
        github_org=args.github_org or "",
        verbose=args.verbose,
        concurrency=args.concurrency,
    ))
