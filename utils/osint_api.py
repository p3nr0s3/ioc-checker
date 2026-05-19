"""
OSINT API integration layer.
Each checker returns a standardised OsintResult with rich, IOC-type-aware details.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from utils.ioc_detector import IOCType


VERDICT_MALICIOUS  = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN      = "clean"
VERDICT_UNKNOWN    = "unknown"
VERDICT_ERROR      = "error"


@dataclass
class SourceResult:
    source:   str
    verdict:  str
    score:    float | None = None
    details:  dict[str, Any] = field(default_factory=dict)
    url:      str | None = None
    error:    str | None = None


@dataclass
class OsintResult:
    ioc:        str
    ioc_type:   IOCType
    sources:    list[SourceResult] = field(default_factory=list)
    checked_at: float = field(default_factory=time.time)

    @property
    def overall_verdict(self) -> str:
        verdicts = [s.verdict for s in self.sources if s.verdict != VERDICT_ERROR]
        if not verdicts:
            return VERDICT_UNKNOWN
        if VERDICT_MALICIOUS in verdicts:
            return VERDICT_MALICIOUS
        if VERDICT_SUSPICIOUS in verdicts:
            return VERDICT_SUSPICIOUS
        if all(v == VERDICT_CLEAN for v in verdicts):
            return VERDICT_CLEAN
        return VERDICT_UNKNOWN

    @property
    def malicious_count(self) -> int:
        return sum(1 for s in self.sources if s.verdict == VERDICT_MALICIOUS)

    @property
    def source_count(self) -> int:
        return len([s for s in self.sources if s.verdict != VERDICT_ERROR])


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def check_virustotal(
    ioc: str, ioc_type: IOCType, api_key: str, client: httpx.AsyncClient
) -> SourceResult:
    base    = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    try:
        if ioc_type == IOCType.IP:
            endpoint   = f"{base}/ip_addresses/{ioc}"
            report_url = f"https://www.virustotal.com/gui/ip-address/{ioc}"
        elif ioc_type == IOCType.DOMAIN:
            endpoint   = f"{base}/domains/{ioc}"
            report_url = f"https://www.virustotal.com/gui/domain/{ioc}"
        elif ioc_type == IOCType.URL:
            url_id     = hashlib.sha256(ioc.encode()).hexdigest()
            endpoint   = f"{base}/urls/{url_id}"
            report_url = f"https://www.virustotal.com/gui/url/{url_id}"
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            endpoint   = f"{base}/files/{ioc}"
            report_url = f"https://www.virustotal.com/gui/file/{ioc}"
        else:
            return SourceResult(source="VirusTotal", verdict=VERDICT_UNKNOWN,
                                error="IOC type not supported")

        r = await client.get(endpoint, headers=headers, timeout=15)
        if r.status_code == 404:
            return SourceResult(source="VirusTotal", verdict=VERDICT_UNKNOWN,
                                url=report_url, details={"note": "Not found in VT"})
        r.raise_for_status()

        data  = r.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = sum(stats.values()) or 1

        verdict = (VERDICT_MALICIOUS if malicious > 0
                   else VERDICT_SUSPICIOUS if suspicious > 0
                   else VERDICT_CLEAN)
        score   = round((malicious + suspicious) / total * 100, 1)

        # ── Base engine stats (all IOC types) ─────────────────────
        details: dict[str, Any] = {
            "engines_malicious":  malicious,
            "engines_suspicious": suspicious,
            "engines_harmless":   harmless,
            "engines_undetected": undetected,
            "engines_total":      total,
        }

        # ── IP-specific ────────────────────────────────────────────
        if ioc_type == IOCType.IP:
            details.update({
                "country":          data.get("country", ""),
                "continent":        data.get("continent", ""),
                "asn":              data.get("asn", ""),
                "as_owner":         data.get("as_owner", ""),
                "network":          data.get("network", ""),
                "regional_internet_registry": data.get("regional_internet_registry", ""),
                "last_https_cert_issuer": (
                    data.get("last_https_certificate", {})
                        .get("issuer", {}).get("O", "")
                ),
                "last_analysis_date": _ts(data.get("last_analysis_date")),
                "reputation":       data.get("reputation", 0),
                "total_votes_harmless":   data.get("total_votes", {}).get("harmless", 0),
                "total_votes_malicious":  data.get("total_votes", {}).get("malicious", 0),
            })

        # ── Domain-specific ────────────────────────────────────────
        elif ioc_type == IOCType.DOMAIN:
            details.update({
                "registrar":          data.get("registrar", ""),
                "creation_date":      _ts(data.get("creation_date")),
                "last_update_date":   _ts(data.get("last_update_date")),
                "last_dns_records":   _dns_summary(data.get("last_dns_records", [])),
                "categories":         _join(list(data.get("categories", {}).values())[:5]),
                "country":            data.get("country", ""),
                "reputation":         data.get("reputation", 0),
                "whois":              _whois_snippet(data.get("whois", "")),
                "last_analysis_date": _ts(data.get("last_analysis_date")),
                "total_votes_harmless":  data.get("total_votes", {}).get("harmless", 0),
                "total_votes_malicious": data.get("total_votes", {}).get("malicious", 0),
            })

        # ── URL-specific ───────────────────────────────────────────
        elif ioc_type == IOCType.URL:
            details.update({
                "final_url":          data.get("last_final_url", ""),
                "title":              data.get("title", ""),
                "last_http_response_code": data.get("last_http_response_code", ""),
                "last_http_response_content_type": data.get(
                    "last_http_response_headers", {}
                ).get("Content-Type", ""),
                "server":             data.get("last_http_response_headers", {})
                                          .get("Server", ""),
                "categories":         _join(list(data.get("categories", {}).values())[:5]),
                "first_submission":   _ts(data.get("first_submission_date")),
                "last_analysis_date": _ts(data.get("last_analysis_date")),
                "times_submitted":    data.get("times_submitted", 0),
                "reputation":         data.get("reputation", 0),
            })

        # ── Hash/File-specific ─────────────────────────────────────
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            sig  = data.get("signature_info", {})
            names = data.get("names", [])
            details.update({
                "file_name":          data.get("meaningful_name", "") or (names[0] if names else ""),
                "file_type":          data.get("type_description", ""),
                "file_extension":     data.get("type_extension", ""),
                "file_size_bytes":    data.get("size", ""),
                "md5":                data.get("md5", ""),
                "sha1":               data.get("sha1", ""),
                "sha256":             data.get("sha256", ""),
                "ssdeep":             data.get("ssdeep", ""),
                "magic":              data.get("magic", ""),
                "first_seen":         _ts(data.get("first_submission_date")),
                "last_seen":          _ts(data.get("last_analysis_date")),
                "times_submitted":    data.get("times_submitted", 0),
                "unique_sources":     data.get("unique_sources", 0),
                "popular_threat_name": data.get("popular_threat_classification", {})
                                           .get("suggested_threat_label", ""),
                "signature_product":  sig.get("product", ""),
                "signature_verified": sig.get("verified", ""),
                "tags":               _join(data.get("tags", [])[:8]),
                "reputation":         data.get("reputation", 0),
            })

        return SourceResult(
            source="VirusTotal", verdict=verdict, score=score,
            details=details, url=report_url,
        )

    except httpx.HTTPStatusError as e:
        return SourceResult(source="VirusTotal", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="VirusTotal", verdict=VERDICT_ERROR, error=str(e))


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async def check_abuseipdb(
    ioc: str, ioc_type: IOCType, api_key: str, client: httpx.AsyncClient
) -> SourceResult:
    if ioc_type != IOCType.IP:
        return SourceResult(source="AbuseIPDB", verdict=VERDICT_UNKNOWN,
                            error="Only supports IP addresses")
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": 90, "verbose": True},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json()["data"]
        confidence = d.get("abuseConfidenceScore", 0)

        verdict = (VERDICT_MALICIOUS  if confidence >= 75
                   else VERDICT_SUSPICIOUS if confidence >= 25
                   else VERDICT_CLEAN)

        # Country name lookup from code
        country_code = d.get("countryCode", "")
        country_name = d.get("countryName", "") or country_code

        reports = d.get("reports", []) or []
        categories_raw: list[int] = []
        for rep in reports[:20]:
            categories_raw.extend(rep.get("categories", []))
        top_categories = _join(
            list({_abuse_category(c) for c in categories_raw if c})
        )

        # Last reporter info (most recent report)
        last_report  = reports[0] if reports else {}
        last_reported_at  = last_report.get("reportedAt", "")
        last_reporter_cc  = last_report.get("reporterCountryCode", "")
        last_comment      = (last_report.get("comment", "") or "")[:200]

        details: dict[str, Any] = {
            # Identity
            "ip_address":          d.get("ipAddress", ioc),
            "ip_version":          d.get("ipVersion", ""),
            "is_public":           d.get("isPublic", ""),
            # Location
            "country_code":        country_code,
            "country_name":        country_name,
            # Network
            "isp":                 d.get("isp", ""),
            "domain":              d.get("domain", ""),
            "hostnames":           _join(d.get("hostnames", [])[:5]),
            "usage_type":          d.get("usageType", ""),
            "asn":                 d.get("asnId", "") or d.get("asn", ""),
            # Flags
            "is_tor":              d.get("isTor", False),
            "is_vpn":              d.get("isVpn", ""),
            "is_whitelisted":      d.get("isWhitelisted", False),
            # Abuse data
            "confidence_score":    confidence,
            "total_reports":       d.get("totalReports", 0),
            "num_distinct_users":  d.get("numDistinctUsers", 0),
            "last_reported_at":    last_reported_at,
            "abuse_categories":    top_categories,
            "last_reporter_cc":    last_reporter_cc,
            "last_comment":        last_comment,
        }

        return SourceResult(
            source="AbuseIPDB", verdict=verdict,
            score=float(confidence),
            url=f"https://www.abuseipdb.com/check/{ioc}",
            details=details,
        )
    except httpx.HTTPStatusError as e:
        return SourceResult(source="AbuseIPDB", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="AbuseIPDB", verdict=VERDICT_ERROR, error=str(e))


# ── Shodan ────────────────────────────────────────────────────────────────────

async def check_shodan(
    ioc: str, ioc_type: IOCType, api_key: str, client: httpx.AsyncClient
) -> SourceResult:
    if ioc_type != IOCType.IP:
        return SourceResult(source="Shodan", verdict=VERDICT_UNKNOWN,
                            error="Only supports IP addresses")
    try:
        r = await client.get(
            f"https://api.shodan.io/shodan/host/{ioc}",
            params={"key": api_key},
            timeout=15,
        )
        if r.status_code == 404:
            return SourceResult(source="Shodan", verdict=VERDICT_UNKNOWN,
                                details={"note": "No Shodan data available"})
        r.raise_for_status()
        d = r.json()

        vulns = d.get("vulns", {})
        ports = sorted(d.get("ports", []))
        tags  = d.get("tags", [])

        # Enrich with service banners from data array
        services: list[dict] = d.get("data", [])
        service_summary = _service_summary(services[:15])

        # CVE severity breakdown
        critical_cves = [c for c in vulns if vulns.get(c, {}).get("cvss", 0) >= 9.0]
        high_cves     = [c for c in vulns
                         if 7.0 <= vulns.get(c, {}).get("cvss", 0) < 9.0]

        suspicious_tags = {"malware", "botnet", "c2", "tor", "vpn", "proxy",
                           "scanner", "honeypot"}
        threat_tags = [t for t in tags if t.lower() in suspicious_tags]

        verdict = (VERDICT_MALICIOUS  if vulns or threat_tags
                   else VERDICT_UNKNOWN)

        details: dict[str, Any] = {
            # Location
            "country_name":      d.get("country_name", ""),
            "country_code":      d.get("country_code", ""),
            "city":              d.get("city", ""),
            "region_code":       d.get("region_code", ""),
            "latitude":          d.get("latitude", ""),
            "longitude":         d.get("longitude", ""),
            # Network
            "org":               d.get("org", ""),
            "isp":               d.get("isp", ""),
            "asn":               d.get("asn", ""),
            "hostnames":         _join(d.get("hostnames", [])[:6]),
            "domains":           _join(d.get("domains", [])[:6]),
            "ip_str":            d.get("ip_str", ioc),
            # System
            "os":                d.get("os", ""),
            "last_update":       d.get("last_update", ""),
            # Ports / services
            "open_port_count":   len(ports),
            "open_ports":        _join([str(p) for p in ports[:25]]),
            "services":          service_summary,
            "tags":              _join(tags),
            "threat_tags":       _join(threat_tags),
            # Vulns
            "vuln_count":        len(vulns),
            "cves":              _join(list(vulns.keys())[:15]),
            "critical_cves":     _join(critical_cves[:5]),
            "high_cves":         _join(high_cves[:5]),
        }

        return SourceResult(
            source="Shodan", verdict=verdict, score=None,
            url=f"https://www.shodan.io/host/{ioc}",
            details=details,
        )
    except httpx.HTTPStatusError as e:
        return SourceResult(source="Shodan", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="Shodan", verdict=VERDICT_ERROR, error=str(e))


# ── AlienVault OTX ────────────────────────────────────────────────────────────

async def check_otx(
    ioc: str, ioc_type: IOCType, api_key: str, client: httpx.AsyncClient
) -> SourceResult:
    base    = "https://otx.alienvault.com/api/v1/indicators"
    headers = {"X-OTX-API-KEY": api_key}

    type_map = {
        IOCType.IP:     ("IPv4",   "general"),
        IOCType.DOMAIN: ("domain", "general"),
        IOCType.URL:    ("url",    "general"),
        IOCType.MD5:    ("file",   "general"),
        IOCType.SHA1:   ("file",   "general"),
        IOCType.SHA256: ("file",   "general"),
        IOCType.EMAIL:  ("email",  "general"),
    }

    if ioc_type not in type_map:
        return SourceResult(source="OTX AlienVault", verdict=VERDICT_UNKNOWN,
                            error="IOC type not supported")

    otx_type, section = type_map[ioc_type]

    try:
        r = await client.get(
            f"{base}/{otx_type}/{ioc}/{section}",
            headers=headers, timeout=15,
        )
        if r.status_code == 404:
            return SourceResult(source="OTX AlienVault", verdict=VERDICT_UNKNOWN,
                                details={"note": "Not found in OTX"})
        r.raise_for_status()
        d = r.json()

        pulse_count = d.get("pulse_info", {}).get("count", 0)
        verdict = (VERDICT_MALICIOUS  if pulse_count >= 5
                   else VERDICT_SUSPICIOUS if pulse_count >= 1
                   else VERDICT_CLEAN)

        pulses   = d.get("pulse_info", {}).get("pulses", [])
        tags_all: list[str] = []
        pulse_names: list[str] = []
        pulse_authors: list[str] = []
        malware_families: list[str] = []
        attack_ids: list[str] = []

        for p in pulses[:10]:
            tags_all.extend(p.get("tags", []))
            pulse_names.append(p.get("name", ""))
            pulse_authors.append(p.get("author_name", ""))
            malware_families.extend(
                [m.get("display_name", "") for m in p.get("malware_families", [])]
            )
            attack_ids.extend(
                [a.get("id", "") for a in p.get("attack_ids", [])]
            )

        details: dict[str, Any] = {
            "pulse_count":      pulse_count,
            "reputation":       d.get("reputation", 0),
        }

        # IP-specific OTX fields
        if ioc_type == IOCType.IP:
            details.update({
                "country_name":  d.get("country_name", ""),
                "country_code":  d.get("country_code", ""),
                "asn":           d.get("asn", ""),
                "city":          d.get("city", ""),
                "latitude":      d.get("latitude", ""),
                "longitude":     d.get("longitude", ""),
            })

        # Domain-specific
        elif ioc_type == IOCType.DOMAIN:
            details.update({
                "alexa":         d.get("alexa", ""),
                "whois":         _whois_snippet(d.get("whois", "")),
            })

        # File/Hash-specific
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            details.update({
                "md5":           d.get("hash", {}).get("md5", ""),
                "sha1":          d.get("hash", {}).get("sha1", ""),
                "sha256":        d.get("hash", {}).get("sha256", ""),
                "file_type":     d.get("analysis", {}).get("info", {})
                                    .get("results", {}).get("file_type", ""),
                "file_size":     d.get("analysis", {}).get("info", {})
                                    .get("results", {}).get("filesize", ""),
            })

        # Pulse detail
        details.update({
            "top_pulse_names":    _join(pulse_names[:5]),
            "pulse_authors":      _join(list(set(pulse_authors))[:5]),
            "malware_families":   _join(list(set(malware_families))[:8]),
            "attack_ids":         _join(list(set(attack_ids))[:10]),
            "tags":               _join(list(set(tags_all))[:12]),
        })

        return SourceResult(
            source="OTX AlienVault", verdict=verdict,
            score=min(float(pulse_count) * 10, 100.0),
            url=f"https://otx.alienvault.com/indicator/{otx_type}/{ioc}",
            details=details,
        )
    except httpx.HTTPStatusError as e:
        return SourceResult(source="OTX AlienVault", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="OTX AlienVault", verdict=VERDICT_ERROR, error=str(e))


# ── URLScan.io ────────────────────────────────────────────────────────────────

async def check_urlscan(
    ioc: str, ioc_type: IOCType, api_key: str, client: httpx.AsyncClient
) -> SourceResult:
    if ioc_type not in (IOCType.URL, IOCType.DOMAIN, IOCType.IP):
        return SourceResult(source="URLScan.io", verdict=VERDICT_UNKNOWN,
                            error="Only supports URL, domain, IP")

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    q = (f"ip:{ioc}"         if ioc_type == IOCType.IP
         else f"domain:{ioc}" if ioc_type == IOCType.DOMAIN
         else f"page.url:{ioc}")

    try:
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            headers=headers,
            params={"q": q, "size": 10},
            timeout=15,
        )
        r.raise_for_status()
        results = r.json().get("results", [])

        if not results:
            return SourceResult(source="URLScan.io", verdict=VERDICT_UNKNOWN,
                                details={"note": "No scans found"})

        malicious_count = sum(
            1 for res in results
            if res.get("verdicts", {}).get("overall", {}).get("malicious", False)
        )
        score   = round(malicious_count / len(results) * 100, 1)
        verdict = (VERDICT_MALICIOUS  if malicious_count >= 3
                   else VERDICT_SUSPICIOUS if malicious_count >= 1
                   else VERDICT_CLEAN)

        latest = results[0]
        page   = latest.get("page", {})
        stats  = latest.get("stats", {})
        meta   = latest.get("meta", {})
        v_tags = latest.get("verdicts", {}).get("overall", {}).get("tags", [])

        # Aggregate categories across scans
        categories: set[str] = set()
        for res in results:
            for cat in res.get("verdicts", {}).get("overall", {}).get("categories", []):
                categories.add(cat)

        details: dict[str, Any] = {
            "total_scans":      len(results),
            "malicious_scans":  malicious_count,
            # Latest scan page info
            "page_url":         page.get("url", ""),
            "page_domain":      page.get("domain", ""),
            "page_ip":          page.get("ip", ""),
            "page_country":     page.get("country", ""),
            "page_server":      page.get("server", ""),
            "page_mime_type":   page.get("mimeType", ""),
            "page_status_code": page.get("status", ""),
            "page_title":       page.get("title", ""),
            # Scan stats
            "requests_total":   stats.get("requests", {}).get("total", ""),
            "requests_malicious": stats.get("requests", {}).get("malicious", ""),
            "unique_domains":   stats.get("uniqDomains", ""),
            "unique_ips":       stats.get("uniqIPs", ""),
            # Metadata
            "asnname":          meta.get("processors", {}).get("asn", {})
                                    .get("data", [{}])[0].get("name", "") if
                                    meta.get("processors", {}).get("asn", {})
                                        .get("data") else "",
            "screenshot_url":   latest.get("screenshot", ""),
            "verdict_tags":     _join(v_tags),
            "categories":       _join(list(categories)[:8]),
        }

        return SourceResult(
            source="URLScan.io", verdict=verdict, score=score,
            url=latest.get("result"),
            details=details,
        )
    except httpx.HTTPStatusError as e:
        return SourceResult(source="URLScan.io", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="URLScan.io", verdict=VERDICT_ERROR, error=str(e))


# ── Orchestrator ──────────────────────────────────────────────────────────────

async def check_ioc_async(
    ioc: str, ioc_type: IOCType, api_keys: dict[str, str],
) -> OsintResult:
    result = OsintResult(ioc=ioc, ioc_type=ioc_type)
    async with httpx.AsyncClient() as client:
        checker_map = {
            "virustotal": check_virustotal,
            "abuseipdb":  check_abuseipdb,
            "shodan":     check_shodan,
            "otx":        check_otx,
            "urlscan":    check_urlscan,
        }
        tasks = [
            asyncio.create_task(fn(ioc, ioc_type, api_keys[k], client))
            for k, fn in checker_map.items()
            if api_keys.get(k, "").strip()
        ]
        if tasks:
            for sr in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(sr, Exception):
                    result.sources.append(
                        SourceResult(source="unknown", verdict=VERDICT_ERROR, error=str(sr))
                    )
                else:
                    result.sources.append(sr)
    return result


def check_ioc(ioc: str, ioc_type: IOCType, api_keys: dict[str, str]) -> OsintResult:
    return asyncio.run(check_ioc_async(ioc, ioc_type, api_keys))


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ts(epoch: int | None) -> str:
    """Unix timestamp → ISO date string."""
    if not epoch:
        return ""
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(int(epoch)))
    except Exception:
        return str(epoch)


def _join(items: list, sep: str = "; ") -> str:
    return sep.join(str(x) for x in items if x) if items else ""


def _whois_snippet(raw: str, max_chars: int = 300) -> str:
    if not raw:
        return ""
    lines = [l.strip() for l in raw.splitlines()
             if l.strip() and not l.strip().startswith("%")]
    return " | ".join(lines[:6])[:max_chars]


def _dns_summary(records: list[dict]) -> str:
    seen: list[str] = []
    for rec in records[:10]:
        rtype = rec.get("type", "")
        val   = rec.get("value", "")
        if rtype and val:
            seen.append(f"{rtype}:{val}")
    return "; ".join(seen)


def _service_summary(services: list[dict]) -> str:
    parts: list[str] = []
    for svc in services:
        port    = svc.get("port", "")
        product = svc.get("product", "")
        version = svc.get("version", "")
        label   = f"{port}/{product}" if product else str(port)
        if version:
            label += f" {version}"
        if label:
            parts.append(label)
    return "; ".join(parts[:10])


_ABUSE_CATEGORIES: dict[int, str] = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def _abuse_category(code: int) -> str:
    return _ABUSE_CATEGORIES.get(code, f"Cat#{code}")
