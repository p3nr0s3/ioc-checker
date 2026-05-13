"""
OSINT API integration layer.
Each checker returns a standardised OsintResult dict.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from utils.ioc_detector import IOCType


# ── Result schema ─────────────────────────────────────────────────────────────

VERDICT_MALICIOUS  = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN      = "clean"
VERDICT_UNKNOWN    = "unknown"
VERDICT_ERROR      = "error"


@dataclass
class SourceResult:
    source:     str
    verdict:    str                        # one of the VERDICT_* constants
    score:      float | None = None        # 0.0–100.0 if applicable
    details:    dict[str, Any] = field(default_factory=dict)
    url:        str | None = None          # permalink to report
    error:      str | None = None


@dataclass
class OsintResult:
    ioc:        str
    ioc_type:   IOCType
    sources:    list[SourceResult] = field(default_factory=list)
    checked_at: float = field(default_factory=time.time)
    # ── Enrichment fields (populated by orchestrator) ──────────────
    threat_context: Any | None = None      # ThreatContext object
    greynoise:      Any | None = None      # GreyNoiseResult object

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
    """Query VirusTotal v3 API."""
    base = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    try:
        if ioc_type == IOCType.IP:
            url = f"{base}/ip_addresses/{ioc}"
            report_url = f"https://www.virustotal.com/gui/ip-address/{ioc}"
        elif ioc_type in (IOCType.DOMAIN,):
            url = f"{base}/domains/{ioc}"
            report_url = f"https://www.virustotal.com/gui/domain/{ioc}"
        elif ioc_type == IOCType.URL:
            url_id = hashlib.sha256(ioc.encode()).hexdigest()
            url = f"{base}/urls/{url_id}"
            report_url = f"https://www.virustotal.com/gui/url/{url_id}"
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            url = f"{base}/files/{ioc}"
            report_url = f"https://www.virustotal.com/gui/file/{ioc}"
        else:
            return SourceResult(
                source="VirusTotal", verdict=VERDICT_UNKNOWN,
                error="IOC type not supported"
            )

        r = await client.get(url, headers=headers, timeout=15)

        if r.status_code == 404:
            return SourceResult(source="VirusTotal", verdict=VERDICT_UNKNOWN,
                                url=report_url, details={"note": "Not found in VT"})
        r.raise_for_status()

        data = r.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1

        if malicious > 0:
            verdict = VERDICT_MALICIOUS
        elif suspicious > 0:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_CLEAN

        score = round((malicious + suspicious) / total * 100, 1)

        details: dict[str, Any] = {
            "malicious":  malicious,
            "suspicious": suspicious,
            "undetected": stats.get("undetected", 0),
            "harmless":   stats.get("harmless", 0),
            "total_engines": total,
        }

        # Extra context per type
        if ioc_type == IOCType.IP:
            details["country"] = data.get("country", "—")
            details["asn"]     = data.get("asn", "—")
            details["as_owner"] = data.get("as_owner", "—")
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            details["type_description"] = data.get("type_description", "—")
            details["meaningful_name"]  = data.get("meaningful_name", "—")
            details["size"] = data.get("size", "—")

        return SourceResult(
            source="VirusTotal", verdict=verdict, score=score,
            details=details, url=report_url
        )

    except httpx.HTTPStatusError as e:
        return SourceResult(source="VirusTotal", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="VirusTotal", verdict=VERDICT_ERROR,
                            error=str(e))


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async def check_abuseipdb(
    ioc: str, ioc_type: IOCType, api_key: str, client: httpx.AsyncClient
) -> SourceResult:
    """Query AbuseIPDB — only supports IP addresses."""
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

        if confidence >= 75:
            verdict = VERDICT_MALICIOUS
        elif confidence >= 25:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_CLEAN

        return SourceResult(
            source="AbuseIPDB",
            verdict=verdict,
            score=float(confidence),
            url=f"https://www.abuseipdb.com/check/{ioc}",
            details={
                "confidence_score": confidence,
                "total_reports":    d.get("totalReports", 0),
                "country":          d.get("countryCode", "—"),
                "isp":              d.get("isp", "—"),
                "domain":           d.get("domain", "—"),
                "usage_type":       d.get("usageType", "—"),
                "is_tor":           d.get("isTor", False),
                "is_vpn":           d.get("isVpn", False) if "isVpn" in d else "—",
            },
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
    """Query Shodan host info — only supports IP addresses."""
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
        verdict = VERDICT_MALICIOUS if vulns else VERDICT_UNKNOWN

        ports = d.get("ports", [])
        tags  = d.get("tags", [])

        # Suspicious tags
        suspicious_tags = {"malware", "botnet", "c2", "tor", "vpn", "proxy"}
        if any(t.lower() in suspicious_tags for t in tags):
            verdict = VERDICT_SUSPICIOUS if verdict == VERDICT_UNKNOWN else verdict

        return SourceResult(
            source="Shodan",
            verdict=verdict,
            url=f"https://www.shodan.io/host/{ioc}",
            details={
                "org":          d.get("org", "—"),
                "isp":          d.get("isp", "—"),
                "country":      d.get("country_name", "—"),
                "os":           d.get("os", "—"),
                "open_ports":   ports[:20],            # cap for display
                "port_count":   len(ports),
                "hostnames":    d.get("hostnames", [])[:5],
                "tags":         tags,
                "vulns":        list(vulns.keys())[:10],
                "vuln_count":   len(vulns),
            },
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
    """Query AlienVault OTX."""
    base = "https://otx.alienvault.com/api/v1/indicators"
    headers = {"X-OTX-API-KEY": api_key}

    type_map = {
        IOCType.IP:     ("IPv4", "general"),
        IOCType.DOMAIN: ("domain", "general"),
        IOCType.URL:    ("url", "general"),
        IOCType.MD5:    ("file", "general"),
        IOCType.SHA1:   ("file", "general"),
        IOCType.SHA256: ("file", "general"),
    }

    if ioc_type not in type_map:
        return SourceResult(source="OTX AlienVault", verdict=VERDICT_UNKNOWN,
                            error="IOC type not supported")

    otx_type, section = type_map[ioc_type]

    try:
        r = await client.get(
            f"{base}/{otx_type}/{ioc}/{section}",
            headers=headers,
            timeout=15,
        )
        if r.status_code == 404:
            return SourceResult(source="OTX AlienVault", verdict=VERDICT_UNKNOWN,
                                details={"note": "Not found in OTX"})
        r.raise_for_status()
        d = r.json()

        pulse_count = d.get("pulse_info", {}).get("count", 0)

        if pulse_count >= 5:
            verdict = VERDICT_MALICIOUS
        elif pulse_count >= 1:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_CLEAN

        pulses = d.get("pulse_info", {}).get("pulses", [])
        tags_all: list[str] = []
        for p in pulses[:5]:
            tags_all.extend(p.get("tags", []))

        return SourceResult(
            source="OTX AlienVault",
            verdict=verdict,
            score=min(float(pulse_count) * 10, 100.0),
            url=f"https://otx.alienvault.com/indicator/{otx_type}/{ioc}",
            details={
                "pulse_count": pulse_count,
                "top_tags":    list(set(tags_all))[:10],
                "reputation":  d.get("reputation", "—"),
                "country":     d.get("country_name", "—") if ioc_type == IOCType.IP else "—",
            },
        )
    except httpx.HTTPStatusError as e:
        return SourceResult(source="OTX AlienVault", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="OTX AlienVault", verdict=VERDICT_ERROR,
                            error=str(e))


# ── URLScan.io ────────────────────────────────────────────────────────────────

async def check_urlscan(
    ioc: str, ioc_type: IOCType, api_key: str, client: httpx.AsyncClient
) -> SourceResult:
    """Query URLScan.io search — supports URL, domain, IP."""
    if ioc_type not in (IOCType.URL, IOCType.DOMAIN, IOCType.IP):
        return SourceResult(source="URLScan.io", verdict=VERDICT_UNKNOWN,
                            error="Only supports URL, domain, IP")

    headers = {"API-Key": api_key, "Content-Type": "application/json"}

    # Build search query
    if ioc_type == IOCType.IP:
        q = f"ip:{ioc}"
    elif ioc_type == IOCType.DOMAIN:
        q = f"domain:{ioc}"
    else:
        q = f"page.url:{ioc}"

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
        score = round(malicious_count / len(results) * 100, 1)

        if malicious_count >= 3:
            verdict = VERDICT_MALICIOUS
        elif malicious_count >= 1:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_CLEAN

        # Latest scan details
        latest = results[0]
        page = latest.get("page", {})

        return SourceResult(
            source="URLScan.io",
            verdict=verdict,
            score=score,
            url=latest.get("result"),
            details={
                "total_scans":    len(results),
                "malicious_scans": malicious_count,
                "latest_country": page.get("country", "—"),
                "latest_server":  page.get("server", "—"),
                "latest_ip":      page.get("ip", "—"),
                "tags":           latest.get("verdicts", {}).get("overall", {}).get("tags", []),
            },
        )
    except httpx.HTTPStatusError as e:
        return SourceResult(source="URLScan.io", verdict=VERDICT_ERROR,
                            error=f"HTTP {e.response.status_code}")
    except Exception as e:
        return SourceResult(source="URLScan.io", verdict=VERDICT_ERROR,
                            error=str(e))


# ── Orchestrator ──────────────────────────────────────────────────────────────

async def check_ioc_async(
    ioc: str,
    ioc_type: IOCType,
    api_keys: dict[str, str],
) -> OsintResult:
    """Run all enabled OSINT checks concurrently for a single IOC.

    Args:
        ioc:      The IOC string to check.
        ioc_type: Detected IOC type.
        api_keys: Dict of source → API key (only sources with non-empty keys run).

    Returns:
        OsintResult with all source results + threat_context + greynoise enrichment.
    """
    from utils.threat_context import derive_threat_context
    from utils.greynoise_api import check_greynoise

    result = OsintResult(ioc=ioc, ioc_type=ioc_type)

    async with httpx.AsyncClient() as client:
        tasks: list[asyncio.Task] = []

        checker_map = {
            "virustotal": check_virustotal,
            "abuseipdb":  check_abuseipdb,
            "shodan":     check_shodan,
            "otx":        check_otx,
            "urlscan":    check_urlscan,
        }

        for key_name, checker_fn in checker_map.items():
            api_key = api_keys.get(key_name, "").strip()
            if api_key:
                tasks.append(
                    asyncio.create_task(
                        checker_fn(ioc, ioc_type, api_key, client)
                    )
                )

        if tasks:
            source_results = await asyncio.gather(*tasks, return_exceptions=True)
            for sr in source_results:
                if isinstance(sr, Exception):
                    result.sources.append(
                        SourceResult(source="unknown", verdict=VERDICT_ERROR,
                                     error=str(sr))
                    )
                else:
                    result.sources.append(sr)

        # ── GreyNoise enrichment (IP only) ──────────────────────────
        gn_key = api_keys.get("greynoise", "").strip()
        if gn_key and ioc_type == IOCType.IP:
            try:
                gn_result = await check_greynoise(ioc, gn_key, client)
                result.greynoise = gn_result
            except Exception:
                result.greynoise = None

    # ── Threat context derivation (post-gather, sync) ───────────────
    try:
        result.threat_context = derive_threat_context(
            verdict=result.overall_verdict,
            sources=result.sources,
        )
    except Exception:
        result.threat_context = None

    return result


def check_ioc(
    ioc: str,
    ioc_type: IOCType,
    api_keys: dict[str, str],
) -> OsintResult:
    """Synchronous wrapper for check_ioc_async — safe to call from Streamlit."""
    return asyncio.run(check_ioc_async(ioc, ioc_type, api_keys))
