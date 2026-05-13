"""
greynoise_api.py
================
GreyNoise Community + Enterprise API integration (async, httpx).

GreyNoise classifies internet-wide scanners to reduce SOC false positives.
  - RIOT  : known benign services (Google, CDN, AWS, etc.) → low priority
  - Noise : internet background noise → deprioritize alert
  - Malicious noise : active attacker scans → elevate priority

API key: https://www.greynoise.io/
Free community API: limited fields but sufficient for triage.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import httpx

GN_ENTERPRISE_URL = "https://api.greynoise.io/v2/noise/context/{ip}"
GN_COMMUNITY_URL  = "https://api.greynoise.io/v3/community/{ip}"
TIMEOUT = 10


@dataclass
class GreyNoiseResult:
    ip: str
    noise: bool = False
    riot: bool = False
    classification: str = "unknown"   # "malicious" | "benign" | "unknown"
    name: str = ""                    # actor / tool name
    tags: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    link: str = ""
    message: str = ""
    error: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @property
    def verdict_label(self) -> str:
        if self.error:
            return "error"
        if self.riot:
            return "riot"
        if not self.noise:
            return "not_seen"
        return self.classification or "noise"

    @property
    def noise_label(self) -> str:
        if self.error:
            return f"GN Error"
        if self.riot:
            return "✓ RIOT — Benign"
        if self.noise and self.classification == "malicious":
            return "⚠ Malicious Scanner"
        if self.noise:
            return "~ Internet Noise"
        return "Not in GreyNoise"

    @property
    def is_low_priority(self) -> bool:
        """True when this is background noise or a benign service."""
        return self.riot or (self.noise and self.classification != "malicious")


async def check_greynoise(
    ioc: str,
    api_key: str,
    client: httpx.AsyncClient,
) -> GreyNoiseResult:
    """Async GreyNoise lookup. Tries enterprise endpoint, falls back to community."""
    if not api_key or not api_key.strip():
        return GreyNoiseResult(ip=ioc, error="No GreyNoise API key")

    headers = {"key": api_key.strip(), "Accept": "application/json"}

    # Try enterprise first
    try:
        resp = await client.get(
            GN_ENTERPRISE_URL.format(ip=ioc),
            headers=headers,
            timeout=TIMEOUT,
        )

        if resp.status_code == 200:
            d = resp.json()
            return GreyNoiseResult(
                ip=ioc,
                noise=d.get("noise", False),
                riot=d.get("riot", False),
                classification=d.get("classification", "unknown"),
                name=d.get("actor", d.get("name", "")),
                tags=d.get("tags", []),
                cve=d.get("cve", []),
                link=f"https://www.greynoise.io/viz/ip/{ioc}",
                message=d.get("message", ""),
                raw=d,
            )

        if resp.status_code == 404:
            return GreyNoiseResult(
                ip=ioc, noise=False, classification="unknown",
                message="IP not seen by GreyNoise.",
                link=f"https://www.greynoise.io/viz/ip/{ioc}",
            )

        if resp.status_code in (401, 403):
            # Key is community-tier — fall back
            return await _community_lookup(ioc, api_key, client)

        return GreyNoiseResult(ip=ioc, error=f"HTTP {resp.status_code}")

    except httpx.TimeoutException:
        return GreyNoiseResult(ip=ioc, error="Timeout")
    except Exception as e:
        return GreyNoiseResult(ip=ioc, error=str(e)[:80])


async def _community_lookup(
    ioc: str, api_key: str, client: httpx.AsyncClient
) -> GreyNoiseResult:
    headers = {"key": api_key.strip()}
    try:
        resp = await client.get(
            GN_COMMUNITY_URL.format(ip=ioc),
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json()
            return GreyNoiseResult(
                ip=ioc,
                noise=d.get("noise", False),
                riot=d.get("riot", False),
                classification=d.get("classification", "unknown"),
                name=d.get("name", ""),
                link=d.get("link", f"https://www.greynoise.io/viz/ip/{ioc}"),
                message=d.get("message", ""),
                raw=d,
            )
        if resp.status_code == 404:
            return GreyNoiseResult(
                ip=ioc, noise=False, classification="unknown",
                message="IP not seen by GreyNoise.",
            )
        return GreyNoiseResult(ip=ioc, error=f"Community API HTTP {resp.status_code}")
    except Exception as e:
        return GreyNoiseResult(ip=ioc, error=str(e)[:80])
