"""
Export helpers: OsintResult list → CSV / JSON / Sigma / YARA bytes.

Changes vs original:
  - CSV now includes: defanged_ioc, threat_tags, mitre_ids,
    greynoise_verdict, greynoise_noise columns
  - New: results_to_sigma()  — Sigma YAML rule skeletons for malicious IOCs
  - New: results_to_yara()   — YARA rules for malicious hash IOCs
"""
from __future__ import annotations

import csv
import datetime
import io
import json
import re
import time
from typing import Any

from utils.osint_api import OsintResult


# ── CSV ───────────────────────────────────────────────────────────────────────

def results_to_csv(results: list[OsintResult]) -> bytes:
    """Flatten results to enriched CSV — one row per IOC × source."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    headers = [
        "ioc", "defanged", "ioc_type", "overall_verdict",
        "threat_tags", "mitre_ids",
        "greynoise_verdict", "greynoise_noise",
        "source", "source_verdict", "score", "report_url", "error",
        "checked_at",
    ]
    writer.writerow(headers)

    for r in results:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at))
        defanged   = _defang(r.ioc)
        ctx        = r.threat_context
        gn         = r.greynoise
        tags_str   = "; ".join(ctx.tags)      if ctx else ""
        mitre_str  = "; ".join(ctx.mitre_ids) if ctx else ""
        gn_verdict = gn.verdict_label if gn else ""
        gn_noise   = ("yes" if gn.noise else "no") if gn else ""

        if r.sources:
            for s in r.sources:
                writer.writerow([
                    r.ioc, defanged, r.ioc_type.value, r.overall_verdict,
                    tags_str, mitre_str,
                    gn_verdict, gn_noise,
                    s.source, s.verdict, s.score or "",
                    s.url or "", s.error or "", ts,
                ])
        else:
            writer.writerow([
                r.ioc, defanged, r.ioc_type.value, r.overall_verdict,
                tags_str, mitre_str,
                gn_verdict, gn_noise,
                "", "", "", "", "", ts,
            ])

    return buf.getvalue().encode("utf-8")


# ── JSON ──────────────────────────────────────────────────────────────────────

def results_to_json(results: list[OsintResult]) -> bytes:
    """Serialise results list to pretty-printed JSON bytes (enriched)."""

    def _serialise(r: OsintResult) -> dict[str, Any]:
        ctx = r.threat_context
        gn  = r.greynoise
        return {
            "ioc":             r.ioc,
            "defanged":        _defang(r.ioc),
            "ioc_type":        r.ioc_type.value,
            "overall_verdict": r.overall_verdict,
            "malicious_sources": r.malicious_count,
            "checked_at":      time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at)
            ),
            "threat_context": {
                "tags":       ctx.tags    if ctx else [],
                "mitre":      ctx.mitre   if ctx else [],
                "confidence": ctx.confidence if ctx else 0,
            },
            "greynoise": {
                "noise":          gn.noise if gn else None,
                "riot":           gn.riot  if gn else None,
                "classification": gn.classification if gn else None,
                "verdict":        gn.verdict_label  if gn else None,
                "name":           gn.name if gn else "",
                "link":           gn.link if gn else "",
            } if gn else None,
            "sources": [
                {
                    "source":  s.source,
                    "verdict": s.verdict,
                    "score":   s.score,
                    "url":     s.url,
                    "details": s.details,
                    "error":   s.error,
                }
                for s in r.sources
            ],
        }

    return json.dumps([_serialise(r) for r in results], indent=2).encode("utf-8")


# ── Sigma ─────────────────────────────────────────────────────────────────────

def results_to_sigma(results: list[OsintResult]) -> bytes:
    """Generate Sigma YAML rule skeletons for malicious/suspicious network IOCs."""
    from utils.ioc_detector import IOCType

    targets = [
        r for r in results
        if r.overall_verdict in ("malicious", "suspicious")
        and r.ioc_type in (IOCType.IP, IOCType.DOMAIN, IOCType.URL)
    ]

    if not targets:
        return b"# No malicious network IOCs found for Sigma rule generation."

    lines: list[str] = []
    today = datetime.date.today().strftime("%Y/%m/%d")

    for r in targets:
        ctx      = r.threat_context
        tags_cmt = ", ".join(ctx.tags[:3]) if ctx and ctx.tags else r.overall_verdict
        mitre_yaml = "\n".join(
            f"    - attack.{t['id'].lower().replace('.', '_')}"
            for t in (ctx.mitre[:3] if ctx else [])
        )
        safe_id = re.sub(r"[^a-z0-9]", "_", r.ioc.lower())[:32]

        if r.ioc_type == IOCType.IP:
            detection = (
                "detection:\n"
                "    selection:\n"
                f"        dst_ip|contains: '{r.ioc}'\n"
                "    condition: selection"
            )
            logsource = "logsource:\n    category: network_connection"
        else:
            detection = (
                "detection:\n"
                "    selection:\n"
                f"        dns_query|contains: '{r.ioc}'\n"
                "    condition: selection"
            )
            logsource = "logsource:\n    category: dns"

        rule = (
            f"title: Malicious IOC - {r.ioc}\n"
            f"id: ioc-{safe_id}\n"
            f"status: experimental\n"
            f"description: >\n"
            f"    Auto-generated from IOC checker. Verdict: {r.overall_verdict}.\n"
            f"    Threat context: {tags_cmt}\n"
            f"date: {today}\n"
            f"author: ioc-checker / VDI SOC\n"
            f"tags:\n"
            f"    - attack.defense_evasion\n"
            f"{mitre_yaml}\n"
            f"{logsource}\n"
            f"{detection}\n"
            f"falsepositives:\n"
            f"    - Verify against asset inventory before blocking\n"
            f"level: {'high' if r.overall_verdict == 'malicious' else 'medium'}\n"
            f"---\n"
        )
        lines.append(rule)

    return "\n".join(lines).encode("utf-8")


# ── YARA ──────────────────────────────────────────────────────────────────────

def results_to_yara(results: list[OsintResult]) -> bytes:
    """Generate YARA rules for malicious hash IOCs."""
    from utils.ioc_detector import IOCType

    hashes = [
        r for r in results
        if r.overall_verdict in ("malicious", "suspicious")
        and r.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)
    ]

    if not hashes:
        return b"// No malicious hash IOCs found for YARA rule generation."

    rules: list[str] = []
    today = str(datetime.date.today())

    for r in hashes:
        ctx      = r.threat_context
        desc     = ctx.tags_display if ctx else r.overall_verdict
        safe_n   = re.sub(r"[^A-Za-z0-9]", "_", r.ioc[:16])
        hash_field = r.ioc_type.value

        rule = (
            f"rule IOC_{safe_n} {{\n"
            f'    meta:\n'
            f'        description = "Malicious {hash_field.upper()} - {desc}"\n'
            f'        date        = "{today}"\n'
            f'        author      = "ioc-checker / VDI SOC"\n'
            f'        verdict     = "{r.overall_verdict}"\n'
            f'        hash        = "{r.ioc}"\n'
            f'    condition:\n'
            f'        {hash_field} == "{r.ioc}"\n'
            f'}}\n'
        )
        rules.append(rule)

    return "\n".join(rules).encode("utf-8")


# ── Internal helper ───────────────────────────────────────────────────────────

def _defang(ioc: str) -> str:
    ioc = re.sub(r"https?://", "hxxp://", ioc, flags=re.IGNORECASE)
    ioc = re.sub(r"\.", "[.]", ioc)
    ioc = ioc.replace("@", "[@]")
    return ioc
