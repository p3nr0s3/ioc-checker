"""
Export helpers — detailed per-source output for CSV and JSON.

CSV layout:
  One row per IOC.
  Shared columns: ioc, ioc_type, overall_verdict, malicious_sources,
                  sources_queried, checked_at.
  Then per-source block (5 sources × ~8 cols each):
    {source}_verdict, {source}_score, {source}_report_url,
    + source-specific detail fields.

JSON layout:
  One object per IOC with full nested detail per source.
"""
from __future__ import annotations

import csv
import io
import json
import time
from typing import Any

from utils.osint_api import OsintResult, SourceResult

# ── Source ordering for consistent column layout ──────────────────────────────
SOURCE_ORDER = ["VirusTotal", "AbuseIPDB", "Shodan", "OTX AlienVault", "URLScan.io"]

# Fields to extract per source (in display order).
# Values are (detail_key, column_suffix) pairs.
SOURCE_DETAIL_FIELDS: dict[str, list[tuple[str, str]]] = {
    "VirusTotal": [
        ("malicious",       "engines_malicious"),
        ("suspicious",      "engines_suspicious"),
        ("undetected",      "engines_undetected"),
        ("total_engines",   "engines_total"),
        ("country",         "country"),
        ("asn",             "asn"),
        ("as_owner",        "as_owner"),
        ("meaningful_name", "file_name"),
        ("type_description","file_type"),
        ("size",            "file_size_bytes"),
    ],
    "AbuseIPDB": [
        ("confidence_score","confidence_pct"),
        ("total_reports",   "total_reports"),
        ("country",         "country"),
        ("isp",             "isp"),
        ("domain",          "domain"),
        ("usage_type",      "usage_type"),
        ("is_tor",          "is_tor"),
        ("is_vpn",          "is_vpn"),
    ],
    "Shodan": [
        ("org",             "org"),
        ("isp",             "isp"),
        ("country",         "country"),
        ("os",              "os"),
        ("port_count",      "open_port_count"),
        ("open_ports",      "open_ports"),
        ("vuln_count",      "cve_count"),
        ("vulns",           "cves"),
        ("tags",            "tags"),
        ("hostnames",       "hostnames"),
    ],
    "OTX AlienVault": [
        ("pulse_count",     "pulse_count"),
        ("reputation",      "reputation"),
        ("country",         "country"),
        ("top_tags",        "tags"),
    ],
    "URLScan.io": [
        ("total_scans",     "total_scans"),
        ("malicious_scans", "malicious_scans"),
        ("latest_country",  "latest_country"),
        ("latest_server",   "latest_server"),
        ("latest_ip",       "latest_ip"),
        ("tags",            "verdict_tags"),
    ],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(val: Any) -> str:
    """Flatten a value to a clean string for CSV."""
    if val is None or val == "" or val == "—":
        return ""
    if isinstance(val, list):
        return "; ".join(str(x) for x in val) if val else ""
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)


def _src_map(result: OsintResult) -> dict[str, SourceResult]:
    return {s.source: s for s in result.sources}


# ── JSON export ───────────────────────────────────────────────────────────────

def _serialise_source(s: SourceResult) -> dict[str, Any]:
    """Full source serialisation with all available detail fields."""
    base: dict[str, Any] = {
        "verdict":    s.verdict,
        "score":      s.score,
        "report_url": s.url,
        "error":      s.error,
    }

    if s.source in SOURCE_DETAIL_FIELDS:
        for detail_key, col_suffix in SOURCE_DETAIL_FIELDS[s.source]:
            val = s.details.get(detail_key)
            if val is not None and val != "—":
                base[col_suffix] = val

    # Include any extra detail fields not in the predefined list
    predefined_keys = {dk for dk, _ in SOURCE_DETAIL_FIELDS.get(s.source, [])}
    for k, v in s.details.items():
        if k not in predefined_keys and v not in (None, "", "—"):
            base[k] = v

    return base


def results_to_json(results: list[OsintResult]) -> bytes:
    """Serialise results to verbose JSON — full detail per IOC per source."""

    def _serialise(r: OsintResult) -> dict[str, Any]:
        sm = _src_map(r)
        sources_out: dict[str, Any] = {}
        for sname in SOURCE_ORDER:
            if sname in sm:
                sources_out[sname] = _serialise_source(sm[sname])

        return {
            "ioc":              r.ioc,
            "ioc_type":         r.ioc_type.value,
            "overall_verdict":  r.overall_verdict,
            "malicious_sources": r.malicious_count,
            "sources_queried":  r.source_count,
            "checked_at":       time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at)
            ),
            "sources": sources_out,
        }

    return json.dumps(
        [_serialise(r) for r in results],
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")


# ── CSV export ────────────────────────────────────────────────────────────────

def _build_csv_headers() -> list[str]:
    """Build the full flat header list."""
    shared = [
        "ioc", "ioc_type", "overall_verdict",
        "malicious_sources", "sources_queried", "checked_at",
    ]
    per_source: list[str] = []
    for sname in SOURCE_ORDER:
        prefix = sname.lower().replace(" ", "_").replace(".", "")
        per_source += [
            f"{prefix}_verdict",
            f"{prefix}_score",
            f"{prefix}_report_url",
            f"{prefix}_error",
        ]
        for _, col_suffix in SOURCE_DETAIL_FIELDS.get(sname, []):
            per_source.append(f"{prefix}_{col_suffix}")

    return shared + per_source


def results_to_csv(results: list[OsintResult]) -> bytes:
    """
    Flat CSV — one row per IOC, one column block per source.
    Each source gets: verdict, score, report_url, error + all detail fields.
    """
    buf     = io.StringIO()
    headers = _build_csv_headers()
    writer  = csv.DictWriter(buf, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()

    for r in results:
        ts   = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at))
        sm   = _src_map(r)
        row: dict[str, str] = {
            "ioc":              r.ioc,
            "ioc_type":         r.ioc_type.value,
            "overall_verdict":  r.overall_verdict,
            "malicious_sources": str(r.malicious_count),
            "sources_queried":  str(r.source_count),
            "checked_at":       ts,
        }

        for sname in SOURCE_ORDER:
            prefix = sname.lower().replace(" ", "_").replace(".", "")
            if sname not in sm:
                continue
            s = sm[sname]
            row[f"{prefix}_verdict"]    = s.verdict
            row[f"{prefix}_score"]      = _fmt(s.score)
            row[f"{prefix}_report_url"] = s.url or ""
            row[f"{prefix}_error"]      = s.error or ""

            for detail_key, col_suffix in SOURCE_DETAIL_FIELDS.get(sname, []):
                val = s.details.get(detail_key)
                row[f"{prefix}_{col_suffix}"] = _fmt(val)

        writer.writerow(row)

    return buf.getvalue().encode("utf-8")


# ── Summary CSV (condensed, one row per IOC × source) ────────────────────────

def results_to_csv_summary(results: list[OsintResult]) -> bytes:
    """
    Alternative condensed export: one row per IOC × source combination.
    Useful for pivot table analysis.
    """
    buf     = io.StringIO()
    headers = [
        "ioc", "ioc_type", "overall_verdict", "checked_at",
        "source", "source_verdict", "score", "report_url", "error",
        "detail_key", "detail_value",
    ]
    writer = csv.writer(buf)
    writer.writerow(headers)

    for r in results:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at))
        for s in r.sources:
            # One row per source with all details collapsed to key=value pairs
            detail_str = " | ".join(
                f"{k}={_fmt(v)}" for k, v in s.details.items()
                if v not in (None, "", "—", [])
            )
            writer.writerow([
                r.ioc, r.ioc_type.value, r.overall_verdict, ts,
                s.source, s.verdict,
                _fmt(s.score), s.url or "", s.error or "",
                "", detail_str,
            ])

    return buf.getvalue().encode("utf-8")
