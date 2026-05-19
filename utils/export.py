"""
Export helpers — IOC-type-aware, per-source column blocks.
CSV (wide): one row per IOC, columns grouped by source.
CSV (long): one row per IOC × source — pivot-friendly.
JSON: full verbose nested output.
"""
from __future__ import annotations

import csv
import io
import json
import time
from typing import Any

from utils.osint_api import OsintResult, SourceResult
from utils.ioc_detector import IOCType

SOURCE_ORDER = ["VirusTotal", "AbuseIPDB", "Shodan", "OTX AlienVault", "URLScan.io"]

# ── Per-source, per-IOC-type detail field mapping ─────────────────────────────
# Structure: source → { ioc_type (or "all") → [(detail_key, csv_column_suffix)] }
# "all" means the field appears for every IOC type that source supports.

_VT_ENGINE_COLS = [
    ("engines_malicious",  "engines_malicious"),
    ("engines_suspicious", "engines_suspicious"),
    ("engines_harmless",   "engines_harmless"),
    ("engines_undetected", "engines_undetected"),
    ("engines_total",      "engines_total"),
]


def _vt_hash_cols() -> list[tuple[str, str]]:
    return [
        ("file_name",           "file_name"),
        ("file_type",           "file_type"),
        ("file_extension",      "file_extension"),
        ("file_size_bytes",     "file_size_bytes"),
        ("md5",                 "md5"),
        ("sha1",                "sha1"),
        ("sha256",              "sha256"),
        ("ssdeep",              "ssdeep"),
        ("magic",               "magic"),
        ("first_seen",          "first_seen"),
        ("last_seen",           "last_seen"),
        ("times_submitted",     "times_submitted"),
        ("unique_sources",      "unique_sources"),
        ("popular_threat_name", "popular_threat_name"),
        ("signature_product",   "signature_product"),
        ("signature_verified",  "signature_verified"),
        ("tags",                "tags"),
    ]



def _otx_hash_cols() -> list[tuple[str, str]]:
    return [
        ("md5",       "md5"),
        ("sha1",      "sha1"),
        ("sha256",    "sha256"),
        ("file_type", "file_type"),
        ("file_size", "file_size"),
    ]


SOURCE_FIELDS: dict[str, dict[str, list[tuple[str, str]]]] = {
    "VirusTotal": {
        "all": _VT_ENGINE_COLS + [("reputation", "reputation")],
        IOCType.IP: [
            ("country",          "country"),
            ("continent",        "continent"),
            ("asn",              "asn"),
            ("as_owner",         "as_owner"),
            ("network",          "network"),
            ("regional_internet_registry", "rir"),
            ("last_https_cert_issuer", "https_cert_issuer"),
            ("last_analysis_date",     "last_analysis_date"),
            ("total_votes_harmless",   "votes_harmless"),
            ("total_votes_malicious",  "votes_malicious"),
        ],
        IOCType.DOMAIN: [
            ("registrar",        "registrar"),
            ("creation_date",    "creation_date"),
            ("last_update_date", "last_update_date"),
            ("last_dns_records", "dns_records"),
            ("categories",       "categories"),
            ("country",          "country"),
            ("whois",            "whois_snippet"),
            ("last_analysis_date", "last_analysis_date"),
            ("total_votes_harmless",  "votes_harmless"),
            ("total_votes_malicious", "votes_malicious"),
        ],
        IOCType.URL: [
            ("final_url",        "final_url"),
            ("title",            "page_title"),
            ("last_http_response_code", "http_status"),
            ("last_http_response_content_type", "content_type"),
            ("server",           "server"),
            ("categories",       "categories"),
            ("first_submission", "first_submission"),
            ("last_analysis_date", "last_analysis_date"),
            ("times_submitted",  "times_submitted"),
        ],
        IOCType.MD5:    _vt_hash_cols(),
        IOCType.SHA1:   _vt_hash_cols(),
        IOCType.SHA256: _vt_hash_cols(),
    },
    "AbuseIPDB": {
        "all": [],   # IP-only source; all fields under IOCType.IP
        IOCType.IP: [
            ("ip_address",         "ip_address"),
            ("ip_version",         "ip_version"),
            ("is_public",          "is_public"),
            ("country_code",       "country_code"),
            ("country_name",       "country_name"),
            ("isp",                "isp"),
            ("domain",             "domain"),
            ("hostnames",          "hostnames"),
            ("usage_type",         "usage_type"),
            ("asn",                "asn"),
            ("is_tor",             "is_tor"),
            ("is_vpn",             "is_vpn"),
            ("is_whitelisted",     "is_whitelisted"),
            ("confidence_score",   "confidence_score"),
            ("total_reports",      "total_reports"),
            ("num_distinct_users", "distinct_reporters"),
            ("last_reported_at",   "last_reported_at"),
            ("abuse_categories",   "abuse_categories"),
            ("last_reporter_cc",   "last_reporter_country"),
            ("last_comment",       "last_report_comment"),
        ],
    },
    "Shodan": {
        "all": [],
        IOCType.IP: [
            ("country_name",   "country_name"),
            ("country_code",   "country_code"),
            ("city",           "city"),
            ("region_code",    "region_code"),
            ("latitude",       "latitude"),
            ("longitude",      "longitude"),
            ("org",            "org"),
            ("isp",            "isp"),
            ("asn",            "asn"),
            ("hostnames",      "hostnames"),
            ("domains",        "domains"),
            ("os",             "os"),
            ("last_update",    "last_update"),
            ("open_port_count","open_port_count"),
            ("open_ports",     "open_ports"),
            ("services",       "services"),
            ("tags",           "tags"),
            ("threat_tags",    "threat_tags"),
            ("vuln_count",     "vuln_count"),
            ("cves",           "cves"),
            ("critical_cves",  "critical_cves"),
            ("high_cves",      "high_cves"),
        ],
    },
    "OTX AlienVault": {
        "all": [
            ("pulse_count",       "pulse_count"),
            ("reputation",        "reputation"),
            ("top_pulse_names",   "top_pulse_names"),
            ("pulse_authors",     "pulse_authors"),
            ("malware_families",  "malware_families"),
            ("attack_ids",        "attack_ids"),
            ("tags",              "tags"),
        ],
        IOCType.IP: [
            ("country_name", "country_name"),
            ("country_code", "country_code"),
            ("asn",          "asn"),
            ("city",         "city"),
            ("latitude",     "latitude"),
            ("longitude",    "longitude"),
        ],
        IOCType.DOMAIN: [
            ("alexa",  "alexa_rank"),
            ("whois",  "whois_snippet"),
        ],
        IOCType.MD5:    _otx_hash_cols(),
        IOCType.SHA1:   _otx_hash_cols(),
        IOCType.SHA256: _otx_hash_cols(),
    },
    "URLScan.io": {
        "all": [
            ("total_scans",       "total_scans"),
            ("malicious_scans",   "malicious_scans"),
            ("page_url",          "page_url"),
            ("page_domain",       "page_domain"),
            ("page_ip",           "page_ip"),
            ("page_country",      "page_country"),
            ("page_server",       "page_server"),
            ("page_mime_type",    "page_mime_type"),
            ("page_status_code",  "page_status_code"),
            ("page_title",        "page_title"),
            ("requests_total",    "requests_total"),
            ("requests_malicious","requests_malicious"),
            ("unique_domains",    "unique_domains"),
            ("unique_ips",        "unique_ips"),
            ("asnname",           "asn_name"),
            ("verdict_tags",      "verdict_tags"),
            ("categories",        "categories"),
        ],
    },
}




def _get_fields_for(source: str, ioc_type: IOCType) -> list[tuple[str, str]]:
    """Return ordered list of (detail_key, col_suffix) for a source + IOC type combo."""
    src_map = SOURCE_FIELDS.get(source, {})
    base    = src_map.get("all", [])
    specific = src_map.get(ioc_type, [])
    return base + specific


def _src_prefix(source: str) -> str:
    return source.lower().replace(" ", "_").replace(".", "")


def _fmt(val: Any) -> str:
    if val is None or val == "" or val == "—":
        return ""
    if isinstance(val, list):
        return "; ".join(str(x) for x in val) if val else ""
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)


# ── CSV wide ──────────────────────────────────────────────────────────────────

def _build_headers(ioc_type: IOCType) -> list[str]:
    shared = [
        "ioc", "ioc_type", "overall_verdict",
        "malicious_sources", "sources_queried", "checked_at",
    ]
    per_source: list[str] = []
    for sname in SOURCE_ORDER:
        pfx = _src_prefix(sname)
        per_source += [
            f"{pfx}_verdict",
            f"{pfx}_score",
            f"{pfx}_report_url",
            f"{pfx}_error",
        ]
        for _, col in _get_fields_for(sname, ioc_type):
            per_source.append(f"{pfx}_{col}")
    return shared + per_source


def results_to_csv(results: list[OsintResult]) -> bytes:
    """Wide CSV — one row per IOC, per-source column blocks (type-aware)."""
    if not results:
        return b""

    # Use the IOC type of first result to drive headers (bulk is usually uniform)
    # For mixed-type batches we use a superset of all types
    ioc_types = list({r.ioc_type for r in results})
    primary_type = ioc_types[0] if len(ioc_types) == 1 else IOCType.IP

    # Build superset headers across all IOC types present
    all_headers: list[str] = [
        "ioc", "ioc_type", "overall_verdict",
        "malicious_sources", "sources_queried", "checked_at",
    ]
    seen_cols: set[str] = set(all_headers)
    for itype in ioc_types:
        for sname in SOURCE_ORDER:
            pfx = _src_prefix(sname)
            for col in [f"{pfx}_verdict", f"{pfx}_score",
                        f"{pfx}_report_url", f"{pfx}_error"]:
                if col not in seen_cols:
                    all_headers.append(col)
                    seen_cols.add(col)
            for _, col_suffix in _get_fields_for(sname, itype):
                col = f"{pfx}_{col_suffix}"
                if col not in seen_cols:
                    all_headers.append(col)
                    seen_cols.add(col)

    buf    = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=all_headers, extrasaction="ignore")
    writer.writeheader()

    for r in results:
        ts  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at))
        sm  = {s.source: s for s in r.sources}
        row: dict[str, str] = {
            "ioc":              r.ioc,
            "ioc_type":         r.ioc_type.value,
            "overall_verdict":  r.overall_verdict,
            "malicious_sources": str(r.malicious_count),
            "sources_queried":  str(r.source_count),
            "checked_at":       ts,
        }

        for sname in SOURCE_ORDER:
            pfx = _src_prefix(sname)
            if sname not in sm:
                continue
            s = sm[sname]
            row[f"{pfx}_verdict"]    = s.verdict
            row[f"{pfx}_score"]      = _fmt(s.score)
            row[f"{pfx}_report_url"] = s.url or ""
            row[f"{pfx}_error"]      = s.error or ""
            for detail_key, col_suffix in _get_fields_for(sname, r.ioc_type):
                row[f"{pfx}_{col_suffix}"] = _fmt(s.details.get(detail_key))

        writer.writerow(row)

    return buf.getvalue().encode("utf-8")


# ── CSV long (pivot-friendly) ─────────────────────────────────────────────────

def results_to_csv_summary(results: list[OsintResult]) -> bytes:
    """Long CSV — one row per IOC × source, all details as key=value string."""
    buf     = io.StringIO()
    headers = [
        "ioc", "ioc_type", "overall_verdict", "checked_at",
        "source", "verdict", "score", "report_url", "error", "details",
    ]
    writer = csv.writer(buf)
    writer.writerow(headers)

    for r in results:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at))
        for s in r.sources:
            detail_str = " | ".join(
                f"{k}={_fmt(v)}"
                for k, v in s.details.items()
                if v not in (None, "", "—", [], {})
            )
            writer.writerow([
                r.ioc, r.ioc_type.value, r.overall_verdict, ts,
                s.source, s.verdict,
                _fmt(s.score), s.url or "", s.error or "",
                detail_str,
            ])

    return buf.getvalue().encode("utf-8")


# ── JSON ──────────────────────────────────────────────────────────────────────

def results_to_json(results: list[OsintResult]) -> bytes:
    """Verbose JSON — full nested per-source detail."""

    def _src(s: SourceResult) -> dict[str, Any]:
        return {
            "verdict":    s.verdict,
            "score":      s.score,
            "report_url": s.url,
            "error":      s.error,
            "details":    {k: v for k, v in s.details.items()
                           if v not in (None, "", "—", [], {})},
        }

    output = []
    for r in results:
        sm = {s.source: s for s in r.sources}
        output.append({
            "ioc":               r.ioc,
            "ioc_type":          r.ioc_type.value,
            "overall_verdict":   r.overall_verdict,
            "malicious_sources": r.malicious_count,
            "sources_queried":   r.source_count,
            "checked_at":        time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at)
            ),
            "sources": {sname: _src(sm[sname]) for sname in SOURCE_ORDER
                        if sname in sm},
        })

    return json.dumps(output, indent=2, ensure_ascii=False).encode("utf-8")
