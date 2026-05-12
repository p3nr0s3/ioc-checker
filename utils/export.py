"""
Export helpers: convert OsintResult list → CSV / JSON bytes.
"""
from __future__ import annotations

import csv
import io
import json
import time
from typing import Any

from utils.osint_api import OsintResult


def results_to_json(results: list[OsintResult]) -> bytes:
    """Serialise results list to pretty-printed JSON bytes."""

    def _serialise(r: OsintResult) -> dict[str, Any]:
        return {
            "ioc":             r.ioc,
            "ioc_type":        r.ioc_type.value,
            "overall_verdict": r.overall_verdict,
            "malicious_sources": r.malicious_count,
            "checked_at":      time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at)
            ),
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


def results_to_csv(results: list[OsintResult]) -> bytes:
    """Flatten results list to CSV bytes (one row per IOC × source)."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    headers = [
        "ioc", "ioc_type", "overall_verdict",
        "source", "source_verdict", "score", "report_url", "error", "checked_at",
    ]
    writer.writerow(headers)

    for r in results:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.checked_at))
        if r.sources:
            for s in r.sources:
                writer.writerow([
                    r.ioc, r.ioc_type.value, r.overall_verdict,
                    s.source, s.verdict, s.score or "", s.url or "", s.error or "", ts,
                ])
        else:
            writer.writerow([
                r.ioc, r.ioc_type.value, r.overall_verdict,
                "", "", "", "", "", ts,
            ])

    return buf.getvalue().encode("utf-8")
