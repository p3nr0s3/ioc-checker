"""
IOC type detection and validation utilities.
"""
import re
from enum import Enum


class IOCType(str, Enum):
    IP       = "ip"
    DOMAIN   = "domain"
    URL      = "url"
    MD5      = "md5"
    SHA1     = "sha1"
    SHA256   = "sha256"
    EMAIL    = "email"
    UNKNOWN  = "unknown"


# ── Regex patterns ────────────────────────────────────────────────────────────
_RE_IPV4    = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_RE_MD5     = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1    = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256  = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_EMAIL   = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_URL     = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN  = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)


def detect_ioc_type(value: str) -> IOCType:
    """Detect the type of an IOC string.

    Args:
        value: Raw IOC string (stripped).

    Returns:
        IOCType enum value.
    """
    v = value.strip()

    if _RE_MD5.match(v):
        return IOCType.MD5
    if _RE_SHA1.match(v):
        return IOCType.SHA1
    if _RE_SHA256.match(v):
        return IOCType.SHA256
    if _RE_EMAIL.match(v):
        return IOCType.EMAIL
    if _RE_IPV4.match(v):
        octets = [int(x) for x in v.split(".")]
        if all(0 <= o <= 255 for o in octets):
            return IOCType.IP
    if _RE_URL.match(v):
        return IOCType.URL
    if _RE_DOMAIN.match(v):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def parse_bulk_input(raw: str) -> list[str]:
    """Parse bulk IOC input — newline or comma separated, deduplicated.

    Args:
        raw: Raw multiline / comma-separated string from textarea.

    Returns:
        Deduplicated list of non-empty IOC strings.
    """
    items: list[str] = []
    for line in raw.splitlines():
        for part in line.split(","):
            cleaned = part.strip()
            if cleaned:
                items.append(cleaned)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


IOC_TYPE_LABELS: dict[IOCType, str] = {
    IOCType.IP:      "🌐 IPv4",
    IOCType.DOMAIN:  "🔗 Domain",
    IOCType.URL:     "🔗 URL",
    IOCType.MD5:     "#️⃣ MD5",
    IOCType.SHA1:    "#️⃣ SHA1",
    IOCType.SHA256:  "#️⃣ SHA256",
    IOCType.EMAIL:   "✉️ Email",
    IOCType.UNKNOWN: "❓ Unknown",
}


def parse_bulk_csv(file_bytes: bytes) -> list[str]:
    """Parse uploaded CSV/TXT file into a deduplicated list of IOC strings.

    Accepts:
      - Plain text files: one IOC per line
      - CSV files: scans every cell of every row for valid IOC patterns
        (handles exports from SentinelOne, Wazuh, SIEM tools, etc.)

    Args:
        file_bytes: Raw bytes from st.file_uploader read()

    Returns:
        Deduplicated list of non-empty candidate IOC strings.
    """
    import io as _io
    import csv as _csv

    text = file_bytes.decode("utf-8", errors="replace")
    candidates: list[str] = []

    # Try CSV parsing first
    try:
        reader = _csv.reader(_io.StringIO(text))
        for row in reader:
            for cell in row:
                cleaned = cell.strip().strip('"').strip("'")
                if cleaned:
                    candidates.append(cleaned)
    except Exception:
        # Fallback: plain line-by-line
        for line in text.splitlines():
            for part in line.split(","):
                cleaned = part.strip()
                if cleaned:
                    candidates.append(cleaned)

    # Deduplicate and filter to recognised IOC types only
    seen: set[str] = set()
    unique: list[str] = []
    for item in candidates:
        if item in seen:
            continue
        seen.add(item)
        if detect_ioc_type(item) != IOCType.UNKNOWN:
            unique.append(item)

    return unique
