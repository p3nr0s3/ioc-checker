"""
threat_context.py
=================
Threat context tagging and MITRE ATT&CK mapping derived from OSINT results.

Provides:
  - Threat tags  : C2, Phishing, Ransomware, TOR Exit Node, Botnet, etc.
  - MITRE TTPs   : mapped from verdict + multi-source context signals
  - Defang/refang: safe IOC sharing
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ── MITRE ATT&CK TTP catalogue ────────────────────────────────────────────────

MITRE_TTPS: dict[str, dict] = {
    "C2": {
        "id": "T1071", "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "Phishing": {
        "id": "T1566", "name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "Ransomware": {
        "id": "T1486", "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "Botnet": {
        "id": "T1584", "name": "Compromise Infrastructure",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1584/",
    },
    "Malware Distribution": {
        "id": "T1608", "name": "Stage Capabilities",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1608/",
    },
    "Credential Theft": {
        "id": "T1556", "name": "Modify Authentication Process",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1556/",
    },
    "TOR Exit Node": {
        "id": "T1090.003", "name": "Multi-hop Proxy",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1090/003/",
    },
    "Proxy / Anonymization": {
        "id": "T1090", "name": "Proxy",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1090/",
    },
    "Scanner": {
        "id": "T1595", "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "Spam": {
        "id": "T1566.002", "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "Exploit": {
        "id": "T1203", "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1203/",
    },
    "Brute-Force": {
        "id": "T1110", "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "SSH Brute-Force": {
        "id": "T1110.003", "name": "Password Spraying",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "DDoS": {
        "id": "T1498", "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "Web App Attack": {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "SQLi": {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "Cryptomining": {
        "id": "T1496", "name": "Resource Hijacking",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1496/",
    },
    "Data Exfiltration": {
        "id": "T1041", "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
}

# Keyword → threat tag (matched against OTX pulse names, VT categories, Shodan tags)
KEYWORD_TAG_MAP: dict[str, str] = {
    "c2":           "C2",
    "command":      "C2",
    "control":      "C2",
    "botnet":       "Botnet",
    "ransomware":   "Ransomware",
    "phish":        "Phishing",
    "phishing":     "Phishing",
    "spam":         "Spam",
    "malware":      "Malware Distribution",
    "trojan":       "Malware Distribution",
    "rat":          "Malware Distribution",
    "tor":          "TOR Exit Node",
    "exit node":    "TOR Exit Node",
    "proxy":        "Proxy / Anonymization",
    "vpn":          "VPN",
    "scanner":      "Scanner",
    "scan":         "Scanner",
    "brute-force":  "Brute-Force",
    "brute force":  "Brute-Force",
    "ssh":          "SSH Brute-Force",
    "credential":   "Credential Theft",
    "stealer":      "Credential Theft",
    "infostealer":  "Credential Theft",
    "exfil":        "Data Exfiltration",
    "exploit":      "Exploit",
    "ddos":         "DDoS",
    "sqli":         "SQLi",
    "injection":    "SQLi",
    "miner":        "Cryptomining",
    "crypto":       "Cryptomining",
    "web attack":   "Web App Attack",
    "hacking":      "Web App Attack",
}

# AbuseIPDB category ID → normalized threat tag
ABUSEIPDB_TO_TAG: dict[int, str] = {
    3:  "Fraud",        4:  "DDoS",
    5:  "Brute-Force",  7:  "Phishing",
    9:  "Proxy / Anonymization",
    10: "Spam",         11: "Spam",
    12: "Spam",         13: "VPN",
    14: "Scanner",      15: "Web App Attack",
    16: "SQLi",         17: "Spoofing",
    18: "Brute-Force",  19: "Scanner",
    20: "Malware Distribution",
    21: "Web App Attack",
    22: "SSH Brute-Force",
    23: "IoT Attack",
}


@dataclass
class ThreatContext:
    tags: list[str] = field(default_factory=list)
    mitre: list[dict] = field(default_factory=list)
    confidence: int = 0

    @property
    def mitre_ids(self) -> list[str]:
        return [t["id"] for t in self.mitre]

    @property
    def tags_display(self) -> str:
        return " · ".join(self.tags) if self.tags else "—"

    @property
    def mitre_summary(self) -> str:
        return " · ".join(f"{t['id']} {t['name']}" for t in self.mitre)


def derive_threat_context(
    verdict: str,
    sources: list,           # list[SourceResult] from osint_api
    shodan_tags: list[str] | None = None,
) -> ThreatContext:
    """
    Derive threat tags and MITRE TTPs from OSINT source results.

    Parameters
    ----------
    verdict      : overall verdict string
    sources      : list of SourceResult objects
    shodan_tags  : raw tags list from Shodan if available
    """
    ctx = ThreatContext()
    if verdict in ("clean", "unknown"):
        return ctx

    tags: set[str] = set()

    for sr in sources:
        if sr.verdict == "error":
            continue
        src = sr.source
        details = sr.details or {}

        # ── AbuseIPDB ────────────────────────────────────────────────
        if src == "AbuseIPDB":
            is_tor = details.get("is_tor", False)
            if is_tor:
                tags.add("TOR Exit Node")
            is_vpn = details.get("is_vpn", False)
            if is_vpn is True:
                tags.add("VPN")
            usage = str(details.get("usage_type", "")).lower()
            for kw, tag in KEYWORD_TAG_MAP.items():
                if kw in usage:
                    tags.add(tag)

        # ── OTX AlienVault ───────────────────────────────────────────
        elif src == "OTX AlienVault":
            for tag_str in details.get("top_tags", []):
                tl = str(tag_str).lower()
                for kw, tag in KEYWORD_TAG_MAP.items():
                    if kw in tl:
                        tags.add(tag)

        # ── VirusTotal ───────────────────────────────────────────────
        elif src == "VirusTotal":
            type_desc = str(details.get("type_description", "")).lower()
            meaningful = str(details.get("meaningful_name", "")).lower()
            for text in (type_desc, meaningful):
                for kw, tag in KEYWORD_TAG_MAP.items():
                    if kw in text:
                        tags.add(tag)

        # ── Shodan ───────────────────────────────────────────────────
        elif src == "Shodan":
            raw_tags = details.get("tags", [])
            for t in raw_tags:
                tl = str(t).lower()
                if "tor" in tl:
                    tags.add("TOR Exit Node")
                for kw, tag in KEYWORD_TAG_MAP.items():
                    if kw in tl:
                        tags.add(tag)
            # Shodan vulns → "Exploit" tag
            if details.get("vuln_count", 0) > 0:
                tags.add("Exploit")

        # ── URLScan ──────────────────────────────────────────────────
        elif src == "URLScan.io":
            for t in details.get("tags", []):
                tl = str(t).lower()
                for kw, tag in KEYWORD_TAG_MAP.items():
                    if kw in tl:
                        tags.add(tag)

    # ── Map tags → MITRE ─────────────────────────────────────────────
    seen_ids: set[str] = set()
    mitre_list = []
    for tag in sorted(tags):
        ttp = MITRE_TTPS.get(tag)
        if ttp and ttp["id"] not in seen_ids:
            seen_ids.add(ttp["id"])
            mitre_list.append(ttp)

    ctx.tags = sorted(tags)
    ctx.mitre = mitre_list
    ctx.confidence = min(20 + len(tags) * 12, 100)
    return ctx


# ── Defang / Refang ───────────────────────────────────────────────────────────

def defang(ioc: str) -> str:
    """Defang an IOC for safe sharing in emails, chat, reports."""
    ioc = re.sub(r"https?://", "hxxp://", ioc, flags=re.IGNORECASE)
    ioc = re.sub(r"\.", "[.]", ioc)
    ioc = ioc.replace("@", "[@]")
    return ioc


def refang(ioc: str) -> str:
    """Reverse defanging."""
    ioc = ioc.replace("[.]", ".").replace("[dot]", ".")
    ioc = re.sub(r"hxxps?://", "https://", ioc, flags=re.IGNORECASE)
    ioc = ioc.replace("[@]", "@")
    return ioc
