# ⬡ IOC Intelligence — Streamlit Threat Checker

Multi-source IOC (Indicator of Compromise) lookup app built for Streamlit Cloud.  
Checks IPs, domains, URLs, file hashes, and emails against 5 OSINT APIs concurrently.

---

## Features

| Feature | Detail |
|---|---|
| **IOC types** | IPv4, Domain, URL, MD5, SHA1, SHA256, Email |
| **Single check** | Paste one IOC, auto-detects type, runs all APIs |
| **Bulk check** | Newline or CSV input, progress bar, per-type routing |
| **History tab** | Filter + sort, summary metrics, export to JSON/CSV |
| **5 OSINT APIs** | VirusTotal · AbuseIPDB · Shodan · OTX · URLScan.io |
| **Dark material UI** | Custom tint colour, JetBrains Mono + Rajdhani fonts |
| **Tint picker** | Live colour picker in sidebar; persist via Secrets |

---

## Deploy to Streamlit Cloud

### 1. Fork / push this repo to GitHub

```
ioc-checker/
├── app.py
├── requirements.txt
├── .streamlit/
│   ├── config.toml
│   └── secrets.toml.example    ← DO NOT commit secrets.toml
├── utils/
│   ├── ioc_detector.py
│   ├── osint_api.py
│   ├── export.py
│   └── theme.py
└── components/
    └── result_card.py
```

### 2. Create a new app on [share.streamlit.io](https://share.streamlit.io)

- **Repository**: your forked repo  
- **Branch**: `main`  
- **Main file path**: `app.py`

### 3. Add secrets

Go to **App → Settings → Secrets** and paste:

```toml
[api_keys]
virustotal = "YOUR_VT_KEY"
abuseipdb  = "YOUR_ABUSEIPDB_KEY"
shodan     = "YOUR_SHODAN_KEY"
otx        = "YOUR_OTX_KEY"
urlscan    = "YOUR_URLSCAN_KEY"

[theme]
tint = "#00D4FF"   # Any hex colour
```

You can omit any key — that source will be skipped silently.

---

## API Key Sources

| Service | Free tier | Get key |
|---|---|---|
| VirusTotal | 4 req/min · 500/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | 1,000/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| Shodan | 100 req/month (free) | [account.shodan.io](https://account.shodan.io/) |
| OTX AlienVault | Unlimited read | [otx.alienvault.com](https://otx.alienvault.com/api) |
| URLScan.io | 1,000 req/day | [urlscan.io](https://urlscan.io/user/signup) |

---

## Local development

```bash
cd ioc-checker
pip install -r requirements.txt

# Create secrets
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit secrets.toml with your keys

streamlit run app.py
```

---

## IOC Type Detection Logic

| Pattern | Detected as |
|---|---|
| 32-char hex | MD5 |
| 40-char hex | SHA1 |
| 64-char hex | SHA256 |
| `user@domain.tld` | Email |
| `x.x.x.x` (valid octets) | IPv4 |
| `https?://…` | URL |
| `domain.tld` | Domain |

---

## Verdict Scale

| Verdict | Condition |
|---|---|
| 🔴 **Malicious** | ≥1 source flags as malicious |
| 🟡 **Suspicious** | ≥1 source flags as suspicious, none malicious |
| 🟢 **Clean** | All queried sources return clean |
| ⚪ **Unknown** | No data found or all sources errored |
