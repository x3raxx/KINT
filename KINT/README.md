# 🔍 KINT (No-API Version) - Open Threat Intelligence CLI Tool

This version of **KINT** works without any API keys and provides essential threat intelligence data using open sources and public methods (scraping, Linux commands).

## ✅ Features

- CVE Lookup (Title, Description, Severity, Dates) from NVD Website
- IP WHOIS & Geolocation (via `whois` command & ipinfo.io)
- Domain WHOIS Info
- CSV/JSON Export
- Terminal UI via `rich`
- No API keys required

## ⚙️ Usage

```bash
kint --cve CVE-2023-12345
kint --ip 8.8.8.8
kint --domain example.com
```

## 🛠️ Setup

```bash
pip install -e .
```

Enjoy using KINT  🎯
