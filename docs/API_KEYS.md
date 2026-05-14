# ShadowScope — API Keys Guide

Where to get each key, free-tier limits, and what ShadowScope uses it for. All keys go in `ioc_tool/.env` (copy from `ioc_tool/.env.example` first).

Missing keys are non-fatal — that source is skipped, the others still run.

## Core (recommended — covers ~90% of value)

### VirusTotal — `VT_API_KEY`
- **Signup**: https://www.virustotal.com/gui/join-us
- **Free tier**: 4 lookups/min, 500/day, 15.5k/month
- **Used for**: IP, domain, URL, hash reputation (multi-engine detection counts)
- **Scope**: required for any IOC type

### AbuseIPDB — `ABUSEIPDB_API_KEY`
- **Signup**: https://www.abuseipdb.com/register
- **Free tier**: 1,000 checks/day
- **Used for**: IP confidence score (0–100), report categories, ISP/usage type
- **Scope**: IP only

### Shodan — `SHODAN_API_KEY`
- **Signup**: https://account.shodan.io/register
- **Free tier**: limited; Membership ($49 one-time) recommended for production use
- **Used for**: open ports, banners, vulnerabilities, host tags (VPN/proxy/Tor)
- **Scope**: IP only

### GreyNoise — `GREYNOISE_API_KEY`
- **Signup**: https://www.greynoise.io/viz/signup
- **Free tier**: Community API — 50 lookups/day per key
- **Used for**: classifying IPs as internet background noise (mass scanners like Censys, Shodan, Project Sonar, Mirai) vs targeted activity. Major false-positive killer in SOC IP triage.
- **Scope**: IP only

## Free / freemium

### URLhaus (abuse.ch) — *no API key*
- **Signup**: none — public API at https://urlhaus-api.abuse.ch/
- **Free tier**: free, no rate limit beyond reasonable use (be polite)
- **Used for**: URL / domain / IP lookups against abuse.ch's community-maintained malicious-URL database (phishing, malware drops, C2 panels). Returns threat type, tags, payload metadata, and a `url_status` (online / offline).
- **Scope**: URL, domain, IP
- **Env var**: none required — module short-circuits on network errors and skips gracefully.

### ThreatFox (abuse.ch) — *no API key*
- **Signup**: none — public API at https://threatfox-api.abuse.ch/api/v1/
- **Free tier**: free, no rate limit beyond reasonable use (be polite)
- **Used for**: lookups against abuse.ch's fresh community-shared IOC feed (botnet C2, payload delivery, distribution hosts). Returns malware family, threat type, confidence level, and tags.
- **Scope**: IP, domain, URL, hash
- **Env var**: none required — module short-circuits on network errors and skips gracefully.

### MalwareBazaar (abuse.ch) — *no API key*
- **Signup**: none — public API at https://mb-api.abuse.ch/api/v1/
- **Free tier**: free, no rate limit beyond reasonable use (be polite)
- **Used for**: hash → sample metadata against abuse.ch's malware sample repository. Returns malware family (`signature`), file type / size / name, tags, first-seen, delivery method, and vendor intel cross-references.
- **Scope**: hash (md5 / sha1 / sha256)
- **Env var**: none required — module short-circuits on network errors and skips gracefully.

## Enrichment (location / fraud context)

### IPQualityScore — `IPQS_API_KEY`
- **Signup**: https://www.ipqualityscore.com/create-account
- **Free tier**: 5,000 IP queries/month
- **Used for**: fraud score (0–100), proxy/VPN/Tor detection, abuse velocity
- **Scope**: IP only

### IPinfo — `IPINFO_API_KEY`
- **Signup**: https://ipinfo.io/signup
- **Free tier**: 50k requests/month
- **Used for**: ASN, organization, country/city, hostname
- **Scope**: IP only

## Sandbox (file & URL detonation)

### FileScan.IO — `FILE_SCAN_IO`
- **Signup**: https://www.filescan.io/users/register
- **Free tier**: generous community tier (rate-limited)
- **Used for**: file + URL static/dynamic analysis with report links
- **Scope**: file, URL

### Hybrid Analysis — `HYBRID_ANALYSIS_API_KEY` *(optional)*
- **Signup**: https://www.hybrid-analysis.com/signup (Falcon Sandbox)
- **Free tier**: vetted community access
- **Used for**: automated malware analysis, behavioural reports
- **Scope**: file, hash

### Joe Sandbox Cloud — `JOE_SANDBOX_CLOUD_API_KEY` *(optional)*
- **Signup**: https://www.joesandbox.com/#contact (paid; trial available)
- **Used for**: deep malware analysis with detailed JSON/PDF reports
- **Scope**: file

## Quick setup

```bash
cp ioc_tool/.env.example ioc_tool/.env
nano ioc_tool/.env   # paste keys
```

Verify keys load:

```bash
python3 -m ioc_tool.main -1 8.8.8.8
```

Sources with missing keys log a warning and are skipped — final score averages whatever did return.
