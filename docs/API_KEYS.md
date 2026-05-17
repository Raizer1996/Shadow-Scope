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

### Censys — `CENSYS_API_KEY`
- **Signup**: https://accounts.censys.io/register → after login, create a Personal Access Token at https://platform.censys.io/settings/access-tokens
- **Free tier**: 500 queries/month (Personal Access Token, Censys Platform v3)
- **Used for**: deeper service banners, software fingerprints (vendor/product/version), OS detection, BGP prefix, full reverse-DNS list. Complements Shodan with a second-opinion port inventory and richer software identification.
- **Scope**: IP only
- **Endpoint**: `https://api.platform.censys.io/v3/global/asset/host/{ip}` (Bearer PAT auth)

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

### Mnemonic Passive DNS — *no API key*
- **Signup**: none for low-volume queries; commercial tier available at https://www.mnemonic.io/resources/blog/introducing-passivedns/
- **Docs**: https://docs.mnemonic.io/display/public/API/PassiveDNS+Search+API
- **Free tier**: anonymous, gentle rate (ShadowScope self-caps at 5 req/min via the `pdns` bucket in `core/ratelimit.py`).
- **Used for**: passive DNS first-seen / last-seen / record-count on IP IOCs. Info-only — surfaces context (brand-new infrastructure vs. long-lived backbone) but does NOT push the composite score.
- **Scope**: IP only (v1; Mnemonic also indexes domains — domain support deferred to keep the v1 scope tight)
- **Env var**: none required.
- **CIRCL (secondary path, optional)**: a future expansion may route through CIRCL Passive DNS when `CIRCL_USERNAME` / `CIRCL_PASSWORD` are set. The env-var placeholders ship commented out in `ioc_tool/.env.example`; the v1 module only implements the Mnemonic path.

### CVE enrichment — *no API keys required*

ShadowScope's CVE pipeline pulls from three free, public sources. All three fire in parallel when an IOC matches the `CVE-YYYY-NNNN` shape.

- **NVD (NIST National Vulnerability Database)** — *no API key*
  - **Signup**: none — public API at https://services.nvd.nist.gov/rest/json/cves/2.0
  - **Free tier**: public endpoint, low-volume use is unauthenticated. An optional `apiKey` header bumps the rate limit; we don't wire one in but the plumbing is trivial (set `NVD_API_KEY` and pass it as a header in `ioc_tool/modules/nvd.py`).
  - **Used for**: canonical CVE metadata — CVSS v3.1 base score + severity, descriptions, configurations, references.
  - **Scope**: CVE.

- **EPSS (Exploit Prediction Scoring System, FIRST.org)** — *no API key*
  - **Signup**: none — public API at https://api.first.org/data/v1/epss
  - **Free tier**: free, no documented rate limit.
  - **Used for**: probability (0.0–1.0) a CVE will be exploited in the wild over the next 30 days, plus percentile rank against all CVEs.
  - **Scope**: CVE.

- **CISA KEV (Known Exploited Vulnerabilities catalog)** — *no API key*
  - **Signup**: none — JSON catalog at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - **Free tier**: free.
  - **Used for**: membership test against CISA's catalog of CVEs known to be actively exploited. Hit surfaces `vendorProject`, `product`, `dateAdded`, `dueDate`, and the `knownRansomwareCampaignUse` flag.
  - **Caching**: the full catalog is downloaded once and persisted at `ioc_tool/data/cisa_kev.json` (gitignored); refreshed when missing or older than 24 h. On network failure during refresh the previously-cached copy is used as a fallback.
  - **Scope**: CVE.

## Enrichment (location / fraud context)

### URLscan.io — `URLSCAN_API_KEY` *(optional but recommended)*
- **Signup**: https://urlscan.io/user/signup
- **Free tier**: 100 unauthenticated + 200 authenticated scans/day; search API allowance is generous in practice
- **Used for**: historical URL-scan search — finds known malicious URLs + screenshots + sibling domains. Each result links to the full URLscan report (HTTP transaction tree, screenshot, certificates, page content) so analysts can click through for phishing triage. ShadowScope uses the **search** API only (read-only / historical) — submitting fresh scans takes 10+ seconds and is out of scope here.
- **Scope**: IP, domain, URL (hash is unsupported — URLscan indexes URLs, not files)
- **Env var**: `URLSCAN_API_KEY` is optional; missing key still works at the lower anon quota.

### AlienVault OTX — `OTX_API_KEY`
- **Signup**: https://otx.alienvault.com/
- **Free tier**: generous — no documented daily quota (be polite)
- **Used for**: community pulse / threat-actor reports. Each OTX **pulse** bundles a campaign or family with the IOCs that identify it, plus tags, references, and (sometimes) a named adversary. A hit with many pulses signals a widely-reported threat; an IOC with negative `reputation` is a community-flagged bad actor.
- **Scope**: IP, domain, URL, hash

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
