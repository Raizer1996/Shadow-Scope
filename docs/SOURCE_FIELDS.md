# Source Fields Audit

Field-by-field inventory of every enrichment source: what it returns, what the UI surfaces today, what the v1.1 derivation layer should surface.

Generated 2026-05-16 by running the test corpus (see `audit/` directory for raw JSON snapshots).

## Test corpus

| Type   | Value                                                                                       |
|--------|---------------------------------------------------------------------------------------------|
| IP     | `76.11.71.130` (residential baseline)                                                       |
| IP     | `185.220.101.45` (TOR exit `tor-exit-45.for-privacy.net`)                                   |
| Hash   | `635d1e58cca091f0515f69e78be4cef6ed549cead6a6e0ed6c6e369130b186e1`                          |
| Hash   | `f57e6ebd87ae42ddefe2b161fd7b02e1f5bc1d3b3d8b5d8cf8d03b14ffec829f`                          |
| Domain | `brittanytheengineer369.github.io`                                                          |
| Domain | `facebook-clone-nu-eight.vercel.app`                                                        |
| Domain | `ziptoonmonkey.fun`                                                                         |
| Domain | `vinted.securedirect.cfd`                                                                   |
| Domain | `01.rocketemail.biz` (parser classifies as domain — no `@`)                                 |
| CVE    | `CVE-2024-3400` (Palo Alto, KEV)                                                            |

Status legend: ✅ surfaced, ❌ not surfaced, ⚠️ partially / fallback only.

---

## IP sources

### Shodan
**Returns** (top-level): `area_code`, `asn`, `city`, `country_code`, `country_name`, `data[]`, `domains`, `hostnames`, `ip`, `ip_str`, `isp`, `last_update`, `latitude`, `longitude`, `org`, `os`, `ports`, `region_code`, `tags`.

**Returns per-banner** (`data[]`): `port`, `transport` (`tcp`/`udp`), `product`, `version`, `info` (HTTP banner), `http`, `ssl`, `_shodan`, `asn`, `domains`, `hash`, `hostnames`, `ip_str`, `isp`, `location`, `opts`, `org`, `os`, `timestamp`.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| `country_code` / `country_name`      | ✅ via `geo.country`                                  | keep |
| `city` / `region_code` / `latitude`/`longitude` | ✅ via `geo`                              | keep |
| `asn` / `org` / `isp`                | ✅ via `geo.asn` / `geo.org`                          | keep, add `isp` distinct |
| `hostnames`                          | ✅ via `geo.hostnames`                                | keep, union with AbuseIPDB |
| `ports` (raw int list)               | ⚠️ numbers only                                      | enrich to `{port, transport, service, product, version, banner_snippet}` |
| `data[].transport`                   | ❌                                                    | derive transport for each port |
| `data[].product` / `version`         | ❌                                                    | surface as service identity |
| `data[].info` (HTTP banner)          | ❌                                                    | first 120 chars in tooltip |
| `data[].ssl.cert.subject`/`issuer`   | ❌                                                    | "SSL: CN=… issuer=… exp=…" chip |
| `data[].ssl.jarm`                    | ❌                                                    | JARM chip |
| `tags`                               | ✅ first 6                                            | keep |
| `os`                                 | ❌                                                    | OS fingerprint chip if present |

### IPinfo
**Returns** (free tier seen): `city`, `country`, `hostname`, `ip`, `loc`, `org`, `postal`, `region`, `timezone`.

**Returns** (paid privacy tier — token-dependent, NOT present in current test runs): `privacy.{vpn, proxy, tor, relay, hosting, service}`, `company.{name, domain, type}`, `abuse.{address, country, email, name, phone, website}`, `asn.{asn, name, domain, route, type}`, `carrier.{name, mcc, mnc}`.

| Field                       | Today | v1.1 plan |
|-----------------------------|-------|-----------|
| `org`                       | ✅ via `geo.asn`/`geo.org` (split)                    | keep |
| `hostname`                  | ✅ via `geo.hostnames`                                | keep |
| `loc`                       | ✅ via `geo.lat`/`geo.lon`                            | keep |
| `privacy.service` (VPN brand) | ❌ (tier not enabled on current token)              | use if present; fall back to org-name heuristic |
| `company.type`              | ❌                                                    | surface as network-usage chip |
| `abuse.email`               | ❌                                                    | "Abuse contact: <email>" row |
| `timezone`                  | ❌                                                    | optional chip |

### AbuseIPDB
**Returns**: `abuseConfidenceScore`, `countryCode`, `domain`, `hostnames[]`, `ipAddress`, `ipVersion`, `isPublic`, `isTor`, `isWhitelisted`, `isp`, `lastReportedAt`, `numDistinctUsers`, `totalReports`, `usageType`, `reports[]` (if available — not in current cache rows).

**Verified on `185.220.101.45`**: `hostnames=['tor-exit-45.for-privacy.net']`, `usageType='Commercial'`, `isTor=True`.

| Field                       | Today | v1.1 plan |
|-----------------------------|-------|-----------|
| `abuseConfidenceScore` + `totalReports` | ✅ in module detail line                  | keep |
| `usageType`                 | ❌                                                    | network-usage chip |
| `hostnames[]`               | ❌                                                    | union into IP Core RDNS row |
| `isTor`                     | ❌ (overlapped by TOR module)                         | feeds Anon consensus |
| `domain`                    | ❌                                                    | optional row |
| `lastReportedAt`            | ❌                                                    | "Last reported: <date>" chip |

### AbstractAPI
**Returns**: `ip_address`, `is_vpn`, `is_proxy`, `is_tor`, `is_hosting`, `is_relay`, `is_mobile`, `is_residential_proxy`, `is_user_abuse`, `abuse_velocity`, `security{}`, `location{}`, `timezone{}`, `connection{}`, `flag.emoji`, `currency{}`.

**Verified on `185.220.101.45`**: `security.is_vpn=True`, `security.is_tor=True`, `security.is_abuse=True`.

| Field                       | Today | v1.1 plan |
|-----------------------------|-------|-----------|
| Top-level `is_*` flags      | ⚠️ used in ThreatSurfacePanel mixed bag              | feed Anon consensus block |
| `security.*` (7 flags)      | ❌                                                    | source of truth for Anon block |
| `abuse_velocity`            | ❌                                                    | chip ("high/med/low") |
| `flag.emoji`                | ❌                                                    | render before country code |
| `connection.connection_type`| ❌                                                    | datacenter vs residential chip |

### IPQS
**Returns**: `ip`, `is_crawler`, `is_vpn`, `is_tor`, `is_proxy`, `is_residential`, `is_user_defined_proxy`, `is_datacenter`, `is_mobile`, `is_bot`, `fraud_score`, `fraud_level`, `recent_abuse`, `is_blacklisted`, `host`, `country_code`, `isp`, `asn`, `organization`, `timezone`, `usage_type`, `latitude`, `longitude`.

**Not present** in current test runs — no `IPQS_API_KEY` configured. Add to `.env.example` if not already.

| Field                       | Today | v1.1 plan |
|-----------------------------|-------|-----------|
| `fraud_score`               | ❌                                                    | numeric chip alongside AbuseIPDB score |
| `is_vpn`/`is_proxy`/`is_tor`/`is_relay` | ❌                                        | feed Anon consensus |
| `usage_type`                | ❌                                                    | network-usage chip |
| `recent_abuse`              | ❌                                                    | "Recent abuse" flag |
| `is_bot` / `is_crawler`     | ❌                                                    | automation chip |

### TOR
**Returns**: `{is_tor: bool}` only.

| Field                       | Today | v1.1 plan |
|-----------------------------|-------|-----------|
| `is_tor`                    | ⚠️ flag in ThreatSurfacePanel                        | keep |
| `nickname` / `exit_country` / `last_seen` / `bandwidth` | ❌ (not fetched)                  | optional: parse Tor consensus file if present in `data/` |

### VirusTotal (IP)
**Returns**: `as_owner`, `asn`, `continent`, `country`, `last_analysis_date`, `last_analysis_results`, `last_analysis_stats`, `last_https_certificate`, `last_https_certificate_date`, `last_modification_date`, `network`, `rdap{}`, `regional_internet_registry`, `reputation`, `tags`, `total_votes`, `whois`, `whois_date`.

**Verified on `185.220.101.45`**: `rdap` includes `{object_class_name, handle, start_address, end_address, ip_version, name, type, country, ...}`. `jarm` is `None`. `last_https_certificate` present.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| `last_analysis_stats.{malicious, suspicious}` | ✅ module detail line              | keep |
| `last_analysis_results[]` (per engine) | ❌                                                  | expandable engine breakdown drawer |
| `rdap.{handle, start_address, end_address, country}` | ❌                                  | "Network: <CIDR>, registrar=<name>" row |
| `last_https_certificate.{subject, issuer, validity}` | ❌                                  | SSL Cert chip |
| `jarm`                               | ❌ (None for this IP)                                | render only when non-null |
| `regional_internet_registry`         | ❌                                                    | "RIR: ARIN/RIPE/…" chip |

### GreyNoise / Pulsedive / URLscan
- **GreyNoise**: `classification`, `name`, `noise`, `riot`, `last_seen`, `link`. Surface `classification` + `name` if non-empty; `riot=true` is a false-positive killer.
- **Pulsedive**: `risk`, `threats[]`, `feeds[]`, `comments[]`. Surface `risk` chip and threats list.
- **URLscan**: `results[]` with `page.{url, domain, ip, asn}`, `verdicts.{urlscan, engines}`, `task.screenshotURL`. Surface verdict count and link to most recent scan.

---

## Domain sources

### VirusTotal (domain)
**Returns**: `categories`, `creation_date`, `expiration_date`, `jarm`, `last_analysis_date`, `last_analysis_results`, `last_analysis_stats`, `last_dns_records`, `last_dns_records_date`, `last_https_certificate`, `last_https_certificate_date`, `last_modification_date`, `last_update_date`, `popularity_ranks`, `registrar`.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| `last_analysis_stats`                | ✅ module detail line                                 | keep |
| `categories` (per-engine)            | ❌                                                    | chip cloud |
| `creation_date` / `expiration_date`  | ❌                                                    | Domain Core "Age / Expires" row |
| `last_dns_records[]`                 | ❌                                                    | DNS history panel |
| `last_https_certificate.{subject, issuer, validity_not_after}` | ❌                          | TLS row in Domain Core |
| `jarm`                               | ❌                                                    | JARM chip if non-null |
| `popularity_ranks` (Alexa/Umbrella)  | ❌                                                    | "Rank: <provider> #<n>" chip |
| `registrar`                          | ❌                                                    | Domain Core registration row |

### WHOIS
**Returns** (varies by registrar; observed): `creation_date`, `expiration_date`, `updated_date`, `registrar`, `registrar_url`, `registrar_id`, `registrant_name`, `registrant_country`, `registrant_state_province`, `registrant_postal_code`, `org`, `name_servers[]`, `dnssec`, `status[]`, `emails[]`, `domain_name`, `address`, `city`, `state`, `country`, `referral_url`.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| Most fields                          | ❌                                                    | full registration block in Domain Core |
| `creation_date`                      | ⚠️ used by NRD heuristic only                        | surface as "Age: N days" chip |

### OTX (domain)
**Returns**: `alexa`, `base_indicator`, `false_positive`, `indicator`, `pulse_info.{count, pulses[], references[]}`, `sections`, `type`, `type_title`, `validation`, `whois`.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| `pulse_info.count`                   | ⚠️ via module detail line                            | promote |
| `pulse_info.pulses[].{name, adversary, malware_families, attack_ids, tags}` | ❌                  | Campaign attribution panel |
| `passive_dns[]`                      | ❌ (not in test responses, exists per OTX API)        | DNS-history pivot |

### Pulsedive / URLscan / Heuristics
- **Pulsedive**: same shape as IP case. Surface `risk` + `threats[]` + `feeds[]`.
- **URLscan**: `results[]` — surface `verdicts.urlscan` + screenshot URL.
- **Heuristics**: `dga{label, entropy, bigram_improbability, longest_consonant_run, score}`, `nrd{age_days, score}`, `typosquat{match, distance, score}`, `idn{mixed_script, score}`. Currently scored but not surfaced — render as chip cloud in Domain Core.

### URLhaus (domain/IP)
Not present in current domain tests (no hits). When hit, returns `payloads[]` with `{sha256, filename, filetype, signature}` — surface as payload table in Domain Core.

### ThreatFox (domain)
Not present in current tests. When hit, returns `malware_family`, `threat_type_desc`, `confidence_level`, `all_tags[]` — feeds Detection chip in Domain Core.

---

## Hash sources

### VirusTotal (hash)
**Returns** (rich): `crowdsourced_ids_results`, `crowdsourced_ids_stats`, `crowdsourced_yara_results`, `detectiteasy`, `elf_info`, `pe_info`, `filecondis`, `first_seen_itw_date`, `first_submission_date`, `last_analysis_date`, `last_analysis_results`, `last_analysis_stats`, `last_modification_date`, `last_submission_date`, `magic`, `magika`, `md5`, `meaningful_name`, `names[]`, `authentihash`, `creation_date`.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| `last_analysis_stats`                | ✅ module detail line                                 | keep |
| `meaningful_name` / `names[]`        | ❌                                                    | Hash Core "Filenames" row |
| `magic` / `magika`                   | ❌                                                    | "File type" row |
| `pe_info.imphash` / sections         | ❌                                                    | PE clustering block (PE-only) |
| `elf_info`                           | ❌                                                    | ELF block (ELF-only) |
| `crowdsourced_yara_results[]`        | ❌                                                    | YARA rule hits |
| `first_submission_date` / `last_submission_date` | ❌                                        | First/last seen row |
| `last_analysis_results[]` (per-engine) | ❌                                                  | engine breakdown drawer |

### OTX (hash)
**Returns**: `base_indicator`, `false_positive`, `indicator`, `pulse_info.{count, pulses[]}`, `sections`, `type`, `type_title`, `validation`.

Same plan as domain OTX.

### MalwareBazaar / ThreatFox / URLhaus / SSLBL (hash)
Not present in current test responses — those hashes aren't in the abuse.ch datasets. When hit, fields per agent inventory: `signature`, `tlsh`, `file_type`, `file_size`, `first_submission`, `last_submission`, `tags[]`, `origins[]`, `clamav`. Union all "family" signals into a single `family` chip.

---

## CVE sources

### NVD
**Returns**: `id`, `sourceIdentifier`, `published`, `lastModified`, `vulnStatus`, `descriptions[]`, `metrics.{cvssMetricV31[], cvssMetricV30[], cvssMetricV2[]}`, `weaknesses[]`, `configurations[]`, `references[]`, `cveTags`, `cisaActionDue`, `cisaExploitAdd`, `cisaRequiredAction`, `cisaVulnerabilityName`.

**Verified on CVE-2024-3400**: all fields present, including `descriptions[0].value` (full text) and `cvssMetricV31[0].cvssData.vectorString`.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| `descriptions[].value`               | ❌                                                    | **CVE Core "Description" block** — full English text |
| `metrics.cvssMetricV31[].cvssData.{baseScore, baseSeverity}` | ⚠️ used in scoring             | render baseScore + severity chip |
| `metrics.cvssMetricV31[].cvssData.vectorString` | ❌                                         | parse into AV/AC/PR/UI/S/C/I/A chips |
| `weaknesses[].description[].value`   | ❌                                                    | CWE chip(s) |
| `configurations[]`                   | ❌                                                    | "Affected: <vendor> <product> <version>" rows (top 5) |
| `references[].url`                   | ❌                                                    | external-link rows (top 5) |
| `cisaActionDue` / `cisaRequiredAction` | ❌ (also in KEV)                                    | dedupe with KEV |

### EPSS
**Returns**: `cve`, `date`, `epss`, `percentile`.

| Field                       | Today | v1.1 plan |
|-----------------------------|-------|-----------|
| `epss`                      | ⚠️ scored                                            | "Exploit prediction: NN%" chip |
| `percentile`                | ❌                                                    | "Top X% of all CVEs" chip |

### KEV
**Returns**: `cveID`, `cwes`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, `product`, `requiredAction`, `shortDescription`, `vendorProject`, `vulnerabilityName`.

| Field                                | Today | v1.1 plan |
|--------------------------------------|-------|-----------|
| Presence in KEV                      | ⚠️ scored                                            | "CISA KEV" badge |
| `dateAdded` / `dueDate`              | ❌                                                    | "Patch by: <date>" alert chip |
| `knownRansomwareCampaignUse`         | ❌                                                    | "Ransomware: known" warning chip |
| `requiredAction`                     | ❌                                                    | guidance row |

---

## Email
The parser maps any string without `@` to `domain`. True email IOCs (with `@`) would route through a future Email Core (HIBP / breach lookup pending — out of scope this round).

For domain-shaped email IOCs (e.g. `01.rocketemail.biz`), use Domain Core directly. Add a heuristic note ("looks like email-without-localpart") if pattern matches.

---

## Summary of fields to add per Core panel

| Core            | New rows / chips (v1.1) |
|-----------------|--------------------------|
| **IP Core**     | ports w/ service+transport+product, Anon block (TOR+VPN+proxy+brand), SSL+JARM, RDAP CIDR, abuse contact, usage-type chip, fraud_score |
| **Domain Core** | registration block (registrar/org/age/expiry/dnssec/status), DNS history, TLS cert subject/issuer/expiry, JARM, OTX campaigns, popularity rank, heuristic chips, payloads (URLhaus) |
| **Hash Core**   | filenames, file type (magic/magika), first/last seen, family (union of sources), PE/ELF block, YARA hits, OTX campaigns, MalwareBazaar/ThreatFox tags |
| **CVE Core**    | full NVD description, parsed CVSS vector chips, CWE chips, affected products list, KEV patch-by alert, EPSS percentile, references |
| **Email Core**  | deferred (route to Domain Core for now) |
