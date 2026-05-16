"""Cross-source synthesis for UI Core panels.

The orchestrator (:func:`ioc_tool.core.enrich.enrich_ioc_async`) returns one
``data`` blob per source. The UI needs a single normalized view per IOC type.
This module derives those views — one synth helper per IOC type — by merging
fields across sources, with reasonable conflict resolution.

Design rules:

* Every synth returns ``None`` when there is nothing useful to render.
* No network I/O — only reads from already-fetched ``data`` blobs.
* No mutation of the input dicts.
* Each synth lists every source it reads from in module-level docstring.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Port → service name map. Covers the ~120 common ports a SOC analyst sees
# day-to-day. Falls back to "port/transport" string for anything missing.
# Source: IANA service-names port-numbers registry (top entries).
# ---------------------------------------------------------------------------
_PORT_SVC: dict[tuple[int, str], str] = {
    (20, "tcp"): "ftp-data", (21, "tcp"): "ftp", (22, "tcp"): "ssh",
    (23, "tcp"): "telnet", (25, "tcp"): "smtp", (53, "tcp"): "dns",
    (53, "udp"): "dns", (67, "udp"): "dhcp-server", (68, "udp"): "dhcp-client",
    (69, "udp"): "tftp", (80, "tcp"): "http", (88, "tcp"): "kerberos",
    (110, "tcp"): "pop3", (111, "tcp"): "rpcbind", (119, "tcp"): "nntp",
    (123, "udp"): "ntp", (135, "tcp"): "msrpc", (137, "udp"): "netbios-ns",
    (138, "udp"): "netbios-dgm", (139, "tcp"): "netbios-ssn",
    (143, "tcp"): "imap", (161, "udp"): "snmp", (162, "udp"): "snmptrap",
    (179, "tcp"): "bgp", (194, "tcp"): "irc", (389, "tcp"): "ldap",
    (443, "tcp"): "https", (445, "tcp"): "smb", (465, "tcp"): "smtps",
    (500, "udp"): "isakmp", (514, "udp"): "syslog", (515, "tcp"): "lpd",
    (520, "udp"): "rip", (587, "tcp"): "submission", (631, "tcp"): "ipp",
    (636, "tcp"): "ldaps", (873, "tcp"): "rsync", (902, "tcp"): "vmware",
    (989, "tcp"): "ftps-data", (990, "tcp"): "ftps", (993, "tcp"): "imaps",
    (995, "tcp"): "pop3s", (1080, "tcp"): "socks", (1194, "udp"): "openvpn",
    (1433, "tcp"): "mssql", (1434, "udp"): "mssql-monitor",
    (1521, "tcp"): "oracle-db", (1701, "udp"): "l2tp", (1723, "tcp"): "pptp",
    (1812, "udp"): "radius-auth", (1813, "udp"): "radius-acct",
    (1883, "tcp"): "mqtt", (1900, "udp"): "ssdp", (2049, "tcp"): "nfs",
    (2082, "tcp"): "cpanel", (2083, "tcp"): "cpanel-ssl", (2086, "tcp"): "whm",
    (2087, "tcp"): "whm-ssl", (2095, "tcp"): "webmail", (2096, "tcp"): "webmail-ssl",
    (2181, "tcp"): "zookeeper", (2375, "tcp"): "docker", (2376, "tcp"): "docker-tls",
    (2379, "tcp"): "etcd-client", (2380, "tcp"): "etcd-peer",
    (3000, "tcp"): "node-http", (3128, "tcp"): "squid-proxy",
    (3268, "tcp"): "ldap-gc", (3306, "tcp"): "mysql",
    (3389, "tcp"): "rdp", (3478, "udp"): "stun", (3690, "tcp"): "svn",
    (4369, "tcp"): "epmd", (4500, "udp"): "ipsec-nat-t", (4789, "udp"): "vxlan",
    (5000, "tcp"): "upnp", (5060, "tcp"): "sip", (5060, "udp"): "sip",
    (5061, "tcp"): "sips", (5222, "tcp"): "xmpp-client", (5269, "tcp"): "xmpp-server",
    (5353, "udp"): "mdns", (5432, "tcp"): "postgres", (5601, "tcp"): "kibana",
    (5672, "tcp"): "amqp", (5683, "udp"): "coap", (5900, "tcp"): "vnc",
    (5984, "tcp"): "couchdb", (6379, "tcp"): "redis", (6443, "tcp"): "k8s-api",
    (6660, "tcp"): "irc", (6667, "tcp"): "irc", (7001, "tcp"): "weblogic",
    (8000, "tcp"): "http-alt", (8008, "tcp"): "http-alt", (8009, "tcp"): "ajp13",
    (8080, "tcp"): "http-proxy", (8086, "tcp"): "influxdb", (8088, "tcp"): "hadoop-web",
    (8089, "tcp"): "splunk", (8161, "tcp"): "activemq", (8443, "tcp"): "https-alt",
    (8500, "tcp"): "consul", (8888, "tcp"): "http-alt", (9000, "tcp"): "http-alt",
    (9042, "tcp"): "cassandra", (9090, "tcp"): "prometheus", (9092, "tcp"): "kafka",
    (9100, "tcp"): "node-exporter", (9200, "tcp"): "elasticsearch",
    (9300, "tcp"): "elasticsearch-tx", (9418, "tcp"): "git",
    (10000, "tcp"): "webmin", (11211, "tcp"): "memcached",
    (27017, "tcp"): "mongodb", (27018, "tcp"): "mongodb-shard",
    (50000, "tcp"): "db2", (50070, "tcp"): "hadoop-namenode",
}


def port_service(port: int, transport: str = "tcp") -> str:
    """Look up service name for a port. Empty string when unknown."""
    return _PORT_SVC.get((int(port), (transport or "tcp").lower()), "")


# ---------------------------------------------------------------------------
# VPN brand heuristic. When IPinfo Privacy tier returns ``privacy.service``
# we use it directly. Otherwise we pattern-match the org / isp / hostname
# against known VPN provider strings.
# ---------------------------------------------------------------------------
_VPN_BRANDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bproton(vpn)?\b|\bm247.*proton", re.I), "ProtonVPN"),
    (re.compile(r"\bmullvad\b", re.I), "Mullvad"),
    (re.compile(r"\bnordvpn\b|\btefincom\b", re.I), "NordVPN"),
    (re.compile(r"\bsurfshark\b", re.I), "Surfshark"),
    (re.compile(r"\bivpn\b", re.I), "IVPN"),
    (re.compile(r"\bprivate ?internet ?access\b|\bpia\b(?!s)", re.I), "PIA"),
    (re.compile(r"\bexpressvpn\b", re.I), "ExpressVPN"),
    (re.compile(r"\bwindscribe\b", re.I), "Windscribe"),
    (re.compile(r"\bcyberghost\b", re.I), "CyberGhost"),
    (re.compile(r"\bperfect ?privacy\b", re.I), "Perfect Privacy"),
    (re.compile(r"\bvyprvpn\b", re.I), "VyprVPN"),
    (re.compile(r"\btorguard\b", re.I), "TorGuard"),
    (re.compile(r"\bhide\.?me\b", re.I), "hide.me"),
    (re.compile(r"\bfor-privacy\.net\b", re.I), "for-privacy.net (Tor exit op)"),
]


def _detect_vpn_brand(*needles: str | None) -> str:
    haystack = " ".join(s for s in needles if s).strip()
    if not haystack:
        return ""
    for pat, brand in _VPN_BRANDS:
        if pat.search(haystack):
            return brand
    return ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _data(modules_raw: dict[str, Any], source: str) -> dict[str, Any]:
    """Safe accessor: ``modules_raw[source].data`` or ``{}``."""
    entry = modules_raw.get(source) or {}
    if not isinstance(entry, dict):
        return {}
    d = entry.get("data") or {}
    return d if isinstance(d, dict) else {}


def _abuseipdb_data(modules_raw: dict[str, Any]) -> dict[str, Any]:
    """AbuseIPDB sometimes wraps payload in {'data': {...}}."""
    raw = _data(modules_raw, "AbuseIPDB")
    inner = raw.get("data")
    return inner if isinstance(inner, dict) else raw


# ---------------------------------------------------------------------------
# IP synthesizers
# ---------------------------------------------------------------------------
def synth_ports(modules_raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Return Shodan ports enriched to ``{port, transport, service, product, version, banner_snippet, risk}``.

    De-duplicates by (port, transport) and prefers the entry with the richest
    banner. Falls back to ``ports[]`` (numbers only) when ``data[]`` banner
    list is empty.
    """
    shodan = _data(modules_raw, "Shodan")
    banners = shodan.get("data") if isinstance(shodan.get("data"), list) else []
    enriched: dict[tuple[int, str], dict[str, Any]] = {}

    for b in banners or []:
        if not isinstance(b, dict):
            continue
        try:
            port = int(b.get("port"))
        except (TypeError, ValueError):
            continue
        transport = (b.get("transport") or "tcp").lower()
        info = (b.get("info") or "").strip()
        snippet = (info[:120] + "…") if len(info) > 120 else info
        product = (b.get("product") or "").strip()
        version = (b.get("version") or "").strip()
        svc = product.lower() if product else port_service(port, transport)
        risk = _port_risk(port, transport)
        entry = {
            "port": port,
            "transport": transport,
            "service": svc or port_service(port, transport),
            "product": product,
            "version": version,
            "banner_snippet": snippet,
            "risk": risk,
        }
        key = (port, transport)
        prev = enriched.get(key)
        if prev is None or (entry["product"] and not prev.get("product")):
            enriched[key] = entry

    if enriched:
        return sorted(enriched.values(), key=lambda e: (e["port"], e["transport"]))

    raw_ports = shodan.get("ports") or []
    return [
        {
            "port": int(p),
            "transport": "tcp",
            "service": port_service(int(p), "tcp"),
            "product": "",
            "version": "",
            "banner_snippet": "",
            "risk": _port_risk(int(p), "tcp"),
        }
        for p in raw_ports if isinstance(p, (int, str)) and str(p).isdigit()
    ]


_HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 11211, 2375}


def _port_risk(port: int, transport: str) -> int:
    if port in _HIGH_RISK_PORTS:
        return 70
    if port in {22, 25, 80, 443, 53, 8080, 8443}:
        return 0
    return 20


def synth_anon(modules_raw: dict[str, Any]) -> dict[str, Any] | None:
    """Build the anonymization block by consensus across TOR/AbuseIPDB/AbstractAPI/IPinfo/IPQS.

    Each flag carries a ``confidence_sources`` list naming the providers
    that agreed, so the UI can show "TOR (3 sources)".
    """
    ipinfo = _data(modules_raw, "IPinfo")
    abstract = _data(modules_raw, "AbstractAPI")
    ipqs = _data(modules_raw, "IPQS")
    aipdb = _abuseipdb_data(modules_raw)
    tor = _data(modules_raw, "TOR")

    ipinfo_priv = ipinfo.get("privacy") if isinstance(ipinfo.get("privacy"), dict) else {}
    abstract_sec = abstract.get("security") if isinstance(abstract.get("security"), dict) else {}

    def collect(flag_key_per_src: dict[str, Any]) -> list[str]:
        return [src for src, val in flag_key_per_src.items() if bool(val)]

    is_tor_sources = collect({
        "TOR": tor.get("is_tor"),
        "AbuseIPDB": aipdb.get("isTor"),
        "AbstractAPI": abstract_sec.get("is_tor") or abstract.get("is_tor"),
        "IPinfo": ipinfo_priv.get("tor"),
        "IPQS": ipqs.get("is_tor"),
    })
    is_vpn_sources = collect({
        "AbstractAPI": abstract_sec.get("is_vpn") or abstract.get("is_vpn"),
        "IPinfo": ipinfo_priv.get("vpn"),
        "IPQS": ipqs.get("is_vpn"),
    })
    is_proxy_sources = collect({
        "AbstractAPI": abstract_sec.get("is_proxy") or abstract.get("is_proxy"),
        "IPinfo": ipinfo_priv.get("proxy"),
        "IPQS": ipqs.get("is_proxy"),
    })
    is_relay_sources = collect({
        "AbstractAPI": abstract_sec.get("is_relay") or abstract.get("is_relay"),
        "IPinfo": ipinfo_priv.get("relay"),
    })
    is_hosting_sources = collect({
        "AbstractAPI": abstract_sec.get("is_hosting") or abstract.get("is_hosting"),
        "IPinfo": ipinfo_priv.get("hosting"),
    })
    is_mobile_sources = collect({
        "AbstractAPI": abstract_sec.get("is_mobile"),
        "IPQS": ipqs.get("is_mobile"),
    })
    is_resproxy_sources = collect({
        "AbstractAPI": abstract_sec.get("is_residential_proxy"),
        "IPQS": ipqs.get("is_residential") or ipqs.get("is_user_defined_proxy"),
    })

    vpn_brand = (ipinfo_priv or {}).get("service") or ""
    if not vpn_brand and (is_vpn_sources or is_tor_sources):
        shodan = _data(modules_raw, "Shodan")
        vpn_brand = _detect_vpn_brand(
            shodan.get("org"), shodan.get("isp"),
            (aipdb.get("hostnames") or [""])[0] if aipdb.get("hostnames") else "",
            ipinfo.get("org"), ipinfo.get("hostname"),
        )

    tor_hostname = ""
    aipdb_hosts = aipdb.get("hostnames") or []
    if is_tor_sources and aipdb_hosts:
        for h in aipdb_hosts:
            if h and "tor" in h.lower():
                tor_hostname = h
                break

    flagged = bool(
        is_tor_sources or is_vpn_sources or is_proxy_sources
        or is_relay_sources or is_resproxy_sources
    )
    if not flagged and not is_hosting_sources and not is_mobile_sources:
        return None

    return {
        "is_tor": bool(is_tor_sources),
        "tor_hostname": tor_hostname,
        "is_vpn": bool(is_vpn_sources),
        "vpn_brand": vpn_brand,
        "is_proxy": bool(is_proxy_sources),
        "is_relay": bool(is_relay_sources),
        "is_hosting": bool(is_hosting_sources),
        "is_mobile": bool(is_mobile_sources),
        "is_residential_proxy": bool(is_resproxy_sources),
        "confidence_sources": {
            "tor": is_tor_sources, "vpn": is_vpn_sources, "proxy": is_proxy_sources,
            "relay": is_relay_sources, "hosting": is_hosting_sources,
            "mobile": is_mobile_sources, "residential_proxy": is_resproxy_sources,
        },
    }


def synth_core_ip(modules_raw: dict[str, Any]) -> dict[str, Any] | None:
    """IP Core extras beyond what ``_synthesize_geo`` already produces.

    Returns ``{ssl_cert, jarm, rdap_cidr, abuse_contact, usage_type,
    usage_sources, fraud_score, vt_engines, abuse_confidence, network_rir,
    hostnames_extra}`` — every field optional.
    """
    shodan = _data(modules_raw, "Shodan")
    vt = _data(modules_raw, "VirusTotal")
    ipinfo = _data(modules_raw, "IPinfo")
    abstract = _data(modules_raw, "AbstractAPI")
    aipdb = _abuseipdb_data(modules_raw)
    ipqs = _data(modules_raw, "IPQS")

    ssl_cert = {}
    jarm = ""
    for b in (shodan.get("data") or []):
        if not isinstance(b, dict):
            continue
        ssl = b.get("ssl") or {}
        cert = (ssl.get("cert") if isinstance(ssl, dict) else None) or {}
        if cert:
            subject = cert.get("subject") or {}
            issuer = cert.get("issuer") or {}
            ssl_cert = {
                "subject_cn": subject.get("CN") if isinstance(subject, dict) else str(subject),
                "issuer_cn": issuer.get("CN") if isinstance(issuer, dict) else str(issuer),
                "expires": cert.get("expires"),
            }
        if ssl and isinstance(ssl, dict) and ssl.get("jarm"):
            jarm = ssl["jarm"]
            break

    if not jarm:
        jarm = vt.get("jarm") or ""

    rdap = vt.get("rdap") or {}
    rdap_cidr = ""
    if rdap.get("start_address") and rdap.get("end_address"):
        rdap_cidr = f'{rdap["start_address"]} – {rdap["end_address"]}'

    abuse_contact = ((ipinfo.get("abuse") or {}).get("email")) or ""

    usage_signals = {
        "AbuseIPDB": aipdb.get("usageType"),
        "IPQS": ipqs.get("usage_type"),
        "IPinfo": (ipinfo.get("company") or {}).get("type"),
        "AbstractAPI": (abstract.get("connection") or {}).get("connection_type"),
    }
    usage_sources = {k: v for k, v in usage_signals.items() if v}
    usage_type = next(iter(usage_sources.values()), "")

    fraud_score = ipqs.get("fraud_score")
    abuse_conf = aipdb.get("abuseConfidenceScore")
    network_rir = vt.get("regional_internet_registry") or ""

    aipdb_hosts = [h for h in (aipdb.get("hostnames") or []) if h]
    shodan_hosts = [h for h in (shodan.get("hostnames") or []) if h]
    hostnames_extra = sorted(set(aipdb_hosts + shodan_hosts))

    core = {
        "ssl_cert": ssl_cert or None,
        "jarm": jarm or "",
        "rdap_cidr": rdap_cidr,
        "abuse_contact": abuse_contact,
        "usage_type": usage_type,
        "usage_sources": usage_sources,
        "fraud_score": fraud_score,
        "abuse_confidence": abuse_conf,
        "network_rir": network_rir,
        "hostnames_extra": hostnames_extra,
    }
    if not any(v for v in core.values() if v not in (None, "", [], {})):
        return None
    return core


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------
def synth_core_domain(modules_raw: dict[str, Any]) -> dict[str, Any] | None:
    """Domain Core: registration + DNS + TLS + campaign + heuristic + URLhaus payloads."""
    vt = _data(modules_raw, "VirusTotal")
    whois = _data(modules_raw, "WHOIS")
    otx = _data(modules_raw, "OTX")
    heur = _data(modules_raw, "Heuristics")
    urlhaus = _data(modules_raw, "URLhaus")
    tfox = _data(modules_raw, "ThreatFox")
    urlscan = _data(modules_raw, "URLscan")
    pulse = _data(modules_raw, "Pulsedive")
    crtsh = _data(modules_raw, "crt.sh")

    registration = {
        "registrar": whois.get("registrar") or vt.get("registrar") or "",
        "registrant_org": whois.get("org") or whois.get("registrant_name") or "",
        "registrant_country": whois.get("registrant_country") or whois.get("country") or "",
        "creation_date": whois.get("creation_date") or vt.get("creation_date") or "",
        "expiration_date": whois.get("expiration_date") or vt.get("expiration_date") or "",
        "updated_date": whois.get("updated_date") or "",
        "dnssec": whois.get("dnssec") or "",
        "status": whois.get("status") or [],
        "name_servers": whois.get("name_servers") or [],
    }

    cert = vt.get("last_https_certificate") or {}
    subject = cert.get("subject") or {} if isinstance(cert, dict) else {}
    issuer = cert.get("issuer") or {} if isinstance(cert, dict) else {}
    validity = cert.get("validity") or {} if isinstance(cert, dict) else {}
    tls = {
        "subject_cn": subject.get("CN") if isinstance(subject, dict) else "",
        "issuer_cn": issuer.get("CN") if isinstance(issuer, dict) else "",
        "not_after": validity.get("not_after") if isinstance(validity, dict) else "",
        "jarm": vt.get("jarm") or "",
    } if cert else {}

    dns_records = vt.get("last_dns_records") or []

    pulses = (otx.get("pulse_info") or {}).get("pulses") or []
    campaigns = []
    for p in pulses[:10]:
        if not isinstance(p, dict):
            continue
        campaigns.append({
            "name": p.get("name") or "",
            "adversary": p.get("adversary") or "",
            "malware_families": p.get("malware_families") or [],
            "attack_ids": p.get("attack_ids") or [],
            "tags": (p.get("tags") or [])[:6],
        })

    heuristics = {
        k: heur[k] for k in ("nrd", "dga", "typosquat", "idn")
        if k in heur and isinstance(heur[k], dict)
    }

    payloads = []
    for p in (urlhaus.get("payloads") or [])[:10]:
        if not isinstance(p, dict):
            continue
        payloads.append({
            "sha256": p.get("sha256") or "",
            "filename": p.get("filename") or "",
            "filetype": p.get("filetype") or "",
            "signature": p.get("signature") or "",
        })

    detections = {
        "vt": (vt.get("last_analysis_stats") or {}),
        "urlscan_verdict": (urlscan.get("results") or [{}])[0].get("verdicts", {}).get("urlscan") if urlscan.get("results") else "",
        "threatfox_family": tfox.get("malware_family") or tfox.get("malware") or "",
        "pulsedive_risk": pulse.get("risk") or "",
    }

    categories = vt.get("categories") or {}
    popularity = vt.get("popularity_ranks") or {}

    subdomains = (crtsh.get("unique_subdomains") or [])[:20] if crtsh else []

    core = {
        "registration": registration,
        "tls": tls or None,
        "dns_records": dns_records,
        "campaigns": campaigns,
        "heuristics": heuristics,
        "payloads": payloads,
        "detections": detections,
        "categories": categories,
        "popularity": popularity,
        "subdomains": subdomains,
    }
    if not any(v for v in core.values() if v not in (None, "", [], {})):
        return None
    return core


# ---------------------------------------------------------------------------
# Hash
# ---------------------------------------------------------------------------
def synth_core_hash(modules_raw: dict[str, Any]) -> dict[str, Any] | None:
    """Hash Core: identity + file metadata + family + sandbox + campaign."""
    vt = _data(modules_raw, "VirusTotal")
    otx = _data(modules_raw, "OTX")
    mb = _data(modules_raw, "MalwareBazaar")
    tfox = _data(modules_raw, "ThreatFox")
    urlhaus = _data(modules_raw, "URLhaus")
    sslbl = _data(modules_raw, "SSLBL")

    identity = {
        "sha256": vt.get("sha256") or mb.get("sha256") or sslbl.get("sha1") or "",
        "sha1": vt.get("sha1") or mb.get("sha1") or sslbl.get("sha1") or "",
        "md5": vt.get("md5") or mb.get("md5") or "",
        "tlsh": mb.get("tlsh") or "",
        "ssdeep": vt.get("ssdeep") or "",
        "authentihash": vt.get("authentihash") or "",
    }

    file_meta = {
        "magic": vt.get("magic") or "",
        "magika": vt.get("magika") or "",
        "file_type": mb.get("file_type") or vt.get("type_description") or "",
        "file_size": vt.get("size") or mb.get("file_size") or None,
        "names": vt.get("names") or [],
        "meaningful_name": vt.get("meaningful_name") or "",
        "first_submission": mb.get("first_submission") or vt.get("first_submission_date") or "",
        "last_submission": mb.get("last_submission") or vt.get("last_submission_date") or "",
    }

    family_signals = {
        "MalwareBazaar": mb.get("signature"),
        "ThreatFox": tfox.get("malware_family") or tfox.get("malware"),
        "URLhaus": urlhaus.get("signature"),
        "SSLBL": sslbl.get("malware"),
        "ClamAV": mb.get("clamav"),
    }
    families = sorted({v for v in family_signals.values() if v})
    family_sources = {k: v for k, v in family_signals.items() if v}

    yara = vt.get("crowdsourced_yara_results") or []

    pe = vt.get("pe_info") or {}
    elf = vt.get("elf_info") or {}

    pulses = (otx.get("pulse_info") or {}).get("pulses") or []
    campaigns = []
    for p in pulses[:10]:
        if not isinstance(p, dict):
            continue
        campaigns.append({
            "name": p.get("name") or "",
            "adversary": p.get("adversary") or "",
            "malware_families": p.get("malware_families") or [],
            "attack_ids": p.get("attack_ids") or [],
        })

    tags = sorted(set((mb.get("tags") or []) + (tfox.get("all_tags") or [])))

    c2_pivot = ""
    if sslbl.get("dst_ip") and sslbl.get("dst_port"):
        c2_pivot = f'{sslbl["dst_ip"]}:{sslbl["dst_port"]}'

    detections = {
        "vt_stats": vt.get("last_analysis_stats") or {},
        "threatfox_confidence": tfox.get("confidence_level"),
        "mb_submissions": mb.get("number_of_submissions"),
    }

    core = {
        "identity": identity,
        "file_meta": file_meta,
        "families": families,
        "family_sources": family_sources,
        "yara_hits": [{"rule": y.get("rule_name", ""), "author": y.get("author", "")} for y in yara[:10] if isinstance(y, dict)],
        "pe": {"imphash": pe.get("imphash", ""), "sections": len(pe.get("sections") or [])} if pe else {},
        "elf": elf if isinstance(elf, dict) else {},
        "campaigns": campaigns,
        "tags": tags,
        "c2_pivot": c2_pivot,
        "detections": detections,
    }
    if not any(v for v in core.values() if v not in (None, "", [], {})):
        return None
    return core


# ---------------------------------------------------------------------------
# CVE
# ---------------------------------------------------------------------------
_CVSS_VECTOR_RE = re.compile(r"([A-Z]+):([A-Z]+)")
_CVSS_FIELD_NAMES = {
    "AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required",
    "UI": "User Interaction", "S": "Scope", "C": "Confidentiality",
    "I": "Integrity", "A": "Availability", "AT": "Attack Requirements",
    "VC": "Vulnerable Confidentiality", "VI": "Vulnerable Integrity", "VA": "Vulnerable Availability",
    "SC": "Subsequent Confidentiality", "SI": "Subsequent Integrity", "SA": "Subsequent Availability",
}


def _parse_cvss_vector(vector: str) -> list[dict[str, str]]:
    if not vector:
        return []
    head, _, body = vector.partition("/")
    if not body and "/" not in vector:
        body = vector
    parts = body.split("/")
    out = []
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        if k.startswith("CVSS"):
            continue
        out.append({"abbr": k, "name": _CVSS_FIELD_NAMES.get(k, k), "value": v})
    return out


def synth_core_cve(modules_raw: dict[str, Any]) -> dict[str, Any] | None:
    """CVE Core: description + CVSS + CWE + affected products + KEV + EPSS."""
    nvd = _data(modules_raw, "NVD")
    epss = _data(modules_raw, "EPSS")
    kev = _data(modules_raw, "KEV")

    descriptions = nvd.get("descriptions") or []
    description_en = ""
    for d in descriptions:
        if isinstance(d, dict) and d.get("lang") == "en":
            description_en = d.get("value", "")
            break

    metrics = nvd.get("metrics") or {}
    cvss31_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV40") or []
    cvss = {}
    vector_parsed: list[dict[str, str]] = []
    if cvss31_list and isinstance(cvss31_list[0], dict):
        data = cvss31_list[0].get("cvssData") or {}
        cvss = {
            "version": data.get("version") or "",
            "vector": data.get("vectorString") or "",
            "base_score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or "",
        }
        vector_parsed = _parse_cvss_vector(cvss["vector"])

    weaknesses = nvd.get("weaknesses") or []
    cwes = []
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for d in (w.get("description") or []):
            if isinstance(d, dict) and d.get("value"):
                cwes.append(d["value"])
    cwes = sorted(set(cwes))

    configurations = nvd.get("configurations") or []
    affected: list[str] = []
    for c in configurations:
        if not isinstance(c, dict):
            continue
        for n in c.get("nodes") or []:
            for m in (n.get("cpeMatch") or []):
                crit = m.get("criteria") or ""
                if crit:
                    affected.append(crit)
    affected = sorted(set(affected))[:20]

    references = [r.get("url") for r in (nvd.get("references") or []) if isinstance(r, dict) and r.get("url")][:10]

    epss_block = {}
    if epss.get("epss") is not None:
        try:
            score = float(epss["epss"])
            pct = float(epss.get("percentile") or 0)
            epss_block = {
                "score": score,
                "score_pct": round(score * 100, 2),
                "percentile_pct": round(pct * 100, 2),
                "rank_text": f"Top {round((1 - pct) * 100, 2)}% most likely to be exploited",
            }
        except (TypeError, ValueError):
            pass

    kev_block = {}
    if kev:
        kev_block = {
            "vendor": kev.get("vendorProject") or "",
            "product": kev.get("product") or "",
            "vulnerability_name": kev.get("vulnerabilityName") or "",
            "date_added": kev.get("dateAdded") or "",
            "due_date": kev.get("dueDate") or "",
            "required_action": kev.get("requiredAction") or "",
            "known_ransomware": (kev.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "short_description": kev.get("shortDescription") or "",
        }

    core = {
        "id": nvd.get("id") or "",
        "published": nvd.get("published") or "",
        "last_modified": nvd.get("lastModified") or "",
        "status": nvd.get("vulnStatus") or "",
        "description": description_en,
        "cvss": cvss,
        "cvss_vector_parsed": vector_parsed,
        "cwes": cwes,
        "affected": affected,
        "references": references,
        "epss": epss_block,
        "kev": kev_block,
    }
    if not description_en and not cvss and not kev_block and not epss_block:
        return None
    return core
