// Shared sample IOC enrichment data for both prototypes.
// Shape mirrors the spec: ioc/type/final_score/modules + agreement.

window.IOC_DB = [
  {
    id: "ioc_01",
    ioc: "evil.example.com",
    type: "domain",
    final_score: 85,
    enriched_at: "2026-05-15T14:32:11Z",
    prev_score: 78,
    case: "campaign-emotet-q2",
    agreement: { sources_total: 6, sources_flagged: 4, sources_missed: 2, consensus: "high" },
    modules: {
      VirusTotal:  { score: 75, detail: "7 / 102 engines malicious", data: { malicious: 7, harmless: 60, suspicious: 0, undetected: 35 } },
      URLhaus:     { score: 95, detail: "threat=malware_download · tag=emotet", data: { threat: "malware_download", tags: ["emotet","downloader"] } },
      ThreatFox:   { score: 80, detail: "Cobalt Strike · confidence 75", data: { malware: "Cobalt Strike", confidence_level: 75 } },
      Pulsedive:   { score: 80, detail: "risk=high · phishing", data: { risk: "high", threats: ["Phishing"] } },
      AbuseIPDB:   { score: 0,  detail: "—", data: {} },
      WHOIS:       { score: 75, detail: "created 2026-05-03 · ns:cloudflare", data: { creation_date: "2026-05-03", registrar: "Namecheap, Inc." } },
      Heuristics:  { score: 75, detail: "NRD(12d) · DGA-low · IDN-mixed", data: {
        nrd:       { bucket: "nrd", age_days: 12, score: 75, created: "2026-05-03" },
        dga:       { score: 30, entropy: 2.3, longest_consonant_run: 3, label: "example" },
        typosquat: null,
        idn:       { mixed_script: false, score: 0 }
      } }
    }
  },
  {
    id: "ioc_02",
    ioc: "185.220.101.45",
    type: "ip",
    final_score: 72,
    enriched_at: "2026-05-15T14:31:50Z",
    prev_score: 70,
    case: "campaign-tor-exit",
    agreement: { sources_total: 5, sources_flagged: 4, sources_missed: 1, consensus: "high" },
    modules: {
      VirusTotal:  { score: 60, detail: "4 / 92 engines malicious",  data: { malicious: 4, harmless: 70, suspicious: 1, undetected: 17 } },
      AbuseIPDB:   { score: 88, detail: "1,204 reports · score 88",  data: { reports: 1204, abuse_score: 88 } },
      Feodo:       { score: 75, detail: "C2 known · last 7d",         data: {} },
      ThreatFox:   { score: 65, detail: "TrickBot · confidence 60",   data: { malware: "TrickBot", confidence_level: 60 } },
      Pulsedive:   { score: 70, detail: "risk=high",                  data: { risk: "high" } },
      Heuristics:  { score: 0,  detail: "—",                           data: {} }
    }
  },
  {
    id: "ioc_03",
    ioc: "paypa1-secure.com",
    type: "domain",
    final_score: 92,
    enriched_at: "2026-05-15T14:30:22Z",
    prev_score: 0,
    case: "campaign-phish-may",
    agreement: { sources_total: 5, sources_flagged: 4, sources_missed: 1, consensus: "high" },
    modules: {
      VirusTotal:  { score: 55, detail: "3 / 102 engines malicious", data: { malicious: 3, harmless: 50, suspicious: 2, undetected: 47 } },
      URLhaus:     { score: 0,  detail: "—", data: {} },
      Pulsedive:   { score: 85, detail: "risk=high · phishing", data: { risk: "high", threats: ["Phishing"] } },
      WHOIS:       { score: 90, detail: "created 2026-05-12 · 3d old", data: { creation_date: "2026-05-12" } },
      Heuristics:  { score: 95, detail: "Typosquat→paypal d=1 · NRD(3d)", data: {
        nrd:       { bucket: "nrd", age_days: 3, score: 90, created: "2026-05-12" },
        dga:       { score: 10, entropy: 1.9, longest_consonant_run: 2, label: "paypa1" },
        typosquat: { match: "paypal", distance: 1, confusables: ["1→l"], score: 95 },
        idn:       { mixed_script: false, score: 0 }
      } }
    }
  },
  {
    id: "ioc_04",
    ioc: "xkz9q2pmcvbnxhtreq.top",
    type: "domain",
    final_score: 78,
    enriched_at: "2026-05-15T14:29:01Z",
    prev_score: 0,
    case: null,
    agreement: { sources_total: 5, sources_flagged: 2, sources_missed: 3, consensus: "medium" },
    modules: {
      VirusTotal:  { score: 0,  detail: "0 / 102 engines malicious",  data: { malicious: 0, harmless: 80, suspicious: 0, undetected: 22 } },
      URLhaus:     { score: 0,  detail: "—", data: {} },
      Pulsedive:   { score: 45, detail: "risk=medium", data: { risk: "medium" } },
      WHOIS:       { score: 80, detail: "created 2026-05-14 · 1d old", data: { creation_date: "2026-05-14" } },
      Heuristics:  { score: 92, detail: "DGA-high · NRD(1d)", data: {
        nrd:       { bucket: "nrd", age_days: 1, score: 95, created: "2026-05-14" },
        dga:       { score: 92, entropy: 4.1, longest_consonant_run: 6, label: "xkz9q2pmcvbnxhtreq" },
        typosquat: null,
        idn:       { mixed_script: false, score: 0 }
      } }
    }
  },
  {
    id: "ioc_05",
    ioc: "аpple.com",
    type: "domain",
    final_score: 88,
    enriched_at: "2026-05-15T14:27:44Z",
    prev_score: 88,
    case: "campaign-phish-may",
    agreement: { sources_total: 5, sources_flagged: 3, sources_missed: 2, consensus: "high" },
    modules: {
      VirusTotal:  { score: 40, detail: "2 / 102 engines malicious", data: { malicious: 2, harmless: 60, suspicious: 0, undetected: 40 } },
      URLhaus:     { score: 0,  detail: "—", data: {} },
      Pulsedive:   { score: 70, detail: "risk=high", data: { risk: "high" } },
      WHOIS:       { score: 60, detail: "created 2025-11-04", data: {} },
      Heuristics:  { score: 95, detail: "IDN-mixed Cyrillic→Latin · homograph", data: {
        nrd:       null,
        dga:       { score: 5 },
        typosquat: { match: "apple", distance: 0, confusables: ["а→a (Cyrillic U+0430)"], score: 95 },
        idn:       { mixed_script: true, score: 95, unicode: "аpple.com", ascii: "xn--pple-43d.com" }
      } }
    }
  },
  {
    id: "ioc_06",
    ioc: "8.8.8.8",
    type: "ip",
    final_score: 5,
    enriched_at: "2026-05-15T14:25:09Z",
    prev_score: 5,
    case: null,
    agreement: { sources_total: 5, sources_flagged: 0, sources_missed: 5, consensus: "none" },
    modules: {
      VirusTotal:  { score: 0,  detail: "0 / 92 engines malicious", data: { malicious: 0, harmless: 88, suspicious: 0, undetected: 4 } },
      AbuseIPDB:   { score: 0,  detail: "0 reports", data: { reports: 0, abuse_score: 0 } },
      Feodo:       { score: 0,  detail: "—", data: {} },
      Pulsedive:   { score: 0,  detail: "risk=none", data: { risk: "none" } },
      Heuristics:  { score: 0,  detail: "—", data: {} }
    }
  },
  {
    id: "ioc_07",
    ioc: "CVE-2024-3094",
    type: "cve",
    final_score: 95,
    enriched_at: "2026-05-15T14:22:31Z",
    prev_score: 95,
    case: "campaign-xz-supply",
    agreement: { sources_total: 3, sources_flagged: 3, sources_missed: 0, consensus: "high" },
    modules: {
      "NVD":  { score: 95, detail: "CVSS 10.0 · CRITICAL", data: { cvss: 10.0, vector: "AV:N/AC:L" } },
      "KEV":  { score: 95, detail: "Known exploited · added 2024-03-29", data: { cveID: "CVE-2024-3094", dateAdded: "2024-03-29" } },
      "EPSS": { score: 80, detail: "epss=0.94 · 94th pct", data: { epss: 0.94 } }
    }
  },
  {
    id: "ioc_08",
    ioc: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    type: "sha256",
    final_score: 62,
    enriched_at: "2026-05-15T14:20:17Z",
    prev_score: 50,
    case: "campaign-emotet-q2",
    agreement: { sources_total: 3, sources_flagged: 2, sources_missed: 1, consensus: "medium" },
    modules: {
      VirusTotal:  { score: 65, detail: "32 / 71 engines malicious", data: { malicious: 32, harmless: 0, suspicious: 4, undetected: 35 } },
      "MalwareBazaar": { score: 70, detail: "Emotet · loader", data: { family: "Emotet" } },
      ThreatFox:   { score: 0,  detail: "—", data: {} }
    }
  },
  {
    id: "ioc_09",
    ioc: "example.com",
    type: "domain",
    final_score: 8,
    enriched_at: "2026-05-15T14:18:02Z",
    prev_score: 8,
    case: null,
    agreement: { sources_total: 6, sources_flagged: 0, sources_missed: 6, consensus: "none" },
    modules: {
      VirusTotal:  { score: 0, detail: "0 / 102 engines malicious", data: { malicious: 0, harmless: 96, suspicious: 0, undetected: 6 } },
      URLhaus:     { score: 0, detail: "—", data: {} },
      Pulsedive:   { score: 0, detail: "risk=none", data: { risk: "none" } },
      WHOIS:       { score: 0, detail: "created 1995-08-14 · 30y old", data: { creation_date: "1995-08-14" } },
      AbuseIPDB:   { score: 0, detail: "—", data: {} },
      Heuristics:  { score: 0, detail: "—", data: {} }
    }
  },
  {
    id: "ioc_10",
    ioc: "45.142.214.13",
    type: "ip",
    final_score: 34,
    enriched_at: "2026-05-15T14:14:55Z",
    prev_score: 51,
    case: null,
    agreement: { sources_total: 5, sources_flagged: 1, sources_missed: 4, consensus: "low" },
    modules: {
      VirusTotal:  { score: 20, detail: "1 / 92 engines malicious", data: { malicious: 1, harmless: 80, suspicious: 0, undetected: 11 } },
      AbuseIPDB:   { score: 45, detail: "32 reports · score 45", data: { reports: 32, abuse_score: 45 } },
      Feodo:       { score: 0,  detail: "—", data: {} },
      Pulsedive:   { score: 25, detail: "risk=low", data: { risk: "low" } },
      Heuristics:  { score: 0,  detail: "—", data: {} }
    }
  },
  {
    id: "ioc_11",
    ioc: "ns3.malware-c2.tk",
    type: "domain",
    final_score: 81,
    enriched_at: "2026-05-15T14:10:11Z",
    prev_score: 0,
    case: null,
    agreement: { sources_total: 5, sources_flagged: 3, sources_missed: 2, consensus: "high" },
    modules: {
      VirusTotal:  { score: 70, detail: "5 / 102 engines malicious", data: { malicious: 5 } },
      URLhaus:     { score: 80, detail: "threat=c2", data: { threat: "c2_server" } },
      ThreatFox:   { score: 75, detail: "QakBot · confidence 80", data: { malware: "QakBot" } },
      Pulsedive:   { score: 60, detail: "risk=high", data: { risk: "high" } },
      Heuristics:  { score: 65, detail: "NRD(28d) · TLD-suspect", data: { nrd: { age_days: 28, score: 65 } } }
    }
  },
  {
    id: "ioc_13",
    ioc: "cdn.evil-mirror.example.com",
    type: "domain",
    final_score: 79,
    enriched_at: "2026-05-15T13:50:11Z",
    prev_score: 0,
    case: "campaign-emotet-q2",
    agreement: { sources_total: 5, sources_flagged: 3, sources_missed: 2, consensus: "high" },
    modules: {
      VirusTotal:  { score: 65, detail: "5 / 102 engines malicious", data: { malicious: 5 } },
      URLhaus:     { score: 70, detail: "threat=malware_distribution · tag=emotet", data: { threat: "malware_distribution", tags: ["emotet"] } },
      ThreatFox:   { score: 75, detail: "Cobalt Strike · confidence 70", data: { malware: "Cobalt Strike", confidence_level: 70 } },
      WHOIS:       { score: 70, detail: "created 2026-04-28 · 17d old", data: { creation_date: "2026-04-28", registrar: "Namecheap, Inc." } },
      Heuristics:  { score: 70, detail: "NRD(17d)", data: { nrd: { age_days: 17, score: 70 } } }
    }
  },
  {
    id: "ioc_14",
    ioc: "194.61.55.142",
    type: "ip",
    final_score: 76,
    enriched_at: "2026-05-15T13:42:33Z",
    prev_score: 76,
    case: null,
    agreement: { sources_total: 4, sources_flagged: 3, sources_missed: 1, consensus: "high" },
    modules: {
      VirusTotal:  { score: 50, detail: "3 / 92 engines malicious", data: { malicious: 3 } },
      AbuseIPDB:   { score: 78, detail: "412 reports · score 78", data: { reports: 412, abuse_score: 78 } },
      ThreatFox:   { score: 70, detail: "Cobalt Strike · confidence 65", data: { malware: "Cobalt Strike", confidence_level: 65 } },
      Pulsedive:   { score: 60, detail: "risk=high", data: { risk: "high" } }
    }
  }
];

window.SOURCES = [
  { id: "VirusTotal",     status: "ok",         latency_ms: 412, ioc_types: ["ip","domain","url","sha256"], key: "present" },
  { id: "AbuseIPDB",      status: "ok",         latency_ms: 188, ioc_types: ["ip"],                          key: "present" },
  { id: "URLhaus",        status: "ok",         latency_ms: 95,  ioc_types: ["url","domain","sha256"],       key: "anonymous" },
  { id: "ThreatFox",      status: "ok",         latency_ms: 142, ioc_types: ["ip","domain","sha256"],        key: "anonymous" },
  { id: "Pulsedive",      status: "ok",         latency_ms: 280, ioc_types: ["ip","domain","url"],           key: "present" },
  { id: "Feodo",          status: "ok",         latency_ms: 84,  ioc_types: ["ip"],                          key: "anonymous" },
  { id: "SSLBL",          status: "ok",         latency_ms: 78,  ioc_types: ["sha256","ip"],                 key: "anonymous" },
  { id: "MalwareBazaar",  status: "ok",         latency_ms: 156, ioc_types: ["sha256"],                      key: "anonymous" },
  { id: "WHOIS",          status: "ok",         latency_ms: 612, ioc_types: ["domain"],                      key: "present" },
  { id: "crt.sh",         status: "ok",         latency_ms: 510, ioc_types: ["domain"],                      key: "anonymous" },
  { id: "CISA KEV",       status: "ok",         latency_ms: 220, ioc_types: ["cve"],                         key: "anonymous" },
  { id: "NVD",            status: "ok",         latency_ms: 305, ioc_types: ["cve"],                         key: "anonymous" },
  { id: "EPSS",           status: "ok",         latency_ms: 110, ioc_types: ["cve"],                         key: "anonymous" },
  { id: "GreyNoise",      status: "degraded",   latency_ms: 1340, ioc_types: ["ip","asn"],                   key: "present" },
  { id: "Shodan",         status: "no_key",     latency_ms: null, ioc_types: ["ip"],                         key: "missing" },
  { id: "AlienVault OTX", status: "no_key",     latency_ms: null, ioc_types: ["ip","domain","sha256"],       key: "missing" },
  { id: "IPQualityScore", status: "down",       latency_ms: null, ioc_types: ["ip","url","email"],           key: "present" },
  { id: "Heuristics",     status: "ok",         latency_ms: 12,  ioc_types: ["ip","domain","url"],           key: "local" },
  { id: "MISP local",     status: "ok",         latency_ms: 45,  ioc_types: ["ip","domain","sha256"],        key: "present" },
  { id: "OpenPhish",      status: "ok",         latency_ms: 230, ioc_types: ["url"],                         key: "anonymous" },
  { id: "PhishTank",      status: "ok",         latency_ms: 198, ioc_types: ["url"],                         key: "anonymous" }
];

window.CASES = [
  { id: "campaign-emotet-q2",   label: "Emotet Q2 resurgence",    iocs: ["ioc_01","ioc_08","ioc_13"],  opened: "2026-05-08", severity: 85 },
  { id: "campaign-phish-may",   label: "PayPal phish wave (May)", iocs: ["ioc_03","ioc_05"],          opened: "2026-05-12", severity: 92 },
  { id: "campaign-tor-exit",    label: "Tor exit abuse",          iocs: ["ioc_02"],                    opened: "2026-04-30", severity: 72 },
  { id: "campaign-xz-supply",   label: "XZ Utils supply chain",   iocs: ["ioc_07"],                    opened: "2024-03-30", severity: 95 }
];

// Live "watch" feed — score deltas in the last 24h.
window.WATCH_FEED = [
  { ts: "14:32:11", ioc: "evil.example.com",         type: "domain", score: 85, delta: +7,  reason: "VT 6→7 mal · URLhaus tag added" },
  { ts: "14:30:22", ioc: "paypa1-secure.com",         type: "domain", score: 92, delta: +92, reason: "first seen · NRD + typosquat" },
  { ts: "14:29:01", ioc: "xkz9q2pmcvbnxhtreq.top",    type: "domain", score: 78, delta: +78, reason: "first seen · DGA-high" },
  { ts: "14:20:17", ioc: "a1b2c3d4…f0a1b2",           type: "sha256", score: 62, delta: +12, reason: "VT 24→32 engines" },
  { ts: "14:14:55", ioc: "45.142.214.13",             type: "ip",     score: 34, delta: -17, reason: "AbuseIPDB reports decayed" },
  { ts: "14:10:11", ioc: "ns3.malware-c2.tk",         type: "domain", score: 81, delta: +81, reason: "first seen · C2 confirmed" },
  { ts: "13:58:02", ioc: "185.220.101.45",            type: "ip",     score: 72, delta: +2,  reason: "AbuseIPDB +14 reports" },
  { ts: "13:42:30", ioc: "kx9.dyndns.work",           type: "domain", score: 68, delta: +68, reason: "first seen · NRD(2d)" },
  { ts: "13:30:09", ioc: "92.118.39.207",             type: "ip",     score: 55, delta: +5,  reason: "Feodo C2 listing" },
  { ts: "13:14:51", ioc: "shop-amaz0n.cf",            type: "domain", score: 84, delta: +84, reason: "first seen · typosquat→amazon" },
  { ts: "13:02:11", ioc: "AS14618",                   type: "asn",    score: 22, delta: 0,   reason: "no change · monitored" },
  { ts: "12:48:33", ioc: "secure-bnk-login.com",      type: "domain", score: 90, delta: +90, reason: "first seen · phish kit match" }
];

// Heuristic explainers used in chips / tooltips.
window.HEUR_EXPLAIN = {
  NRD:       "Newly Registered Domain — registered within the last 30 days. Strong indicator of throwaway phishing or malware infrastructure.",
  DGA:       "Domain Generation Algorithm — high entropy / random-looking string. Malware C2 channels frequently use DGAs to evade blocklists.",
  TYPOSQUAT: "Typosquat — a string-edit distance away from a high-value brand (paypal, microsoft, etc.). Used in phishing.",
  IDN:       "Internationalized Domain Name homograph — mixes Cyrillic/Greek/Latin lookalike characters to impersonate brands."
};

// Symbolic flag library — surfaces at-a-glance category icons on IOCs.
window.IOC_FLAGS = (ioc) => {
  const out = [];
  const anon = ioc.anon || {};
  // Tor exit — only when the structured anon block confirms it (not a substring match on serialized JSON).
  if (anon.is_tor === true || ioc.case === "campaign-tor-exit") {
    const srcs = (anon.confidence_sources?.tor || []).length;
    out.push({ k: "TOR", glyph: "⊙", label: anon.tor_hostname ? `Tor exit · ${anon.tor_hostname}` : "Tor exit node", color: "#a78bfa", title: `Tor exit node — traffic anonymized via Tor network. Confirmed by ${srcs || 1} source(s).` });
  }
  // VPN — surface brand when known. Suppress when TOR is already flagged
  // (the TOR chip is the primary classification; e.g. AbstractAPI tags Tor
  // exits as VPN+TOR, no need to show both).
  if (anon.is_vpn === true && anon.is_tor !== true) {
    const srcs = (anon.confidence_sources?.vpn || []).length;
    const label = anon.vpn_brand ? `VPN · ${anon.vpn_brand}` : "VPN";
    out.push({ k: "VPN", glyph: "⛨", label, color: "#f59e0b", title: `Anonymizing VPN. Confirmed by ${srcs} source(s)${anon.vpn_brand ? ` — brand: ${anon.vpn_brand}` : ""}.` });
  }
  // Proxy (incl. residential proxy)
  if (anon.is_proxy === true || anon.is_residential_proxy === true) {
    const isRes = anon.is_residential_proxy === true;
    const srcs = (anon.confidence_sources?.[isRes ? "residential_proxy" : "proxy"] || []).length;
    out.push({ k: "PROXY", glyph: "⇄", label: isRes ? "Residential proxy" : "Proxy", color: "#f97316", title: `${isRes ? "Residential proxy — rotated through real-user IPs (hard to block)" : "Open / commercial proxy"}. Confirmed by ${srcs} source(s).` });
  }
  // C2 channel
  const isC2 = Object.values(ioc.modules).some(m => /c2|command/i.test(m.detail || "") || m.data?.threat === "c2_server");
  if (isC2) {
    out.push({ k: "C2", glyph: "⌬", label: "Known C2", color: "#f43f5e", title: "Known Command & Control infrastructure. Confirmed beacon destination." });
  }
  // Phishing
  const isPhish = Object.values(ioc.modules).some(m => /phish/i.test(m.detail || "") || m.data?.threats?.some(t => /phish/i.test(t)));
  if (isPhish) {
    out.push({ k: "PHISH", glyph: "⚐", label: "Phishing", color: "#fb923c", title: "Indicator linked to credential-harvesting or phishing campaign." });
  }
  // Malware download / dropper
  const isMal = Object.values(ioc.modules).some(m => /malware_download|loader|dropper/i.test(m.data?.threat || "") || /loader/i.test(m.detail || ""));
  if (isMal) {
    out.push({ k: "MAL", glyph: "⚙", label: "Malware host", color: "#f43f5e", title: "Hosts malware payloads (loader / dropper / second stage)." });
  }
  // CVE exploited in the wild — backend uses module key "KEV" with data.cveID
  // on hit; fall back to the legacy mock key "CISA KEV" so demo data keeps
  // rendering until it's migrated.
  if (ioc.type === "cve" && (ioc.modules.KEV?.data?.cveID || ioc.modules["CISA KEV"]?.data?.kev)) {
    out.push({ k: "KEV", glyph: "★", label: "CISA KEV", color: "#f43f5e", title: "CISA Known Exploited Vulnerabilities catalog — confirmed exploited in the wild." });
  }
  // NRD shortcut
  if (ioc.modules.Heuristics?.data?.nrd?.age_days != null && ioc.modules.Heuristics.data.nrd.age_days < 30) {
    out.push({ k: "NRD", glyph: "◷", label: "NRD < 30d", color: "#fb923c", title: window.HEUR_EXPLAIN.NRD });
  }
  // Cloud hosting
  if (/cloudflare|aws|gcp|azure|akamai/i.test(JSON.stringify(ioc.modules))) {
    out.push({ k: "CDN", glyph: "▤", label: "CDN-fronted", color: "#60a5fa", title: "Hosted behind a CDN/cloud provider. Take-down may require provider abuse contact." });
  }
  return out;
};

// Synthetic Shodan-style data for IP IOCs.
window.SHODAN_DATA = {
  ioc_02: {
    ip: "185.220.101.45",
    country: "DE", country_name: "Germany", city: "Berlin", lat: 52.52, lon: 13.40,
    asn: "AS208294", org: "M247 Europe SRL", isp: "M247 LTD",
    hostnames: ["tor-exit-de.relay.network"],
    tags: ["tor", "proxy"],
    ports: [
      { port: 22,   service: "OpenSSH",   banner: "SSH-2.0-OpenSSH_8.9p1", risk: 0 },
      { port: 80,   service: "nginx",     banner: "nginx/1.22.0",          risk: 0 },
      { port: 443,  service: "nginx",     banner: "TLS · self-signed",     risk: 30 },
      { port: 9001, service: "Tor relay", banner: "Tor 0.4.7.13",          risk: 70 },
      { port: 9030, service: "Tor dir",   banner: "—",                      risk: 60 }
    ]
  },
  ioc_06: {
    ip: "8.8.8.8",
    country: "US", country_name: "United States", city: "Mountain View", lat: 37.39, lon: -122.08,
    asn: "AS15169", org: "Google LLC", isp: "Google",
    hostnames: ["dns.google"],
    tags: ["dns", "google"],
    ports: [
      { port: 53,  service: "DNS",   banner: "Google Public DNS", risk: 0 },
      { port: 443, service: "HTTPS", banner: "DNS-over-HTTPS",    risk: 0 }
    ]
  },
  ioc_10: {
    ip: "45.142.214.13",
    country: "RU", country_name: "Russia", city: "Moscow", lat: 55.75, lon: 37.62,
    asn: "AS49505", org: "Selectel Ltd.", isp: "Selectel",
    hostnames: [],
    tags: ["bulletproof-suspect"],
    ports: [
      { port: 22,   service: "OpenSSH",   banner: "SSH-2.0-OpenSSH_7.4 (outdated)", risk: 40 },
      { port: 3389, service: "RDP",       banner: "Microsoft RDP",                   risk: 60 },
      { port: 8080, service: "HTTP-proxy",banner: "Squid 3.5.27",                    risk: 50 }
    ]
  },
  ioc_14: {
    ip: "194.61.55.142",
    country: "NL", country_name: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.89,
    asn: "AS60068", org: "Datacamp Limited", isp: "CDN77",
    hostnames: [],
    tags: ["c2-confirmed", "cobalt-strike"],
    ports: [
      { port: 80,   service: "HTTP",     banner: "Cobalt Strike teamserver beacon", risk: 95 },
      { port: 443,  service: "HTTPS",    banner: "Cobalt Strike · self-signed",      risk: 95 },
      { port: 50050,service: "CS team",  banner: "Cobalt Strike teamserver default", risk: 99 }
    ]
  }
};

// MITRE ATT&CK map — malware family to relevant techniques.
window.MITRE_MAP = {
  "Cobalt Strike": [
    { id: "T1055", name: "Process Injection",          tactic: "Defense Evasion" },
    { id: "T1071", name: "Application Layer Protocol", tactic: "Command & Control" },
    { id: "T1547", name: "Boot or Logon Autostart",     tactic: "Persistence" },
    { id: "T1059", name: "Command & Scripting Interp.", tactic: "Execution" }
  ],
  "Emotet": [
    { id: "T1566", name: "Phishing",                    tactic: "Initial Access" },
    { id: "T1027", name: "Obfuscated Files",            tactic: "Defense Evasion" },
    { id: "T1573", name: "Encrypted Channel",           tactic: "Command & Control" }
  ],
  "TrickBot": [
    { id: "T1090", name: "Proxy",                       tactic: "Command & Control" },
    { id: "T1003", name: "OS Credential Dumping",       tactic: "Credential Access" },
    { id: "T1021", name: "Remote Services",             tactic: "Lateral Movement" }
  ],
  "QakBot": [
    { id: "T1055", name: "Process Injection",          tactic: "Defense Evasion" },
    { id: "T1218", name: "System Binary Proxy Exec.",  tactic: "Defense Evasion" },
    { id: "T1071", name: "Application Layer Protocol", tactic: "Command & Control" }
  ]
};

// Pivotable token kinds — used to extract drill-down chips from source detail.
window.PIVOT_KINDS = {
  malware:    { glyph: "◆", color: "#f43f5e", label: "malware family" },
  tag:        { glyph: "#", color: "#fb923c", label: "tag" },
  registrar:  { glyph: "▤", color: "#60a5fa", label: "registrar" },
  asn:        { glyph: "▦", color: "#60a5fa", label: "ASN" }
};

// Source freshness — synthetic "last fetched" minutes ago.
window.FRESHNESS = (sourceName, iocId) => {
  let h = 0; const s = sourceName + iocId;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  const minutes = h % 240; // 0–240
  return { minutes, stale: minutes > 120 };
};

window.RISK_TIER = (s) => {
  if (s >= 80) return { tier: "CRITICAL", short: "CRIT", idx: 4 };
  if (s >= 60) return { tier: "HIGH",     short: "HIGH", idx: 3 };
  if (s >= 40) return { tier: "MEDIUM",   short: "MED",  idx: 2 };
  if (s >= 20) return { tier: "LOW",      short: "LOW",  idx: 1 };
  return        { tier: "SAFE",     short: "SAFE", idx: 0 };
};

// Defang helpers — replaces . with [.] and :// with [://] in URLs/domains/IPs.
window.defangText = (s) => {
  if (!s) return s;
  return String(s)
    .replace(/:\/\//g, "[://]")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
};

// IOC history sparkline data (score over time, last 14 days).
window.IOC_HISTORY = {
  ioc_01: [40, 45, 50, 55, 60, 62, 65, 70, 72, 75, 78, 78, 78, 85],
  ioc_03: [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  92],
  ioc_02: [60, 62, 64, 65, 65, 66, 67, 68, 69, 70, 70, 70, 70, 72],
  ioc_05: [85, 85, 86, 86, 87, 87, 88, 88, 88, 88, 88, 88, 88, 88],
  ioc_07: [95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95]
};

// -----------------------------------------------------------------------------
// Live backend fetch — points the brutalist UI at the real /api/ui/enrich
// endpoint. Returns a Promise resolving to a record in the same shape as
// window.IOC_DB entries. Errors bubble up — the caller falls back to
// fabricateRecord() to keep the dashboard responsive.
//
// Token: read from sessionStorage (if the auth banner has captured one).
// -----------------------------------------------------------------------------
window.shadowscopeFetch = async function (ioc, opts) {
  opts = opts || {};
  const params = new URLSearchParams({ ioc: String(ioc).trim() });
  if (opts.defang)   params.set("defang", "true");
  if (opts.summary)  params.set("summary", "true");
  if (opts.no_cache) params.set("no_cache", "true");
  const headers = {};
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const r = await fetch("/api/ui/enrich?" + params.toString(), { headers });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("HTTP " + r.status + " " + body.slice(0, 200));
  }
  return await r.json();
};
