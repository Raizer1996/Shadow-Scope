// Dashboard helper data + rendering utilities.
//
// Demo IOC fixtures (IOC_DB, SHODAN_DATA, IOC_HISTORY) were removed when
// the recent strip switched to /api/ui/recent — the dashboard now reflects
// real cache state only. WATCH_FEED + CASES remain as synthetic demo
// scaffolding for the Watch / Cases tabs (no backend equivalent yet).
// IOC_FLAGS, HEUR_EXPLAIN, MITRE_MAP, PIVOT_KINDS, RISK_TIER, defangText
// are pure rendering helpers that operate on whatever record they get.

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

// -----------------------------------------------------------------------------
// Live backend fetch — points the brutalist UI at the real /api/ui/enrich
// endpoint. Returns a Promise resolving to a record carrying the brutalist
// UI shape (id, ioc, type, modules, final_score, agreement, enriched_at).
// Errors bubble up — the caller surfaces a toast and leaves the strip
// unchanged.
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

// Fetch the newest cached IOCs for the recent strip. Returns an array of
// records in the same shape window.shadowscopeFetch produces, sorted
// newest-first. Empty list = no enrichments cached yet — caller should
// render an empty-state prompt instead of falling back to fake data.
window.shadowscopeRecent = async function (limit) {
  const n = Number.isFinite(limit) ? limit : 8;
  const headers = {};
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const r = await fetch("/api/ui/recent?limit=" + n, { headers });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("HTTP " + r.status + " " + body.slice(0, 200));
  }
  return await r.json();
};

// Pivot lookup — find related IOCs across the whole SQLite cache by
// tag / malware family / registrar / etc. Used by PivotPanel to widen
// the "RELATED" view beyond whatever happens to be on the strip.
// Returns an array of records (may be empty); errors bubble up so the
// caller can fall back to in-memory results.
window.shadowscopePivot = async function (kind, value, opts) {
  opts = opts || {};
  const params = new URLSearchParams({ kind: String(kind), value: String(value) });
  if (opts.limit)   params.set("limit", String(opts.limit));
  if (opts.exclude) params.set("exclude", String(opts.exclude));
  const headers = {};
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const r = await fetch("/api/ui/pivot?" + params.toString(), { headers });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("HTTP " + r.status + " " + body.slice(0, 200));
  }
  return await r.json();
};
