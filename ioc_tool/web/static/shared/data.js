// Dashboard helper data + rendering utilities.
//
// Every demo IOC / event fixture has been removed. The dashboard now
// reads exclusively from the SQLite cache via:
//   /api/ui/recent  — strip seed + Watch tab history
//   /api/ui/pivot   — PivotPanel related-IOC lookup
//   /api/ui/cases   — Cases tab
//   /api/ui/sources — Sources drawer + badge
// The AlertTicker derives its high-severity items from the React
// `results` state (the strip), so it tracks the actual enrichments
// the analyst has cached.
//
// What remains here is pure rendering helpers that operate on
// whatever record they get: IOC_FLAGS, HEUR_EXPLAIN, MITRE_MAP,
// PIVOT_KINDS, RISK_TIER, defangText.

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

// Streaming enrich — calls /api/ui/enrich/stream and dispatches per-source
// events to the supplied handlers as they arrive. Returns a Promise that
// resolves to the final shaped record (same shape as shadowscopeFetch).
//
// Why fetch+ReadableStream instead of EventSource? EventSource cannot send
// the Authorization header, so a token-protected install would 401 on every
// call. fetch streaming + manual SSE-frame parsing keeps the auth path the
// same as every other endpoint.
//
// Handlers (all optional):
//   onMeta({ioc, type, pending, allowlisted})
//   onModule({name, entry: {score, data}})
//   onError({detail})
window.shadowscopeFetchStream = async function (ioc, opts, handlers) {
  opts = opts || {};
  handlers = handlers || {};
  const params = new URLSearchParams({ ioc: String(ioc).trim() });
  if (opts.defang)   params.set("defang", "true");
  if (opts.no_cache) params.set("no_cache", "true");
  const headers = { "Accept": "text/event-stream" };
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const r = await fetch("/api/ui/enrich/stream?" + params.toString(), { headers });
  if (!r.ok || !r.body) {
    const body = r.body ? "" : "(no body)";
    const text = r.body ? await r.text().catch(() => "") : body;
    throw new Error("HTTP " + r.status + " " + text.slice(0, 200));
  }
  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let final = null;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    // SSE frames are separated by a blank line ("\n\n").
    let idx;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const frame = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      // Parse one frame: collect "event:" + "data:" lines.
      let evt = "message";
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:")) evt = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
        // ":" comment lines are ignored.
      }
      if (!data) continue;
      let parsed;
      try { parsed = JSON.parse(data); } catch (e) { continue; }
      if (evt === "meta")  { handlers.onMeta  && handlers.onMeta(parsed); }
      else if (evt === "module") { handlers.onModule && handlers.onModule(parsed); }
      else if (evt === "final") { final = parsed; }
      else if (evt === "error") {
        handlers.onError && handlers.onError(parsed);
        throw new Error(parsed.detail || "stream error");
      }
    }
  }
  if (!final) throw new Error("stream closed before final event");
  return final;
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

// Cases — list every case in the workspace with members + derived
// severity / opened-at. Used by CasesView; replaces the hardcoded
// window.CASES demo list.
window.shadowscopeCases = async function () {
  const headers = {};
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const r = await fetch("/api/ui/cases", { headers });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("HTTP " + r.status + " " + body.slice(0, 200));
  }
  return await r.json();
};

// Assign / detach a case for an IOC. Pass `case: null` (or "") to
// detach. Returns the server's `{ioc, case}` echo on success.
window.shadowscopeSetCase = async function (iocValue, caseName) {
  const headers = { "Content-Type": "application/json" };
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const r = await fetch(`/api/ui/iocs/${encodeURIComponent(iocValue)}/case`, {
    method: "PATCH",
    headers,
    body: JSON.stringify({ case: caseName || null }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("HTTP " + r.status + " " + body.slice(0, 200));
  }
  return await r.json();
};

// Delete a case (detaches every IOC from it). The IOCs themselves stay
// in cache. Returns `{case, removed}` with the row count.
window.shadowscopeDeleteCase = async function (caseName) {
  const headers = {};
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const r = await fetch(`/api/ui/cases/${encodeURIComponent(caseName)}`, {
    method: "DELETE",
    headers,
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("HTTP " + r.status + " " + body.slice(0, 200));
  }
  return await r.json();
};

// Score history — chronological score snapshots for one IOC. Backs the
// inline sparkline on the IOC detail view. Returns `{ioc, count, points}`
// where points is an array of `{score, recorded_at}` ordered oldest →
// newest. 404 (IOC not in cache) is normalised to an empty result so
// the caller can render an empty state without try/catching.
window.shadowscopeScoreHistory = async function (value, limit) {
  const n = Number.isFinite(limit) ? limit : 50;
  const headers = {};
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  const url = `/api/ui/score_history/${encodeURIComponent(value)}?limit=${n}`;
  const r = await fetch(url, { headers });
  if (r.status === 404) {
    return { ioc: value, count: 0, points: [] };
  }
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("HTTP " + r.status + " " + body.slice(0, 200));
  }
  return await r.json();
};

// Server-Sent Events stream — replaces the legacy 8s /api/ui/recent
// poll for live activity. Returns a `{close}` handle so callers can
// tear down cleanly on unmount.
//
// Auto-reconnect: native EventSource already retries, but we layer
// exponential backoff (capped at 30s) on top so a flapping proxy
// doesn't hammer the server. The `onScore` callback receives every
// `score` event payload as `{ioc, score, ...}`; `onHello` fires once
// per fresh connection. Auth: EventSource can't set headers, so the
// token is appended as a `?token=` query string. When the backend has
// `SHADOWSCOPE_API_TOKEN` configured the stream is gated; without a
// matching ?token= it returns 401 and the EventSource onerror path
// triggers the backoff reconnect (which is a quiet no-op until the
// user provides a token via the auth banner / sessionStorage).
window.shadowscopeSubscribeEvents = function (onScore, onHello, onError) {
  let es = null;
  let backoff = 1000;
  let closed = false;
  let timer = null;

  const buildUrl = () => {
    let tok = null;
    try { tok = sessionStorage.getItem("ss_api_token"); } catch (e) {}
    return tok
      ? "/api/ui/events?token=" + encodeURIComponent(tok)
      : "/api/ui/events";
  };
  const connect = () => {
    const url = buildUrl();
    if (closed) return;
    try {
      es = new EventSource(url);
    } catch (e) {
      if (typeof onError === "function") onError(e);
      scheduleReconnect();
      return;
    }
    es.addEventListener("hello", (ev) => {
      backoff = 1000; // reset on confirmed connection
      try {
        if (typeof onHello === "function") onHello(JSON.parse(ev.data || "{}"));
      } catch (_) { /* malformed hello — ignore */ }
    });
    es.addEventListener("score", (ev) => {
      backoff = 1000;
      try {
        const payload = JSON.parse(ev.data || "{}");
        if (typeof onScore === "function") onScore(payload);
      } catch (_) { /* bad JSON — drop */ }
    });
    es.onerror = (err) => {
      if (typeof onError === "function") onError(err);
      try { es && es.close(); } catch (_) {}
      es = null;
      scheduleReconnect();
    };
  };

  const scheduleReconnect = () => {
    if (closed) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      backoff = Math.min(backoff * 2, 30000);
      connect();
    }, backoff);
  };

  connect();

  return {
    close: () => {
      closed = true;
      if (timer) { clearTimeout(timer); timer = null; }
      try { es && es.close(); } catch (_) {}
      es = null;
    },
  };
};

// Recently-used cases — localStorage-backed MRU list used by
// CaseAssignBar to hoist common cases to the top of its <datalist>.
// Capped at 5, deduped (case-insensitive), newest first. Storage
// failures (private mode, quota) degrade silently to an empty list.
window.SHADOWSCOPE_RECENT_CASES_KEY = "shadowscope.recentCases";
window.SHADOWSCOPE_RECENT_CASES_MAX = 5;

window.shadowscopeGetRecentCases = function () {
  try {
    const raw = localStorage.getItem(window.SHADOWSCOPE_RECENT_CASES_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((s) => typeof s === "string" && s.trim());
  } catch (_) {
    return [];
  }
};

window.shadowscopePushRecentCase = function (name) {
  if (!name || typeof name !== "string") return [];
  const trimmed = name.trim();
  if (!trimmed) return [];
  const lower = trimmed.toLowerCase();
  let list;
  try {
    list = window.shadowscopeGetRecentCases();
    // Remove any prior occurrence (case-insensitive) so MRU wins.
    list = list.filter((s) => s.toLowerCase() !== lower);
    list.unshift(trimmed);
    list = list.slice(0, window.SHADOWSCOPE_RECENT_CASES_MAX);
    localStorage.setItem(window.SHADOWSCOPE_RECENT_CASES_KEY, JSON.stringify(list));
  } catch (_) {
    return [];
  }
  return list;
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
