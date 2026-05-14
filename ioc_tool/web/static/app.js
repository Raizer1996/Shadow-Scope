/*
 * ShadowScope dashboard — vanilla JS.
 *
 * Talks to the FastAPI JSON endpoints exposed by ioc_tool/web/api.py:
 *   GET  /health
 *   GET  /enrich?ioc=<v>&defang=<bool>
 *   POST /enrich/bulk      body {iocs:[...]}
 *   POST /extract          body {text:"..."}
 *   GET  /sources
 *
 * Auth: token is read from ?token=<value> on the URL on page load and kept
 * in memory only (intentionally NOT in localStorage — embed flows pass the
 * token via query string). Subsequent fetches add Authorization: Bearer <token>.
 *
 * Note on rendering: we never use innerHTML for untrusted content. All
 * dynamic content is inserted as text nodes via document.createTextNode or
 * the el() helper below, which only accepts strings (set as textContent) or
 * pre-built Nodes. Clearing containers is done via replaceChildren().
 */

(() => {
  "use strict";

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------

  /** @type {string|null} */
  let authToken = null;

  const els = {};

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  function $(id) { return document.getElementById(id); }

  function clearNode(node) {
    // Safe replacement for innerHTML = "" — uses DOM API only.
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function authHeaders() {
    return authToken ? { Authorization: "Bearer " + authToken } : {};
  }

  function showAuthBanner(show, msg) {
    if (!els.authBanner) return;
    els.authBanner.classList.toggle("hidden", !show);
    if (msg) {
      const m = els.authBanner.querySelector(".auth-msg");
      if (m) m.textContent = msg;
    }
  }

  function setStatus(text, isError) {
    els.statusText.textContent = text || "";
    els.status.classList.toggle("error", !!isError);
  }

  function setSpinner(on) {
    els.spinner.classList.toggle("hidden", !on);
    els.enrichBtn.disabled = !!on;
  }

  function safeJson(resp) {
    return resp.text().then(t => {
      if (!t) return null;
      try { return JSON.parse(t); } catch { return { _raw: t }; }
    });
  }

  async function apiFetch(path, opts = {}) {
    const init = {
      method: opts.method || "GET",
      headers: {
        "Accept": "application/json",
        ...(opts.body ? { "Content-Type": "application/json" } : {}),
        ...authHeaders(),
      },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    };
    const resp = await fetch(path, init);
    const data = await safeJson(resp);
    if (resp.status === 401 || resp.status === 403) {
      showAuthBanner(true,
        resp.status === 401
          ? "Authentication required — paste your API token."
          : "Invalid token — try again.");
      const err = new Error("auth");
      err.status = resp.status;
      err.body = data;
      throw err;
    }
    if (!resp.ok) {
      const detail = data && (data.detail || data._raw)
        ? (data.detail || data._raw)
        : ("HTTP " + resp.status);
      const err = new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
      err.status = resp.status;
      err.body = data;
      throw err;
    }
    return data;
  }

  // ---------------------------------------------------------------------
  // Input classification
  // ---------------------------------------------------------------------

  /**
   * Classify the raw input into one of three call modes:
   *   - "single":  one token  → GET /enrich
   *   - "bulk":    few tokens, no prose  → POST /enrich/bulk
   *   - "extract": multi-line / prose-like → POST /extract
   * Returns {mode, tokens, text}.
   */
  function classifyInput(raw) {
    const text = (raw || "").trim();
    if (!text) return { mode: "empty", tokens: [], text: "" };

    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

    const tokens = text
      .split(/[\s,;]+/)
      .map(t => t.trim())
      .filter(Boolean);

    if (tokens.length === 1) return { mode: "single", tokens, text };

    // Prose heuristic: any line has 4+ whitespace-separated words, OR
    // we have 5+ non-empty lines (treat as a blob → /extract).
    const looksLikeProse = lines.some(line => {
      const words = line.split(/\s+/).filter(Boolean);
      return words.length >= 4;
    });

    if (lines.length >= 5 || looksLikeProse) {
      return { mode: "extract", tokens, text };
    }

    return { mode: "bulk", tokens, text };
  }

  // ---------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------

  const SOURCE_SHORT = {
    VirusTotal: "VT",
    AbuseIPDB: "AbuseIPDB",
    Shodan: "Shodan",
    IPQS: "IPQS",
    IPinfo: "IPinfo",
    GreyNoise: "GreyNoise",
    URLhaus: "URLhaus",
    ThreatFox: "ThreatFox",
    MalwareBazaar: "MalwareBazaar",
    OTX: "OTX",
    URLscan: "URLscan",
    WHOIS: "WHOIS",
    Tor: "Tor",
    FileScan: "FileScan",
    HybridAnalysis: "HA",
    JoeSandbox: "Joe",
  };

  function scoreClass(score) {
    const s = Number(score) || 0;
    if (s >= 80) return "score-crit";
    if (s >= 60) return "score-high";
    if (s >= 40) return "score-medium";
    if (s >= 20) return "score-low";
    return "score-safe";
  }

  function riskTier(score) {
    const s = Number(score) || 0;
    if (s >= 80) return "Critical";
    if (s >= 60) return "High";
    if (s >= 40) return "Medium";
    if (s >= 20) return "Low";
    return "Safe";
  }

  function sourcesHit(modules) {
    if (!modules || typeof modules !== "object") return [];
    return Object.keys(modules).map(k => SOURCE_SHORT[k] || k);
  }

  /**
   * Build a DOM element. `children` may be strings (inserted as text nodes)
   * or Nodes. We never accept raw HTML — preventing innerHTML XSS routes.
   */
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === "class") node.className = v;
        else if (k === "dataset") Object.assign(node.dataset, v);
        else if (k.startsWith("on") && typeof v === "function") {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else if (v !== false && v != null) {
          node.setAttribute(k, v);
        }
      }
    }
    for (const c of children) {
      if (c == null || c === false) continue;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return node;
  }

  function renderResults(results, extractedBuckets) {
    clearNode(els.results);
    if (!results || !results.length) {
      els.results.appendChild(el("p", { class: "dim" }, "No enrichable IOCs."));
      return;
    }

    const section = el("section", { class: "results-section" });

    if (extractedBuckets) {
      const totalExtracted = Object.values(extractedBuckets)
        .reduce((acc, arr) => acc + (Array.isArray(arr) ? arr.length : 0), 0);
      const breakdown = Object.entries(extractedBuckets)
        .filter(([, v]) => Array.isArray(v) && v.length)
        .map(([k, v]) => k + "(" + v.length + ")")
        .join(", ");
      section.appendChild(el(
        "div",
        { class: "extracted-summary" },
        "Extracted " + totalExtracted + " IOC(s) from blob: " + breakdown
      ));
    }

    const table = el("table", { class: "results" });
    table.appendChild(el(
      "thead", null,
      el("tr", null,
        el("th", null, "IOC"),
        el("th", null, "Type"),
        el("th", null, "Score"),
        el("th", null, "Risk"),
        el("th", null, "Sources hit"))));
    const tbody = el("tbody");

    results.forEach((r, idx) => {
      const score = Number(r.final_score) || 0;
      const sources = sourcesHit(r.modules);
      const row = el(
        "tr",
        { class: "row", dataset: { idx: String(idx) } },
        el("td", null,
          el("span", { class: "toggle" }, "▸"),
          el("span", { class: "ioc-value" }, r.ioc || "—")),
        el("td", null, el("span", { class: "type-pill" }, r.type || "?")),
        el("td", { class: "score-cell " + scoreClass(score) }, String(score)),
        el("td", { class: "risk-tier " + scoreClass(score) }, riskTier(score)),
        el("td", { class: "sources-hit" }, sources.length ? sources.join(", ") : "—"));

      const detailsRow = el(
        "tr",
        { class: "details hidden", dataset: { idx: String(idx) } },
        el("td", { colspan: "5" }, buildDetails(r)));

      row.addEventListener("click", () => {
        const isHidden = detailsRow.classList.toggle("hidden");
        const toggle = row.querySelector(".toggle");
        if (toggle) toggle.textContent = isHidden ? "▸" : "▾";
      });

      tbody.appendChild(row);
      tbody.appendChild(detailsRow);
    });

    table.appendChild(tbody);
    section.appendChild(table);
    els.results.appendChild(section);
  }

  function buildDetails(r) {
    const wrap = el("div");
    const modules = r.modules || {};
    const keys = Object.keys(modules);
    if (!keys.length) {
      wrap.appendChild(el("span", { class: "dim" }, "No source data."));
      return wrap;
    }
    const dl = el("dl", { class: "modules-dl" });
    for (const k of keys) {
      const v = modules[k];
      dl.appendChild(el("dt", null, k));
      let body;
      try {
        body = JSON.stringify(v, null, 2);
      } catch {
        body = String(v);
      }
      // Body is a plain string — inserted as a text node by el().
      dl.appendChild(el("dd", null, el("pre", null, body)));
    }
    wrap.appendChild(dl);
    return wrap;
  }

  // ---------------------------------------------------------------------
  // Sources panel
  // ---------------------------------------------------------------------

  async function loadSources() {
    try {
      const data = await apiFetch("/sources");
      renderSources(data);
    } catch (e) {
      clearNode(els.sourcesList);
      if (e.status === 401 || e.status === 403) {
        els.sourcesList.appendChild(el("span", { class: "dim" },
          "auth required to list sources"));
        return;
      }
      els.sourcesList.appendChild(el("span", { class: "dim" },
        "failed to load sources: " + (e.message || "error")));
    }
  }

  function renderSources(map) {
    clearNode(els.sourcesList);
    const entries = Object.entries(map || {}).sort(([a], [b]) => a.localeCompare(b));
    if (!entries.length) {
      els.sourcesList.appendChild(el("span", { class: "dim" }, "(none)"));
      return;
    }
    for (const [name, ok] of entries) {
      const marker = el("span",
        { class: "marker " + (ok ? "ok" : "off") },
        ok ? "●" : "○");
      const item = el("span", { class: "source-item" },
        marker,
        el("span", null, name));
      els.sourcesList.appendChild(item);
    }
  }

  // ---------------------------------------------------------------------
  // Enrich flow
  // ---------------------------------------------------------------------

  async function runEnrich() {
    const raw = els.input.value || "";
    const { mode, tokens, text } = classifyInput(raw);
    if (mode === "empty") {
      setStatus("Enter an IOC, a list, or paste a text blob.", true);
      return;
    }
    const defang = !!els.defang.checked;
    setSpinner(true);
    setStatus(
      mode === "single" ? "Enriching 1 IOC…" :
      mode === "bulk"   ? "Enriching " + tokens.length + " IOCs…" :
                          "Extracting IOCs from blob…",
      false
    );
    try {
      let results, extracted;
      if (mode === "single") {
        const r = await apiFetch(
          "/enrich?ioc=" + encodeURIComponent(tokens[0]) +
          "&defang=" + (defang ? "true" : "false"));
        results = [r];
      } else if (mode === "bulk") {
        const r = await apiFetch(
          "/enrich/bulk?defang=" + (defang ? "true" : "false"),
          { method: "POST", body: { iocs: tokens } });
        results = Array.isArray(r) ? r : [];
      } else {
        const r = await apiFetch(
          "/extract?defang=" + (defang ? "true" : "false"),
          { method: "POST", body: { text } });
        results = (r && r.results) || [];
        extracted = (r && r.extracted) || null;
      }
      setStatus(
        "Done — " + results.length + " result" + (results.length === 1 ? "" : "s") + ".",
        false);
      renderResults(results, extracted);
    } catch (e) {
      if (e.status === 401 || e.status === 403) {
        setStatus("Authentication required.", true);
      } else {
        setStatus("Error: " + (e.message || "request failed"), true);
      }
    } finally {
      setSpinner(false);
    }
  }

  // ---------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------

  function readTokenFromQuery() {
    try {
      const params = new URLSearchParams(window.location.search);
      const t = params.get("token");
      if (t) authToken = t;
    } catch { /* noop */ }
  }

  async function probeHealth() {
    // /health is always public; we probe /sources (auth-gated when token
    // is set) so we can show the auth banner up front.
    try {
      const resp = await fetch("/sources", { headers: authHeaders() });
      if (resp.status === 401) {
        showAuthBanner(true, "Authentication required — paste your API token.");
        return false;
      }
      if (resp.status === 403) {
        showAuthBanner(true, "Invalid token — paste a valid one.");
        return false;
      }
      if (resp.ok) {
        showAuthBanner(false);
        const data = await resp.json().catch(() => null);
        if (data) renderSources(data);
        return true;
      }
    } catch { /* network error — leave UI alone */ }
    return true;
  }

  function wireAuthBanner() {
    if (!els.authSubmit) return;
    els.authSubmit.addEventListener("click", () => {
      const v = (els.authInput.value || "").trim();
      if (!v) return;
      authToken = v;
      showAuthBanner(false);
      els.authInput.value = "";
      loadSources();
    });
    els.authInput.addEventListener("keydown", e => {
      if (e.key === "Enter") { e.preventDefault(); els.authSubmit.click(); }
    });
  }

  function init() {
    els.input       = $("ioc-input");
    els.enrichBtn   = $("enrich-btn");
    els.defang      = $("defang-checkbox");
    els.status      = $("status");
    els.statusText  = $("status-text");
    els.spinner     = $("spinner");
    els.results     = $("results");
    els.sourcesList = $("sources-list");
    els.authBanner  = $("auth-banner");
    els.authInput   = $("auth-token-input");
    els.authSubmit  = $("auth-token-submit");

    readTokenFromQuery();
    wireAuthBanner();

    els.enrichBtn.addEventListener("click", runEnrich);
    els.input.addEventListener("keydown", e => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runEnrich();
      }
    });

    probeHealth();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
