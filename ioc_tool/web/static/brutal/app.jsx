// Brutalist — main app shell.

const { useState, useEffect, useMemo, useRef, useCallback } = React;

const SEVERITY = {
  SAFE:     { fg: "#4ade80", glow: "#4ade8044", bg: "#0a0a0a", label: "SAFE" },
  LOW:      { fg: "#60a5fa", glow: "#60a5fa44", bg: "#0a0a0a", label: "LOW" },
  MEDIUM:   { fg: "#fbbf24", glow: "#fbbf2444", bg: "#0a0a0a", label: "MEDIUM" },
  HIGH:     { fg: "#fb923c", glow: "#fb923c44", bg: "#0a0a0a", label: "HIGH" },
  CRITICAL: { fg: "#f43f5e", glow: "#f43f5e44", bg: "#0a0a0a", label: "CRITICAL" }
};

function sevOf(score) {
  return SEVERITY[window.RISK_TIER(score).tier];
}

// ─────────── App root ───────────

function App() {
  const [tab, setTab] = useState("enrich");
  const [helpOpen, setHelpOpen] = useState(false);
  const [defang, setDefang] = useState(false);
  const [density, setDensity] = useState("normal");
  const [llm, setLlm] = useState(false);
  const [sourcesOpen, setSourcesOpen] = useState(false);
  const [results, setResults] = useState([]);
  const [activeIocId, setActiveIocId] = useState(null);
  const [diffPair, setDiffPair] = useState(["ioc_01", "ioc_03"]);
  const [enriching, setEnriching] = useState(false);
  // Pending IOC string for the in-flight enrich call. Drives the skeleton
  // card so the user sees instant feedback instead of the stale active row.
  const [pendingIoc, setPendingIoc] = useState(null);
  const [tweaksOpen, setTweaksOpen] = useState(false);
  const [accent, setAccent] = useState("ember");
  const [patterns, setPatterns] = useState(false);
  const [disabledSources, setDisabledSources] = useState(new Set());

  // Boot screen — show once per session.
  const [booted, setBooted] = useState(() => {
    try { return sessionStorage.getItem("ss_booted") === "1"; } catch (e) { return false; }
  });

  const activeIoc = results.find(r => r.id === activeIocId) || results[0];

  const accentMap = {
    ember: { hex: "#ff6b35" },
    mint:  { hex: "#3ddc97" },
    cyan:  { hex: "#22d3ee" }
  };
  const acc = accentMap[accent];

  useEffect(() => {
    document.documentElement.style.setProperty("--accent", acc.hex);
    document.documentElement.style.setProperty("--row-h", density === "dense" ? "26px" : "32px");
    document.documentElement.style.setProperty("--row-pad", density === "dense" ? "10px" : "14px");
    document.body.classList.toggle("patterns", patterns);
  }, [acc, density, patterns]);

  // Reset disabled sources when navigating to a different IOC
  useEffect(() => { setDisabledSources(new Set()); }, [activeIocId]);

  // Seed the recent strip from real cache on mount. Silent failure —
  // dashboard renders the empty-state prompt and waits for the user to
  // enrich something. We never fall back to demo fixtures here so the
  // UI always reflects actual workspace state.
  useEffect(() => {
    if (!window.shadowscopeRecent) return;
    window.shadowscopeRecent(8)
      .then(rows => {
        if (!Array.isArray(rows) || rows.length === 0) return;
        setResults(rows);
        setActiveIocId(rows[0].id);
      })
      .catch(err => {
        console.warn("[shadowscope] /api/ui/recent failed:", err.message);
      });
  }, []);

  // Clear just the recent strip (UI state). Does NOT touch the SQLite
  // cache — that lives behind the Cache tab's explicit wipe action.
  const clearRecentStrip = () => {
    setResults([]);
    setActiveIocId(null);
  };

  useEffect(() => {
    const handler = (e) => {
      if (e.data?.type === "__activate_edit_mode") setTweaksOpen(true);
      if (e.data?.type === "__deactivate_edit_mode") setTweaksOpen(false);
    };
    window.addEventListener("message", handler);
    window.parent.postMessage({ type: "__edit_mode_available" }, "*");
    return () => window.removeEventListener("message", handler);
  }, []);

  // Pivot — drilling a chip (tag / malware family / registrar). First try
  // to jump to a record already on the strip; otherwise treat the value
  // as a new IOC and enrich it. The backend is the source of truth — we
  // no longer fall back to a demo corpus.
  const onPivot = (kind, value) => {
    const v = String(value).toLowerCase();
    const inStrip = results.find(r => r.id !== activeIocId && r.ioc.toLowerCase() === v);
    if (inStrip) {
      setActiveIocId(inStrip.id);
      setTab("enrich");
      return;
    }
    // Only enrich values that look like IOCs (ip/domain/url/hash/cve).
    // Free-form chips (tag/malware/registrar) have no enrichable form —
    // surface a toast so the click doesn't appear to do nothing.
    const looksEnrichable = /^([\w.-]+\.[a-z]{2,}|\d+\.\d+\.\d+\.\d+|[a-f0-9]{32,}|cve-\d{4}-\d+)$/i.test(value);
    if (looksEnrichable) {
      onEnrich(value);
      return;
    }
    const toast = document.createElement("div");
    toast.className = "pivot-toast";
    toast.textContent = `// "${kind}=${value}" not directly enrichable`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2200);
  };

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "g" && !e.metaKey && !e.ctrlKey && document.activeElement.tagName !== "TEXTAREA" && document.activeElement.tagName !== "INPUT") {
        const second = (e2) => {
          if (e2.key === "b") setTab("batch");
          if (e2.key === "e") setTab("enrich");
          if (e2.key === "w") setTab("watch");
          if (e2.key === "c") setTab("cases");
          if (e2.key === "d") setTab("diff");
          if (e2.key === "k") setTab("cache");
          if (e2.key === "s") setSourcesOpen(v => !v);
          window.removeEventListener("keydown", second);
        };
        window.addEventListener("keydown", second, { once: true });
      }
      if (e.key === "/" && document.activeElement.tagName !== "TEXTAREA") {
        e.preventDefault();
        document.getElementById("ioc-input")?.focus();
      }
      if (e.key === "?" && document.activeElement.tagName !== "TEXTAREA" && document.activeElement.tagName !== "INPUT") {
        e.preventDefault();
        setHelpOpen(v => !v);
      }
      if (e.key === "Escape") { setSourcesOpen(false); setHelpOpen(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const onEnrich = (text) => {
    const value = text.trim();
    if (!value) return;
    setEnriching(true);
    setPendingIoc(value);
    setTab("enrich");

    // Live backend call. The setResults filter dedups by record id
    // AND by raw ioc string so re-enriching the same IOC never creates
    // a duplicate row, even when the backend canonicalises (e.g. CVE
    // uppercase, ASN strip leading zeros) and the local input would
    // otherwise hash to a different key for the same indicator.
    window.shadowscopeFetch(value, { defang, summary: llm })
      .then((record) => {
        setResults(prev => [
          record,
          ...prev.filter(r => r.id !== record.id && r.ioc !== record.ioc && r.ioc !== value),
        ]);
        setActiveIocId(record.id);
      })
      .catch((err) => {
        console.warn("[shadowscope] /api/ui/enrich failed:", err.message);
        // Show a transient toast and leave the strip unchanged. Falling
        // back to fake records would hide real backend / auth problems.
        const toast = document.createElement("div");
        toast.className = "pivot-toast";
        toast.textContent = `// enrich failed: ${err.message.slice(0, 120)}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3500);
      })
      .finally(() => {
        setEnriching(false);
        setPendingIoc(null);
      });
  };

  const fmt = (s) => defang ? window.defangText(s) : s;

  return (
    <div className={`app ${density === "dense" ? "dense" : ""}`}>
      {!booted && <BootScreen onDone={() => { try { sessionStorage.setItem("ss_booted", "1"); } catch (e) {} setBooted(true); }} />}
      <PatternDefs />
      <TopBar tab={tab} setTab={setTab} setSourcesOpen={setSourcesOpen} setHelpOpen={setHelpOpen} />
      <AlertTicker results={results} setActiveIoc={setActiveIocId} setTab={setTab} fmt={fmt} />
      <InputBar onEnrich={onEnrich} defang={defang} setDefang={setDefang} llm={llm} setLlm={setLlm} enriching={enriching} />

      <main className="main">
        {tab === "enrich" && <EnrichView ioc={activeIoc} fmt={fmt} llm={llm} results={results} setResults={setResults} setActiveIocId={setActiveIocId} disabledSources={disabledSources} setDisabledSources={setDisabledSources} onPivot={onPivot} clearRecentStrip={clearRecentStrip} pendingIoc={pendingIoc} />}
        {tab === "batch"  && <BatchView results={results} setActiveIocId={setActiveIocId} setTab={setTab} fmt={fmt} />}
        {tab === "watch"  && <WatchView fmt={fmt} results={results} setResults={setResults} setActiveIocId={setActiveIocId} setTab={setTab} />}
        {tab === "cases"  && <CasesView results={results} fmt={fmt} setActiveIocId={setActiveIocId} setTab={setTab} />}
        {tab === "diff"   && <DiffView results={results} diffPair={diffPair} setDiffPair={setDiffPair} fmt={fmt} />}
        {tab === "cache"  && <CacheView />}
      </main>

      <StatusBar results={results} />

      {sourcesOpen && <SourcesDrawer onClose={() => setSourcesOpen(false)} />}
      {helpOpen && <HelpOverlay onClose={() => setHelpOpen(false)} />}
      {tweaksOpen && <Tweaks accent={accent} setAccent={setAccent} density={density} setDensity={setDensity} patterns={patterns} setPatterns={setPatterns} onClose={() => { setTweaksOpen(false); window.parent.postMessage({ type: "__edit_mode_dismissed" }, "*"); }} />}
    </div>
  );
}

// Live source-status badge — fetches /api/ui/sources once on mount and
// renders the real count (e.g. "SOURCES 10/22 keyed · 12 anon").
function SourcesBadge({ onClick }) {
  const [stats, setStats] = useState(null);
  useEffect(() => {
    const h = {};
    try {
      const tok = sessionStorage.getItem("ss_api_token");
      if (tok) h["Authorization"] = "Bearer " + tok;
    } catch (e) {}
    fetch("/api/ui/sources", { headers: h })
      .then(r => r.ok ? r.json() : null)
      .then(j => j && setStats(j))
      .catch(() => {});
  }, []);
  if (!stats) {
    return (
      <button className="src-btn" onClick={onClick}>
        <span className="src-dot ok" />
        <span>SOURCES …</span>
      </button>
    );
  }
  const operational = stats.ok + (stats.local || 0);
  const missing = stats.no_key || 0;
  return (
    <button className="src-btn" onClick={onClick} title="open sources drawer">
      <span className={`src-dot ${missing > 0 ? "deg" : "ok"}`} />
      <span>SOURCES <b>{operational}</b>/<span className="dim">{stats.total}</span></span>
    </button>
  );
}


// ─────────── Top Bar / tabs ───────────

function HelpOverlay({ onClose }) {
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="help-overlay" onClick={onClose}>
      <div className="help-card" onClick={(e) => e.stopPropagation()}>
        <div className="help-head">
          <span className="help-title">KEYBOARD · SHORTCUTS</span>
          <button className="help-close" onClick={onClose}>ESC</button>
        </div>
        <div className="help-body">
          <div className="help-section">
            <div className="help-section-title">navigate</div>
            {[
              [["g", "e"], "jump to enrich"],
              [["g", "b"], "jump to batch"],
              [["g", "w"], "jump to watch"],
              [["g", "c"], "jump to cases"],
              [["g", "d"], "jump to diff"],
            ].map(([keys, desc]) => (
              <div className="help-row" key={desc}>
                <span className="help-keys">
                  <span className="help-kbd">{keys[0]}</span>
                  <span className="help-then">then</span>
                  <span className="help-kbd">{keys[1]}</span>
                </span>
                <span className="help-desc">{desc}</span>
              </div>
            ))}
          </div>
          <div className="help-section">
            <div className="help-section-title">input</div>
            <div className="help-row">
              <span className="help-keys"><span className="help-kbd">/</span></span>
              <span className="help-desc">focus the IOC input</span>
            </div>
            <div className="help-row">
              <span className="help-keys"><span className="help-kbd">⏎</span></span>
              <span className="help-desc">submit · enrich the current IOC</span>
            </div>
            <div className="help-row">
              <span className="help-keys"><span className="help-kbd">⇧</span><span className="help-then">+</span><span className="help-kbd">⏎</span></span>
              <span className="help-desc">newline (multi-line paste)</span>
            </div>
          </div>
          <div className="help-section">
            <div className="help-section-title">panels</div>
            <div className="help-row">
              <span className="help-keys"><span className="help-kbd">g</span><span className="help-then">then</span><span className="help-kbd">s</span></span>
              <span className="help-desc">toggle sources drawer</span>
            </div>
            <div className="help-row">
              <span className="help-keys"><span className="help-kbd">?</span></span>
              <span className="help-desc">toggle this overlay</span>
            </div>
            <div className="help-row">
              <span className="help-keys"><span className="help-kbd">esc</span></span>
              <span className="help-desc">close any open overlay</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function TopBar({ tab, setTab, setSourcesOpen, setHelpOpen }) {
  const tabs = [
    { id: "enrich", label: "ENRICH", kbd: "g e",
      help: "Single-IOC enrichment. Paste an IP / domain / URL / hash / CVE / ASN — every source queries in parallel and aggregates into the composite score." },
    { id: "batch",  label: "BATCH",  kbd: "g b",
      help: "All IOCs you've enriched this session, sorted highest-score first. Click a row to drill into ENRICH for that IOC." },
    { id: "watch",  label: "WATCH",  kbd: "g w",
      help: "Live alert stream — re-enrich daily and surface deltas. Tied to the `shadowscope watch` CLI; backend wiring lands next." },
    { id: "cases",  label: "CASES",  kbd: "g c",
      help: "Investigation cases — group IOCs by campaign (tag via `shadowscope tag <ioc> --case=name`). Empty until you tag IOCs." },
    { id: "diff",   label: "DIFF",   kbd: "g d",
      help: "Side-by-side compare two IOCs' per-source scores. Spots shared infrastructure across a campaign." },
    { id: "cache",  label: "CACHE",  kbd: "g k",
      help: "Inspect, prune, or wipe the SQLite enrichment cache. Mirrors `shadowscope cache stats|prune|clear`." },
  ];
  return (
    <header className="topbar">
      <div className="brand">
        <BrandMark size={28} />
        <div className="brand-text">
          <div className="brand-row1">
            <span className="brand-name">SHADOWSCOPE</span>
            <span className="brand-ver">v0.9.2</span>
          </div>
          <span className="brand-tag">// indicator of compromise · enrichment</span>
        </div>
      </div>
      <nav className="tabs">
        {tabs.map(t => (
          <button
            key={t.id}
            className={`tab ${tab === t.id ? "on" : ""}`}
            onClick={() => setTab(t.id)}
            title={t.help}
          >
            <span className="tab-label">{t.label}</span>
            <span className="tab-kbd">{t.kbd}</span>
          </button>
        ))}
      </nav>
      <div className="topbar-right">
        <ClockLive />
        <SourcesBadge onClick={() => setSourcesOpen(true)} />
        <button className="help-btn" title="keyboard shortcuts (?)" onClick={() => setHelpOpen(v => !v)}>?</button>
      </div>
    </header>
  );
}

// Brand mark — sniper scope viewfinder with the ◢◤ reticle target inside.
function BrandMark({ size = 24 }) {
  return (
    <svg className="brand-mark" width={size} height={size} viewBox="0 0 28 28" fill="none" aria-hidden="true">
      {/* Outer scope ring (cropped by corners) */}
      <circle cx="14" cy="14" r="10.5" stroke="currentColor" strokeWidth="0.8" strokeOpacity="0.35" fill="none" />
      {/* Corner viewfinder brackets */}
      <path d="M 2 8 L 2 2 L 8 2"   stroke="currentColor" strokeWidth="2" />
      <path d="M 26 8 L 26 2 L 20 2" stroke="currentColor" strokeWidth="2" />
      <path d="M 2 20 L 2 26 L 8 26" stroke="currentColor" strokeWidth="2" />
      <path d="M 26 20 L 26 26 L 20 26" stroke="currentColor" strokeWidth="2" />
      {/* Crosshair edge ticks */}
      <rect x="13.5" y="6"  width="1" height="3" fill="currentColor" />
      <rect x="13.5" y="19" width="1" height="3" fill="currentColor" />
      <rect x="6"  y="13.5" width="3" height="1" fill="currentColor" />
      <rect x="19" y="13.5" width="3" height="1" fill="currentColor" />
      {/* ◢◤ reticle target — original mark, now the scope's center */}
      <polygon points="9,9 14,9 9,14" fill="var(--accent)" />
      <polygon points="19,19 14,19 19,14" fill="var(--accent)" />
      <rect x="13.5" y="13.5" width="1" height="1" fill="currentColor" />
    </svg>
  );
}

function ClockLive() {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  const z = now.toISOString().slice(11, 19);
  return <span className="clock"><span className="dim">UTC</span> {z}</span>;
}

// ─────────── Input Bar ───────────

function InputBar({ onEnrich, defang, setDefang, llm, setLlm, enriching }) {
  const [value, setValue] = useState("");
  const taRef = useRef(null);
  const submit = () => { onEnrich(value); };
  return (
    <div className="inputbar">
      <div className="prompt">▌</div>
      <textarea
        id="ioc-input"
        ref={taRef}
        rows={1}
        value={value}
        placeholder="paste IOC — ip · domain · url · sha256 · cve · email · asn — or a free-text blob"
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
        }}
      />
      <div className="inputbar-controls">
        <label className="chk"><input type="checkbox" checked={defang} onChange={(e) => setDefang(e.target.checked)} /><span>defang</span></label>
        <label className="chk"><input type="checkbox" checked={llm} onChange={(e) => setLlm(e.target.checked)} /><span>LLM verdict</span></label>
        <button className={`enrich-btn ${enriching ? "busy" : ""}`} onClick={submit} disabled={enriching}>
          {enriching ? <><span className="spin" /> ENRICHING…</> : <>ENRICH <span className="dim">⏎</span></>}
        </button>
      </div>
    </div>
  );
}

// ─────────── Status Bar (bottom) ───────────

function StatusBar({ results }) {
  const critical = results.filter(r => r.final_score >= 80).length;
  const high = results.filter(r => r.final_score >= 60 && r.final_score < 80).length;
  return (
    <footer className="statusbar">
      <span className="sb-cell"><span className="sb-key">READY</span> <span className="dim">awaiting input · press /</span></span>
      <span className="sb-cell"><span className="sb-key">ENRICHED</span> {results.length}</span>
      <span className="sb-cell"><span className="sb-key" style={{color: "#f43f5e"}}>CRIT</span> {critical}</span>
      <span className="sb-cell"><span className="sb-key" style={{color: "#fb923c"}}>HIGH</span> {high}</span>
      <span className="sb-cell is-redundant"><span className="sb-key">SOURCES</span> 18 ok · 1 deg · 2 ✕</span>
      <span className="sb-cell right">by <b className="sb-credit">Raizer1996</b></span>
    </footer>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
