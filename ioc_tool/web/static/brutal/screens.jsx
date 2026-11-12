// Cinematic Ops — Batch / Watch / Cases / Diff / Sources / Tweaks views.

function BatchView({ results: stripResults, setResults, setActiveIocId, setTab, fmt }) {
  // The strip only holds the newest few; this tab lists every cached IOC.
  const [cached, setCached] = useState([]);
  React.useEffect(() => {
    let dead = false;
    window.shadowscopeRecent(500).then(rows => { if (!dead && Array.isArray(rows)) setCached(rows); }).catch(() => {});
    return () => { dead = true; };
  }, [stripResults.length]);
  const results = useMemo(() => {
    const byId = new Map(cached.map(r => [r.id, r]));
    stripResults.forEach(r => byId.set(r.id, r));      // live strip rows win
    return Array.from(byId.values());
  }, [cached, stripResults]);
  const [sortKey, setSortKey] = useState("score");
  // ── Paste / drop a list ────────────────────────────────────────────────
  const [addOpen, setAddOpen] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [run, setRun] = useState(null);          // {total, done, failed, degraded, note}
  const cancelRef = React.useRef(false);
  const busy = !!(run && run.done < run.total && !run.stopped);

  const loadFile = (file) => {
    if (!file) return;
    if (file.size > 2000000) { setRun({ total: 0, done: 0, failed: 0, degraded: 0, note: "file too large (max 2 MB)" }); return; }
    const rd = new FileReader();
    rd.onload = () => { setPasteText(String(rd.result || "")); setAddOpen(true); };
    rd.readAsText(file);
  };

  const startRun = async () => {
    if (busy || !pasteText.trim()) return;
    cancelRef.current = false;
    let ex;
    try { ex = await window.shadowscopeExtract(pasteText); }
    catch (e) { setRun({ total: 0, done: 0, failed: 0, degraded: 0, note: String(e.message || e) }); return; }
    const queue = ex.iocs.slice();
    const note = [ex.truncated ? `${ex.truncated} over the 200 limit dropped` : "", ex.skipped ? `${ex.skipped} lines not recognised` : ""].filter(Boolean).join(" · ");
    if (queue.length === 0) { setRun({ total: 0, done: 0, failed: 0, degraded: 0, note: note || "no indicators found in that text" }); return; }
    await runQueue(queue, note);
  };

  // ── Import with details (STIX / CSV with case, tags, notes, verdict) ────
  const [imp, setImp] = useState(null);          // preview from /api/ui/import/preview
  const [impCase, setImpCase] = useState("");
  const [impBusy, setImpBusy] = useState(false);
  const fail = (e) => setRun({ total: 0, done: 0, failed: 0, degraded: 0, note: String(e.message || e) });

  const previewImport = () => {
    if (busy || impBusy || !pasteText.trim()) return;
    setImpBusy(true);
    window.ssApi("POST", "/api/ui/import/preview", { text: pasteText })
      .then(r => { setImp(r); setRun(null); })
      .catch(fail)
      .finally(() => setImpBusy(false));
  };
  const applyImport = async (thenEnrich) => {
    if (!imp || impBusy) return;
    setImpBusy(true);
    let res;
    try { res = await window.ssApi("POST", "/api/ui/import/apply", { rows: imp.rows, case: impCase.trim() || null }); }
    catch (e) { setImpBusy(false); fail(e); return; }
    setImpBusy(false);
    const bits = [`${res.imported} imported (${res.new} new)`, res.cases && `${res.cases} put in a case`, res.tags && `${res.tags} tags`,
      res.notes && `${res.notes} notes`, res.verdicts && `${res.verdicts} verdicts`, res.rejected && `${res.rejected} rejected`].filter(Boolean).join(" · ");
    const rows = imp.rows;
    setImp(null); setImpCase("");
    if (!thenEnrich) {
      setRun({ total: 0, done: 0, failed: 0, degraded: 0, note: bits + " · not looked up yet — find them in SEARCH" });
      setPasteText("");
      return;
    }
    const over = Math.max(0, rows.length - 200);
    await runQueue(rows.slice(0, 200).map(r => ({ value: r.ioc })), bits + (over ? ` · ${over} beyond the first 200 left un-enriched` : ""));
  };

  const runQueue = async (queue, note) => {
    cancelRef.current = false;
    const st = { total: queue.length, done: 0, failed: 0, degraded: 0, note };
    setRun({ ...st });
    // Three at a time: enough to be quick, low enough that per-source rate
    // limits are not tripped by our own fan-out.
    const worker = async () => {
      while (queue.length && !cancelRef.current) {
        const item = queue.shift();
        try {
          const rec = await window.shadowscopeFetch(item.value);
          if (rec.degraded) st.degraded += 1;
          if (setResults) setResults(prev => [rec, ...prev.filter(x => x.id !== rec.id)]);
        } catch (e) { st.failed += 1; }
        st.done += 1;
        setRun({ ...st, stopped: cancelRef.current });
      }
    };
    await Promise.all([worker(), worker(), worker()]);
    setRun({ ...st, total: cancelRef.current ? st.done : st.total, stopped: cancelRef.current });
    if (!cancelRef.current) setPasteText("");
  };

  const exportCsv = (rows) => {
    const esc = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
    const lines = [["ioc", "type", "score", "tier", "flagged", "sources", "degraded", "enriched_at"].join(",")];
    rows.forEach(r => lines.push([r.ioc, r.type, r.final_score, window.RISK_TIER(r.final_score).tier,
      r.agreement.sources_flagged, r.agreement.sources_total, r.degraded ? "yes" : "no", r.enriched_at].map(esc).join(",")));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([lines.join("\r\n")], { type: "text/csv" }));
    a.download = `shadowscope-batch-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const [filterTier, setFilterTier] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [q, setQ] = useState("");

  const sorted = useMemo(() => {
    let r = [...results];
    if (filterTier !== "all") r = r.filter(x => window.RISK_TIER(x.final_score).tier === filterTier);
    if (filterType !== "all") r = r.filter(x => x.type === filterType);
    if (q.trim()) r = r.filter(x => x.ioc.toLowerCase().includes(q.toLowerCase()));
    if (sortKey === "score") r.sort((a, b) => b.final_score - a.final_score);
    if (sortKey === "time") r.sort((a, b) => new Date(b.enriched_at) - new Date(a.enriched_at));
    if (sortKey === "type") r.sort((a, b) => a.type.localeCompare(b.type));
    return r;
  }, [results, sortKey, filterTier, filterType, q]);

  const tiers = ["all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"];
  const types = ["all", "domain", "ip", "url", "sha256", "cve", "asn", "email"];

  return (
    <div className="batch-view">
      <div className="batch-toolbar">
        <span className="bt-title">BATCH · {sorted.length} indicators</span>
        <div className="bt-group">
          <span className="bt-label">filter</span>
          {tiers.map(t => (
            <button key={t} className={`pill ${filterTier === t ? "on" : ""}`} onClick={() => setFilterTier(t)}>
              {t === "all" ? "all" : t}
            </button>
          ))}
        </div>
        <div className="bt-group">
          <span className="bt-label">type</span>
          <select value={filterType} onChange={e => setFilterType(e.target.value)} className="bt-select">
            {types.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="bt-group">
          <span className="bt-label">sort</span>
          <select value={sortKey} onChange={e => setSortKey(e.target.value)} className="bt-select">
            <option value="score">score ↓</option>
            <option value="time">time ↓</option>
            <option value="type">type ↑</option>
          </select>
        </div>
        <input className="bt-search" value={q} onChange={e => setQ(e.target.value)} placeholder="grep ioc…" />
        <button className="btn-outline" onClick={() => exportCsv(sorted)} disabled={sorted.length === 0}>EXPORT .csv</button>
        <button className="btn-outline" onClick={() => setAddOpen(o => !o)} style={{ borderColor: "var(--accent)", color: "var(--accent)" }}>
          {addOpen ? "× CLOSE" : "+ ADD INDICATORS"}
        </button>
      </div>

      {addOpen && (
        <div className="batch-add"
             onDragOver={e => e.preventDefault()}
             onDrop={e => { e.preventDefault(); loadFile(e.dataTransfer.files && e.dataTransfer.files[0]); }}
             style={{ border: "1px dashed var(--line-2)", background: "var(--bg-2)", padding: 12, margin: "8px 0", display: "grid", gap: 8 }}>
          <textarea value={pasteText} onChange={e => setPasteText(e.target.value)} disabled={busy} rows={6} spellCheck={false}
                    placeholder={"paste indicators, one per line — or any text (log lines, an email, a report): IPs, domains, URLs, hashes, CVE ids and AS numbers are picked out.\ndefanged forms like 1[.]2[.]3[.]4 or hxxp:// are fine. you can also drop a .txt / .csv / .log file here."}
                    style={{ width: "100%", background: "var(--bg)", color: "var(--ink)", border: "1px solid var(--line-2)", font: "inherit", padding: 8, resize: "vertical" }} />
          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button className="btn-outline" onClick={startRun} disabled={busy || impBusy || !!imp || !pasteText.trim()}>{busy ? "RUNNING…" : "EXTRACT & ENRICH"}</button>
            <button className="btn-outline" onClick={previewImport} disabled={busy || impBusy || !pasteText.trim()}
                    title="For STIX bundles and CSV files that carry a case, tags, notes or verdicts. Shows what was found before anything is saved.">
              {impBusy && !imp ? "READING…" : "PREVIEW IMPORT"}
            </button>
            {busy && <button className="btn-outline" onClick={() => { cancelRef.current = true; }}>STOP</button>}
            <label className="dim small" style={{ cursor: "pointer" }}>
              or choose a file <input type="file" accept=".txt,.csv,.log,.json,.md,text/*" style={{ display: "none" }} onChange={e => loadFile(e.target.files && e.target.files[0])} />
              <span style={{ textDecoration: "underline" }}>browse</span>
            </label>
            <span className="dim small">enrich: max 200 indicators · 256 KB · already-cached ones cost no quota — import: STIX / CSV / text up to 2 MB</span>
          </div>
          {imp && (() => {
            const withMeta = imp.rows.filter(r => r.case || r.tags.length || r.note || r.verdict).length;
            return (
              <div style={{ border: "1px solid var(--line-2)", padding: 10, display: "grid", gap: 8 }}>
                <div className="small">
                  <b style={{ color: "var(--accent)" }}>{imp.format === "stix" ? "STIX" : imp.format === "csv" ? "CSV" : "PLAIN TEXT"}</b>
                  {" · "}<b>{imp.rows.length}</b> indicators
                  {imp.known ? ` · ${imp.known} already here` : ""}
                  {withMeta ? ` · ${withMeta} with case, tags, notes or verdict` : " · no extra details in this file"}
                  {imp.skipped ? ` · ${imp.skipped} entries not usable` : ""}
                  {imp.truncated ? ` · ${imp.truncated} over the ${imp.rows.length} limit dropped` : ""}
                </div>
                {imp.rows.length > 0 && (
                  <table className="batch-table">
                    <thead><tr><th style={{ width: "8ch" }}>type</th><th>indicator</th><th>case</th><th>tags</th><th>note</th><th>verdict</th><th style={{ width: "8ch" }}></th></tr></thead>
                    <tbody>
                      {imp.rows.slice(0, 8).map(r => (
                        <tr key={r.ioc} className="batch-row" style={{ cursor: "default" }}>
                          <td className="mono dim">{r.type}</td>
                          <td className="bt-ioc">{fmt(r.ioc).length > 48 ? fmt(r.ioc).slice(0, 44) + "…" : fmt(r.ioc)}</td>
                          <td className="small">{r.case || <span className="dim">—</span>}</td>
                          <td className="small">{r.tags.join(", ") || <span className="dim">—</span>}</td>
                          <td className="small" title={r.note || ""}>{r.note ? (r.note.length > 50 ? r.note.slice(0, 48) + "…" : r.note) : <span className="dim">—</span>}</td>
                          <td className="small">{r.verdict ? r.verdict.replace("_", " ") : <span className="dim">—</span>}</td>
                          <td className="dim small">{r.cached ? "here" : "new"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {imp.rows.length > 8 && <div className="dim small">… and {imp.rows.length - 8} more</div>}
                {imp.rows.length > 0 ? (
                  <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <input className="bt-search" style={{ maxWidth: 260 }} maxLength={80} value={impCase} onChange={e => setImpCase(e.target.value)}
                           placeholder="put all into case… (optional)" title="Used for rows that do not name a case themselves. Created if it does not exist." />
                    <button className="btn-outline" onClick={() => applyImport(false)} disabled={impBusy}
                            title="Save indicators and their details locally. Nothing is looked up, no quota used.">IMPORT ONLY · no lookups</button>
                    <button className="btn-outline" onClick={() => applyImport(true)} disabled={impBusy} style={{ borderColor: "var(--accent)", color: "var(--accent)" }}
                            title="Save, then look up the first 200 at the sources">IMPORT + ENRICH{imp.rows.length > 200 ? " first 200" : ""}</button>
                    <button className="btn-outline" onClick={() => setImp(null)} disabled={impBusy}>CANCEL</button>
                  </div>
                ) : (
                  <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <span className="dim small">// nothing usable found in that text</span>
                    <button className="btn-outline" onClick={() => setImp(null)}>CLOSE</button>
                  </div>
                )}
              </div>
            );
          })()}
          {run && (
            <div className="small" role="status">
              {run.total > 0 && (
                <div style={{ height: 6, background: "var(--line)", marginBottom: 4 }}>
                  <div style={{ height: "100%", width: `${Math.round(100 * run.done / run.total)}%`, background: run.failed ? "var(--med)" : "var(--accent)" }} />
                </div>
              )}
              <span>
                {run.total > 0 ? `${run.done}/${run.total} enriched` : ""}
                {run.stopped ? " · stopped" : ""}
                {run.failed ? ` · ${run.failed} failed` : ""}
                {run.degraded ? ` · ${run.degraded} degraded (some sources did not answer)` : ""}
                {run.note ? `${run.total > 0 ? " · " : ""}${run.note}` : ""}
              </span>
            </div>
          )}
        </div>
      )}

      <table className="batch-table">
        <thead>
          <tr>
            <th style={{width: "6ch"}}>score</th>
            <th style={{width: "10ch"}}>tier</th>
            <th style={{width: "8ch"}}>type</th>
            <th>indicator</th>
            <th style={{width: "20ch"}}>sources flagged</th>
            <th style={{width: "16ch"}}>heuristics</th>
            <th style={{width: "10ch"}}>Δ 24h</th>
            <th style={{width: "10ch"}}>enriched</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(r => {
            const s = sevOf(r.final_score);
            const heur = r.modules.Heuristics?.data || {};
            const heurChips = [];
            if (heur.nrd?.age_days < 30) heurChips.push("NRD");
            if (heur.dga?.score >= 60) heurChips.push("DGA");
            if (heur.typosquat) heurChips.push("TYPO");
            if (heur.idn?.mixed_script) heurChips.push("IDN");
            const delta = r.final_score - r.prev_score;
            return (
              <tr key={r.id} className="batch-row" onClick={() => { if (setResults && !stripResults.find(x => x.id === r.id)) setResults(prev => [r, ...prev]); setActiveIocId(r.id); setTab("enrich"); }}>
                <td className="bt-score" style={{color: s.fg, borderLeft: `3px solid ${s.fg}`}}>{r.final_score}</td>
                <td><span className="tier-mini" style={{color: s.fg, borderColor: s.fg + "55"}}>{s.label}</span></td>
                <td className="mono dim">{r.type}</td>
                <td className="bt-ioc"><Copyable text={fmt(r.ioc)}>{fmt(r.ioc).length > 60 ? fmt(r.ioc).slice(0, 56) + "…" : fmt(r.ioc)}</Copyable>{r.degraded && <span title={"no answer from " + Object.keys(r.unavailable || {}).join(", ")} style={{ color: "var(--med)", marginLeft: 6 }}>⚠</span>}</td>
                <td>
                  <span className="agree-bar-mini">
                    {Array.from({length: r.agreement.sources_total}).map((_, i) => (
                      <span key={i} className={i < r.agreement.sources_flagged ? "on" : "off"} />
                    ))}
                  </span>
                  <span className="dim small"> {r.agreement.sources_flagged}/{r.agreement.sources_total}</span>
                </td>
                <td>
                  {heurChips.length === 0 ? <span className="dim">—</span> : heurChips.map(c => <span key={c} className="heur-chip">{c}</span>)}
                </td>
                <td className={delta > 0 ? "delta-up" : delta < 0 ? "delta-dn" : "dim"}>
                  {delta === 0 ? "·" : (delta > 0 ? "↑+" : "↓") + Math.abs(delta)}
                </td>
                <td className="dim small"><Relative iso={r.enriched_at} /></td>
                <td className="bt-arrow">▸</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {sorted.length === 0 && (
        <div className="tab-empty">
          <div className="tab-empty-title">// BATCH is empty</div>
          <div className="tab-empty-desc">
            Every IOC you enrich this session lands here, sorted by score.
            Head back to <button className="tab-empty-link" onClick={() => setTab("enrich")}>ENRICH</button> and paste one in.
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────── Search (everything in the local cache) ───────────

const SEARCH_DEFAULTS = { q: "", type: "", min_score: "", verdict: "", case: "", watched: false, has_notes: false, since_days: "", deep: true, sort: "score" };
const SEARCH_TYPES = ["ip", "domain", "url", "hash", "cve", "asn"];

function searchQueryString(f, extra) {
  const p = new URLSearchParams();
  if (f.q.trim()) p.set("q", f.q.trim());
  if (f.type) p.set("type", f.type);
  if (f.min_score !== "") p.set("min_score", String(f.min_score));
  if (f.verdict) p.set("verdict", f.verdict);
  if (f.case) p.set("case", f.case);
  if (f.watched) p.set("watched", "true");
  if (f.has_notes) p.set("has_notes", "true");
  if (f.since_days !== "") p.set("since_days", String(f.since_days));
  if (!f.deep) p.set("deep", "false");
  if (f.sort && f.sort !== "score") p.set("sort", f.sort);
  Object.entries(extra || {}).forEach(([k, v]) => p.set(k, String(v)));
  return p.toString();
}

function SearchView({ results, setResults, setActiveIocId, setTab, onEnrich, fmt }) {
  const [f, setF] = React.useState(SEARCH_DEFAULTS);
  const [data, setData] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [saved, setSaved] = React.useState([]);
  const [cases, setCases] = React.useState([]);
  const seq = React.useRef(0);
  const PAGE = 100;

  const set = (patch) => setF(prev => ({ ...prev, ...patch }));
  const loadSaved = () => window.ssApi("GET", "/api/ui/filters").then(setSaved).catch(() => {});

  React.useEffect(() => {
    loadSaved();
    window.ssApi("GET", "/api/ui/cases").then(cs => setCases((cs || []).map(c => c.id))).catch(() => {});
  }, []);

  // Re-run on every change; typing is debounced, and a late answer to an
  // older query is dropped so results never flip back.
  React.useEffect(() => {
    const mine = ++seq.current;
    const timer = setTimeout(() => {
      setBusy(true);
      window.ssApi("GET", "/api/ui/search?" + searchQueryString(f, { limit: PAGE }))
        .then(r => { if (mine === seq.current) { setData(r); setErr(null); } })
        .catch(e => { if (mine === seq.current) setErr(String(e.message || e)); })
        .finally(() => { if (mine === seq.current) setBusy(false); });
    }, 250);
    return () => clearTimeout(timer);
  }, [f]);

  const more = () => {
    const mine = seq.current;
    setBusy(true);
    window.ssApi("GET", "/api/ui/search?" + searchQueryString(f, { limit: PAGE, offset: data.rows.length }))
      .then(r => { if (mine === seq.current) setData(d => ({ ...r, rows: d.rows.concat(r.rows) })); })
      .catch(e => setErr(String(e.message || e)))
      .finally(() => setBusy(false));
  };

  const open = (row) => {
    const want = row.ioc.toLowerCase();
    const inStrip = (results || []).find(r => r.ioc.toLowerCase() === want);
    if (inStrip) { setActiveIocId(inStrip.id); setTab("enrich"); return; }
    window.shadowscopePivot("ioc", row.ioc, { limit: 20 })
      .then(rows => {
        const hit = (rows || []).find(r => r.ioc.toLowerCase() === want);
        if (!hit) { onEnrich && onEnrich(row.ioc); return; }
        setResults(prev => [hit, ...prev.filter(x => x.id !== hit.id)]);
        setActiveIocId(hit.id); setTab("enrich");
      })
      .catch(() => { onEnrich && onEnrich(row.ioc); });
  };

  const saveFilter = () => {
    const name = (prompt("Name for this filter:") || "").trim();
    if (!name) return;
    const params = {};
    Object.keys(SEARCH_DEFAULTS).forEach(k => { if (f[k] !== SEARCH_DEFAULTS[k] && f[k] !== "") params[k] = f[k]; });
    window.ssApi("POST", "/api/ui/filters", { name, params }).then(loadSaved).catch(e => setErr(String(e.message || e)));
  };
  const dropFilter = (name) => window.ssApi("DELETE", "/api/ui/filters/" + encodeURIComponent(name)).then(loadSaved).catch(e => setErr(String(e.message || e)));

  const exportCsv = () => {
    const esc = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
    const lines = [["ioc", "type", "score", "tier", "verdict", "case", "watched", "notes", "last_seen", "matched_in"].join(",")];
    data.rows.forEach(r => lines.push([r.ioc, r.type, r.score, r.tier, r.verdict, r.case, r.watched ? "yes" : "no", r.notes, r.last_seen, r.matched.join("; ")].map(esc).join(",")));
    window.ssDownload(`shadowscope-search-${new Date().toISOString().slice(0, 10)}.csv`, lines.join("\r\n"), "text/csv");
  };

  const typesOn = f.type ? f.type.split(",") : [];
  const toggleType = (t) => set({ type: (typesOn.includes(t) ? typesOn.filter(x => x !== t) : typesOn.concat(t)).join(",") });
  const dirty = JSON.stringify(f) !== JSON.stringify(SEARCH_DEFAULTS);
  const rows = data ? data.rows : [];
  const verdictColor = { malicious: "var(--crit, #f43f5e)", suspicious: "var(--med)", benign: "var(--safe)", false_positive: "var(--ink-2)" };

  return (
    <div className="batch">
      <div className="batch-toolbar" style={{ flexWrap: "wrap", rowGap: 8 }}>
        <span className="bt-title">SEARCH · {data ? data.total : "…"} {busy && <span className="dim">· searching</span>}</span>
        <input className="bt-search" autoFocus value={f.q} onChange={e => set({ q: e.target.value })} style={{ flex: "1 1 320px", maxWidth: "none" }}
               placeholder={'search everything — indicator, note, case, tag, malware family, any text a source returned · "exact phrase"'} />
        <button className="btn-outline" onClick={saveFilter} disabled={!dirty} title="Save the current search and filters under a name">SAVE FILTER</button>
        <button className="btn-outline" onClick={exportCsv} disabled={rows.length === 0}>EXPORT .csv</button>
        <button className="btn-outline" onClick={() => setF(SEARCH_DEFAULTS)} disabled={!dirty}>RESET</button>
      </div>
      <div className="batch-toolbar" style={{ flexWrap: "wrap", rowGap: 8, borderTop: "none" }}>
        <div className="bt-group">
          <span className="bt-label">type</span>
          {SEARCH_TYPES.map(t => <button key={t} className={`pill ${typesOn.includes(t) ? "on" : ""}`} onClick={() => toggleType(t)}>{t}</button>)}
        </div>
        <div className="bt-group">
          <span className="bt-label">score ≥</span>
          <select className="bt-select" value={f.min_score} onChange={e => set({ min_score: e.target.value === "" ? "" : Number(e.target.value) })}>
            <option value="">any</option><option value="20">20 · low</option><option value="40">40 · medium</option><option value="60">60 · high</option><option value="80">80 · critical</option>
          </select>
        </div>
        <div className="bt-group">
          <span className="bt-label">verdict</span>
          <select className="bt-select" value={f.verdict} onChange={e => set({ verdict: e.target.value })}>
            <option value="">any</option><option value="any">has a verdict</option><option value="none">no verdict yet</option>
            <option value="malicious">malicious</option><option value="suspicious">suspicious</option><option value="benign">benign</option><option value="false_positive">false positive</option>
          </select>
        </div>
        <div className="bt-group">
          <span className="bt-label">case</span>
          <select className="bt-select" value={f.case} onChange={e => set({ case: e.target.value })}>
            <option value="">any</option><option value="any">in a case</option><option value="none">not in a case</option>
            {cases.concat(f.case && !["any", "none"].includes(f.case) && !cases.includes(f.case) ? [f.case] : []).map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div className="bt-group">
          <span className="bt-label">seen</span>
          <select className="bt-select" value={f.since_days} onChange={e => set({ since_days: e.target.value === "" ? "" : Number(e.target.value) })}>
            <option value="">any time</option><option value="1">last 24 h</option><option value="7">last 7 days</option><option value="30">last 30 days</option>
          </select>
        </div>
        <div className="bt-group">
          <button className={`pill ${f.watched ? "on" : ""}`} onClick={() => set({ watched: !f.watched })}>★ watched</button>
          <button className={`pill ${f.has_notes ? "on" : ""}`} onClick={() => set({ has_notes: !f.has_notes })}>✎ has notes</button>
          <button className={`pill ${f.deep ? "on" : ""}`} onClick={() => set({ deep: !f.deep })}
                  title="On: also search the full text of every cached source answer (finds org names, hostnames, URLs…). Off: only indicators, notes, cases, tags and families — faster on a big cache.">deep</button>
        </div>
        <div className="bt-group">
          <span className="bt-label">sort</span>
          <select className="bt-select" value={f.sort} onChange={e => set({ sort: e.target.value })}>
            <option value="score">score ↓</option><option value="recent">last seen ↓</option><option value="value">indicator a→z</option>
          </select>
        </div>
      </div>
      {saved.length > 0 && (
        <div className="batch-toolbar" style={{ flexWrap: "wrap", rowGap: 6, borderTop: "none" }}>
          <span className="bt-label">saved</span>
          {saved.map(s => (
            <span key={s.name} style={{ display: "inline-flex" }}>
              <button className="pill" title={JSON.stringify(s.params)} onClick={() => setF({ ...SEARCH_DEFAULTS, ...s.params })}>{s.name}</button>
              <button className="pill" title="delete this saved filter" style={{ borderLeft: "none", padding: "0 6px" }} onClick={() => dropFilter(s.name)}>×</button>
            </span>
          ))}
        </div>
      )}
      {err && <div className="small" style={{ color: "var(--bad,#ff7474)", padding: "8px 12px" }}>// {err}</div>}

      <table className="batch-table">
        <thead>
          <tr>
            <th style={{ width: "6ch" }}>score</th><th style={{ width: "10ch" }}>tier</th><th style={{ width: "8ch" }}>type</th>
            <th>indicator</th><th style={{ width: "14ch" }}>verdict</th><th style={{ width: "16ch" }}>case</th>
            <th style={{ width: "8ch" }}>flags</th><th>found in</th><th style={{ width: "12ch" }}>last seen</th><th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => {
            const s = sevOf(r.score || 0);
            const shown = fmt(r.ioc);
            return (
              <tr key={r.ioc} className="batch-row" onClick={() => open(r)}>
                {r.score == null
                  ? <td className="bt-score dim" style={{ borderLeft: "3px solid var(--line-2)" }} title="in cache, no stored score">—</td>
                  : <td className="bt-score" style={{ color: s.fg, borderLeft: `3px solid ${s.fg}` }}>{r.score}</td>}
                <td>{r.tier ? <span className="tier-mini" style={{ color: s.fg, borderColor: s.fg + "55" }}>{s.label}</span> : <span className="dim">—</span>}</td>
                <td className="mono dim">{r.type}</td>
                <td className="bt-ioc"><Copyable text={shown}>{shown.length > 60 ? shown.slice(0, 56) + "…" : shown}</Copyable></td>
                <td className="small" style={{ color: verdictColor[r.verdict] || "var(--ink-3)" }}>{r.verdict ? r.verdict.replace("_", " ") : "—"}</td>
                <td className="small">{r.case || <span className="dim">—</span>}</td>
                <td className="small">{r.watched && <span title="on the watchlist">★ </span>}{r.notes > 0 && <span title={r.notes + " note(s)"}>✎{r.notes}</span>}</td>
                <td className="dim small">{r.matched.join(" · ")}</td>
                <td className="dim small">{r.last_seen ? window.SS_STAMP(String(r.last_seen).replace(" ", "T")) : "—"}</td>
                <td className="bt-arrow">▸</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {data && rows.length < data.total && (
        <div style={{ padding: 10, textAlign: "center" }}>
          <button className="btn-outline" onClick={more} disabled={busy}>SHOW MORE · {rows.length} of {data.total}</button>
        </div>
      )}
      {data && data.total === 0 && (
        <div className="tab-empty">
          <div className="tab-empty-title">// nothing matches</div>
          <div className="tab-empty-desc">
            {dirty ? "Every word has to match somewhere, and all filters apply together. Remove a word or a filter." : "The cache is empty — enrich an indicator first."}
            {f.q.trim() && !f.q.trim().includes(" ") && <React.Fragment> Not looked up yet? <button className="tab-empty-link" onClick={() => onEnrich && onEnrich(f.q.trim())}>ENRICH {f.q.trim()}</button></React.Fragment>}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────── Lists (your own blocklist / allowlist) ───────────

function ListColumn({ name, title, blurb, color, rows, onChange, fmt }) {
  const [pattern, setPattern] = React.useState("");
  const [note, setNote] = React.useState("");
  const [err, setErr] = React.useState(null);
  const add = () => {
    if (!pattern.trim()) return;
    window.ssApi("POST", "/api/ui/lists", { list: name, pattern: pattern.trim(), note: note.trim() || null })
      .then(() => { setPattern(""); setNote(""); setErr(null); onChange(); })
      .catch(e => setErr(String(e.message || e)));
  };
  const remove = (id) => window.ssApi("DELETE", "/api/ui/lists/" + id).then(onChange).catch(e => setErr(String(e.message || e)));
  return (
    <div style={{ border: "1px solid var(--line-2)", background: "var(--bg-2)", padding: 12, minWidth: 0 }}>
      <div className="sec-head"><span className="sec-title" style={{ color }}>{title} · {rows.length}</span></div>
      <div className="dim small" style={{ margin: "4px 0 8px" }}>{blurb}</div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        <input className="bt-search" style={{ flex: "2 1 200px", maxWidth: "none" }} value={pattern} maxLength={2100}
               onChange={e => setPattern(e.target.value)} onKeyDown={e => { if (e.key === "Enter") add(); }}
               placeholder="IP · 203.0.113.0/24 · evil.example · URL · hash · CVE" />
        <input className="bt-search" style={{ flex: "1 1 140px", maxWidth: "none" }} value={note} maxLength={300}
               onChange={e => setNote(e.target.value)} onKeyDown={e => { if (e.key === "Enter") add(); }} placeholder="why (optional)" />
        <button className="btn-outline" onClick={add} disabled={!pattern.trim()}>+ ADD</button>
      </div>
      {err && <div className="small" style={{ color: "var(--bad,#ff7474)", paddingTop: 4 }}>// {err}</div>}
      {rows.length === 0
        ? <div className="dim small" style={{ padding: "10px 0" }}>// empty</div>
        : (
          <table className="batch-table" style={{ marginTop: 8 }}>
            <thead><tr><th style={{ width: "8ch" }}>kind</th><th>entry</th><th>why</th><th style={{ width: "17ch" }}>added</th><th style={{ width: "9ch" }}></th></tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.id} className="batch-row" style={{ cursor: "default" }}>
                  <td className="mono dim">{r.kind}</td>
                  <td className="bt-ioc" title={r.kind === "domain" ? "also covers every subdomain" : ""}>{r.kind === "domain" ? "*." : ""}{fmt(r.pattern)}</td>
                  <td className="small">{r.note || <span className="dim">—</span>}</td>
                  <td className="dim small">{r.created}</td>
                  <td><button className="pill warn" onClick={() => remove(r.id)}>remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
    </div>
  );
}

function ListsView({ fmt }) {
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const load = () => window.ssApi("GET", "/api/ui/lists").then(r => { setRows(r); setErr(null); }).catch(e => { setRows([]); setErr(String(e.message || e)); });
  React.useEffect(() => { load(); }, []);
  const all = rows || [];
  return (
    <div className="batch">
      <div className="batch-toolbar">
        <span className="bt-title">YOUR LISTS · {all.length}</span>
        <span className="dim small">kept on this machine · apply at once, no restart · most specific entry wins, and on a tie the blocklist does</span>
      </div>
      {err && <div className="small" style={{ color: "var(--bad,#ff7474)", padding: "8px 12px" }}>// {err}</div>}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: 12, marginTop: 10 }}>
        <ListColumn name="block" title="BLOCKLIST" color="var(--crit, #f43f5e)" fmt={fmt} onChange={load} rows={all.filter(r => r.list === "block")}
                    blurb="Known bad for you. A match adds a Blocklist source scoring 100, so the indicator reads Critical whatever the public sources say." />
        <ListColumn name="allow" title="ALLOWLIST" color="var(--safe)" fmt={fmt} onChange={load} rows={all.filter(r => r.list === "allow")}
                    blurb="Known good or your own. A match skips every lookup (no quota used) and the indicator scores 0." />
      </div>
    </div>
  );
}

// ─────────── Watch (live stream) ───────────

function WatchlistPanel({ fmt }) {
  const [rows, setRows] = React.useState(null);
  const [ioc, setIoc] = React.useState("");
  const [thr, setThr] = React.useState(20);
  const [busy, setBusy] = React.useState(false);
  const [report, setReport] = React.useState(null);
  const [err, setErr] = React.useState(null);

  const load = React.useCallback(() => {
    window.ssApi("GET", "/api/ui/watchlist").then(r => { setRows(r); }).catch(e => setErr(String(e.message || e)));
  }, []);
  React.useEffect(() => { load(); }, []);

  const add = () => {
    const v = ioc.trim();
    if (!v) return;
    window.ssApi("POST", "/api/ui/watchlist", { ioc: v, threshold: Number(thr) || 20 })
      .then(() => { setIoc(""); setErr(null); load(); })
      .catch(e => setErr(String(e.message || e)));
  };
  const remove = (v) => window.ssApi("DELETE", "/api/ui/watchlist?ioc=" + encodeURIComponent(v)).then(load).catch(e => setErr(String(e.message || e)));
  const setThreshold = (v, t) => window.ssApi("POST", "/api/ui/watchlist", { ioc: v, threshold: t }).then(load).catch(e => setErr(String(e.message || e)));
  const check = () => {
    setBusy(true); setReport(null);
    window.ssApi("POST", "/api/ui/watchlist/check")
      .then(r => { setReport(r); setErr(null); load(); })
      .catch(e => setErr(String(e.message || e)))
      .finally(() => setBusy(false));
  };

  const n = rows ? rows.length : 0;
  return (
    <div style={{ border: "1px solid var(--line-2)", background: "var(--bg-2)", margin: "8px 0", padding: 10 }}>
      <div className="watch-toolbar" style={{ border: "none", padding: 0 }}>
        <span className="bt-title">WATCHLIST · {n}</span>
        <input className="bt-search" style={{ maxWidth: 320 }} value={ioc} onChange={e => setIoc(e.target.value)}
               onKeyDown={e => { if (e.key === "Enter") add(); }} placeholder="add an enriched indicator…" />
        <span className="dim small">alert at Δ ≥</span>
        <input type="number" min="1" max="100" value={thr} onChange={e => setThr(e.target.value)} className="bt-search" style={{ width: 64 }} />
        <button className="btn-outline" onClick={add} disabled={!ioc.trim()}>+ WATCH</button>
        <button className="btn-outline" onClick={check} disabled={busy || n === 0}
                title="Fetch every watched indicator fresh, one at a time, and report score changes">
          {busy ? "CHECKING…" : "CHECK NOW"}
        </button>
      </div>
      {err && <div className="small" style={{ color: "var(--bad,#ff7474)", padding: "4px 0" }}>// {err}</div>}
      {report && (
        <div className="small" style={{ padding: "6px 0" }}>
          checked {report.checked}/{report.watched}
          {report.alerts.length === 0 ? " · no score moved past its threshold" : ""}
          {report.alerts.map(a => (
            <div key={a.ioc} style={{ color: a.delta > 0 ? "var(--high)" : "var(--safe)" }}>
              ▲ {fmt ? fmt(a.ioc) : a.ioc}: {a.previous} → {a.score} ({a.delta > 0 ? "+" : ""}{a.delta}, threshold {a.threshold}) · {a.tier}
            </div>
          ))}
          {report.degraded.map(d => (
            <div key={d.ioc} style={{ color: "var(--med)" }}>
              ⚠ {fmt ? fmt(d.ioc) : d.ioc}: not compared — no answer from {Object.keys(d.unavailable || {}).join(", ")}
            </div>
          ))}
        </div>
      )}
      {rows && n === 0 && <div className="dim small" style={{ padding: "6px 0" }}>// nothing watched yet — add one here or press ☆ WATCH on an indicator in the Enrich tab</div>}
      {n > 0 && (
        <table className="batch-table" style={{ marginTop: 6 }}>
          <thead><tr><th style={{ width: "6ch" }}>score</th><th style={{ width: "8ch" }}>type</th><th>indicator</th><th>alert at Δ ≥</th><th>last check</th><th>last Δ</th><th></th></tr></thead>
          <tbody>
            {rows.map(r => {
              const s = sevOf(r.score || 0);
              return (
                <tr key={r.value} className="batch-row" style={{ cursor: "default" }}>
                  <td className="bt-score" style={{ color: s.fg, borderLeft: `3px solid ${s.fg}` }}>{r.score ?? "—"}</td>
                  <td className="mono dim">{r.type}</td>
                  <td className="bt-ioc">{fmt ? fmt(r.value) : r.value}</td>
                  <td>
                    <select className="bt-select" value={r.threshold} onChange={e => setThreshold(r.value, Number(e.target.value))}>
                      {[5, 10, 20, 30, 50].concat([5, 10, 20, 30, 50].includes(r.threshold) ? [] : [r.threshold]).sort((a, b) => a - b).map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </td>
                  <td className="dim small">{r.last_checked ? window.SS_STAMP(String(r.last_checked).replace(" ", "T")) : "never"}</td>
                  <td className="small">{r.last_delta == null ? "—" : (r.last_delta > 0 ? "+" : "") + r.last_delta}</td>
                  <td><button className="pill warn" onClick={() => remove(r.value)}>remove</button></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function WatchView({ fmt, setActiveIocId, setTab, setResults, results }) {
  // Cache-wide history — every IOC ever enriched, newest first. Seeded
  // from /api/ui/recent (limit bumped to 500 server-side for this view)
  // then kept fresh via the /api/ui/events SSE stream. A slow 60 s
  // fallback poll covers proxies that strip SSE (chunked transfer
  // disabled). Pause halts re-enrichment refreshes; filter "big"
  // surfaces only |Δ| ≥ 20.
  const [feed, setFeed] = React.useState([]);
  const [paused, setPaused] = React.useState(false);
  const [filter, setFilter] = React.useState("all");
  const [err, setErr] = React.useState(null);
  const [loadedAt, setLoadedAt] = React.useState(null);
  const [sseConnected, setSseConnected] = React.useState(false);

  const reload = React.useCallback(() => {
    if (!window.shadowscopeRecent) return;
    window.shadowscopeRecent(200)
      .then(rows => {
        setFeed(rows || []);
        setLoadedAt(new Date());
        setErr(null);
      })
      .catch(e => setErr(String(e.message || e)));
  }, []);

  React.useEffect(() => { reload(); }, [reload]);

  // SSE wiring — push-based updates replace the 8 s poll. On each
  // `score` event we re-pull /api/ui/recent so the row payload
  // (modules, agreement, geo) is the same shape the rest of the UI
  // expects. Cheap: the cache hit returns instantly. Closed on
  // unmount; the helper handles auto-reconnect with exponential
  // backoff capped at 30 s.
  React.useEffect(() => {
    if (paused) return;
    if (!window.shadowscopeSubscribeEvents) return;
    const handle = window.shadowscopeSubscribeEvents(
      (_score) => { reload(); },
      (_hello) => {
        setSseConnected(true);
        // eslint-disable-next-line no-console
        console.log("[shadowscope] SSE connected:", _hello);
      },
      (_err) => { setSseConnected(false); },
    );
    return () => { try { handle && handle.close(); } catch (e) {} };
  }, [paused, reload]);

  // Safety-net poll — slow (60 s) so we hardly ever hit it under
  // healthy SSE, but covers the case where a reverse proxy buffers
  // event-stream responses or kills the connection silently.
  React.useEffect(() => {
    if (paused) return;
    const t = setInterval(reload, 60000);
    return () => clearInterval(t);
  }, [paused, reload]);

  // Derive ticker-shape rows from the brutalist UI shape. Delta from
  // prev_score → final_score; "reason" synthesises a one-liner from
  // the agreement summary + dominant flagging source.
  const toEvent = (r) => {
    const ts = window.SS_STAMP(r.enriched_at);
    const delta = r.final_score - (r.prev_score ?? r.final_score);
    const top = Object.entries(r.modules || {})
      .filter(([_, m]) => (m.score || 0) > 0)
      .sort((a, b) => (b[1].score || 0) - (a[1].score || 0))[0];
    const reason = top
      ? `${top[0]} ${top[1].score} · ${r.agreement?.consensus || "?"}`
      : (r.agreement?.consensus || "no signal");
    return { id: r.id, ts, ioc: r.ioc, type: r.type, score: r.final_score, delta, reason };
  };
  const events = feed.map(toEvent);
  const filtered = filter === "all" ? events : events.filter(e => Math.abs(e.delta) >= 20);

  const onClick = (e) => {
    // Add to strip if not there, then navigate to Enrich tab.
    const target = feed.find(r => r.id === e.id);
    if (target && setResults && !results.find(x => x.id === e.id)) {
      setResults(prev => [target, ...prev.filter(x => x.id !== e.id)]);
    }
    if (setActiveIocId) setActiveIocId(e.id);
    if (setTab) setTab("enrich");
  };

  return (
    <div className="watch-view">
      <div className="watch-toolbar">
        <span className="bt-title">HISTORY · every enrichment</span>
        <div className="bt-group">
          <button className={`pill ${filter === "all" ? "on" : ""}`} onClick={() => setFilter("all")}>all</button>
          <button className={`pill ${filter === "big" ? "on" : ""}`} onClick={() => setFilter("big")}>|Δ| ≥ 20</button>
        </div>
        <div className="bt-group">
          <button className={`pill ${paused ? "" : "on"}`} onClick={() => setPaused(false)}>● LIVE</button>
          <button className={`pill ${paused ? "on" : ""}`} onClick={() => setPaused(true)}>⏸ PAUSE</button>
          <button className="pill" onClick={reload}>refresh</button>
        </div>
        <span className="dim small">
          {feed.length} cached IOC{feed.length !== 1 ? "s" : ""} · {sseConnected ? "SSE" : "poll"}
          {loadedAt && ` · ${loadedAt.toTimeString().slice(0, 8)}`}
        </span>
      </div>
      <WatchlistPanel fmt={fmt} />
      {err && <div className="dim small" style={{ padding: 12, color: "var(--bad,#ff7474)" }}>// {err}</div>}
      {!err && filtered.length === 0 && (
        <div className="dim small" style={{ padding: 12 }}>
          // {feed.length === 0 ? "no enrichments cached yet — start enriching some IOCs" : "no rows match the current filter"}
        </div>
      )}
      <div className="watch-stream">
        {filtered.map((e, i) => {
          const s = sevOf(e.score);
          const up = e.delta > 0;
          return (
            <div key={`${e.id}-${i}`} className="watch-row" onClick={() => onClick(e)} style={{ cursor: "pointer" }}>
              <span className="w-ts dim">{e.ts}</span>
              <span className="w-score" style={{color: s.fg}}>{String(e.score).padStart(3, " ")}</span>
              <span className="w-tier" style={{color: s.fg, borderColor: s.fg + "55"}}>{s.label.slice(0,4)}</span>
              <span className="w-type dim">{(e.type || "").padEnd(6, " ")}</span>
              <span className="w-ioc"><Copyable text={fmt(e.ioc)}>{fmt(e.ioc)}</Copyable></span>
              <span className={`w-delta ${up ? "up" : e.delta < 0 ? "dn" : "zero"}`}>
                {e.delta === 0 ? " ·  " : (up ? "↑+" : "↓") + String(Math.abs(e.delta)).padStart(2, " ")}
              </span>
              <span className="w-reason dim">// {e.reason}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────── Cases (campaign grouping) ───────────

function NewCaseForm({ onCreated }) {
  const [name, setName] = React.useState("");
  const [err, setErr] = React.useState(null);
  const create = () => {
    const n = name.trim();
    if (!n) return;
    window.ssApi("POST", "/api/ui/cases", { name: n })
      .then(() => { setName(""); setErr(null); onCreated(n); })
      .catch(e => setErr(String(e.message || e)));
  };
  return (
    <div style={{ display: "flex", gap: 6, padding: "6px 0", flexWrap: "wrap" }}>
      <input value={name} onChange={e => setName(e.target.value)} onKeyDown={e => { if (e.key === "Enter") create(); }}
             maxLength={80} placeholder="new case name" className="bt-search" style={{ flex: 1, minWidth: 120 }} />
      <button className="btn-outline" onClick={create} disabled={!name.trim()}>+ CASE</button>
      {err && <span className="small" style={{ color: "var(--bad,#ff7474)" }}>// {err}</span>}
    </div>
  );
}

function CasesView({ results, fmt, setActiveIocId, setTab }) {
  // Cases load from /api/ui/cases — no more hardcoded fixtures. Each
  // case carries its IOC values (strings); we resolve them against the
  // recent strip OR enrich on click so panels can render.
  const [cases, setCases] = React.useState([]);
  const [openId, setOpenId] = React.useState(null);
  const [err, setErr] = React.useState(null);

  const reload = React.useCallback(() => {
    if (!window.shadowscopeCases) return;
    window.shadowscopeCases()
      .then(rows => {
        setCases(rows || []);
        if (rows && rows.length && !rows.find(c => c.id === openId)) {
          setOpenId(rows[0].id);
        }
      })
      .catch(e => setErr(String(e.message || e)));
  }, [openId]);

  React.useEffect(() => { reload(); }, []);

  const open = cases.find(c => c.id === openId);

  if (err) {
    return (
      <div className="cases-view">
        <div className="dim small" style={{ padding: 20 }}>// failed to load cases: {err}</div>
      </div>
    );
  }
  if (cases.length === 0) {
    return (
      <div className="cases-view">
        <div style={{ padding: 20, maxWidth: 520 }}>
          <div className="dim small">// no cases yet — create one here, then assign indicators to it from the Enrich tab</div>
          <NewCaseForm onCreated={(n) => { setOpenId(n); reload(); }} />
        </div>
      </div>
    );
  }
  if (!open) return null;

  // Resolve members against the visible strip first; show plain rows
  // for cache-only members that haven't been re-enriched this session.
  const openMembers = open.iocs.map(value => {
    const hit = results.find(r => r.ioc === value);
    return { value, record: hit || null };
  });

  const caseAction = (body, nextId) => {
    window.ssApi("PATCH", "/api/ui/cases/" + encodeURIComponent(open.id), body)
      .then(() => { if (nextId) setOpenId(nextId); reload(); })
      .catch(e => alert(String(e.message || e)));
  };
  const exportCase = (format) => {
    window.ssReport("/api/ui/cases/" + encodeURIComponent(open.id) + "/report", format)
      .catch(e => alert(String(e.message || e)));
  };

  const deleteCase = () => {
    if (!confirm(`Detach every IOC from case "${open.label}"? The IOCs themselves stay in cache.`)) return;
    window.shadowscopeDeleteCase(open.id)
      .then(() => reload())
      .catch(e => setErr(String(e.message || e)));
  };

  return (
    <div className="cases-view">
      <aside className="case-list">
        <div className="sec-head"><span className="sec-title">CASES · {cases.length}</span></div>
        <NewCaseForm onCreated={(n) => { setOpenId(n); reload(); }} />
        {cases.map(c => {
          const s = sevOf(c.severity);
          return (
            <button key={c.id} className={`case-card ${c.id === openId ? "on" : ""}`} onClick={() => setOpenId(c.id)} style={{ borderLeft: `3px solid ${s.fg}` }}>
              <div className="case-card-top">
                <span className="case-sev" style={{color: s.fg}}>{c.severity}</span>
                <span className="case-iocs dim">{c.ioc_count} IOC</span>
              </div>
              <div className="case-label">{c.label}{c.status === "closed" && <span className="dim small"> · closed</span>}</div>
              <div className="case-meta dim small">opened {c.opened || "—"}</div>
            </button>
          );
        })}
      </aside>
      <section className="case-detail">
        <header className="case-detail-head">
          <div>
            <span className="hero-type">CASE</span>
            <span className="case-detail-title">{open.label}</span>
          </div>
          <div className="case-detail-meta">
            <span className="dim">opened</span> {open.opened || "—"}
            <span className="dim"> · max member score</span>{" "}
            <b style={{color: sevOf(open.severity).fg}}>{open.severity}</b>
            <span className="dim"> · </span><b>{open.status === "closed" ? "closed" : "open"}</b>
            <button className="pill" style={{ marginLeft: 12 }} onClick={() => caseAction({ status: open.status === "closed" ? "open" : "closed" })}>
              {open.status === "closed" ? "reopen" : "close case"}
            </button>
            <button className="pill" onClick={() => { const n = prompt("New name for this case:", open.label); if (n && n.trim() && n.trim() !== open.label) caseAction({ rename: n.trim() }, n.trim()); }}>rename</button>
            <button className="pill" onClick={() => { const d = prompt("Case description:", open.description || ""); if (d !== null) caseAction({ description: d }); }}>describe</button>
            <button className="pill" title="Download a Markdown report of this case" onClick={() => exportCase("md")}>report .md</button>
            <button className="pill" title="Open a printable page — use its button, then choose Save as PDF" onClick={() => exportCase("html")}>print / pdf</button>
            <button className="pill warn" onClick={deleteCase}>delete case</button>
          </div>
        </header>
        {open.description && <div className="small" style={{ padding: "6px 14px", whiteSpace: "pre-wrap" }}>{open.description}</div>}
        {open.iocs.length === 0 && <div className="dim small" style={{ padding: 14 }}>// empty case — open an indicator in the Enrich tab and type this case name into its CASE box</div>}
        <table className="batch-table">
          <thead><tr><th>score</th><th>type</th><th>indicator</th><th>flagged</th><th></th></tr></thead>
          <tbody>
            {openMembers.map(({ value, record }) => {
              if (record) {
                const s = sevOf(record.final_score);
                return (
                  <tr key={value} className="batch-row" onClick={() => { setActiveIocId(record.id); setTab("enrich"); }}>
                    <td className="bt-score" style={{color: s.fg, borderLeft: `3px solid ${s.fg}`}}>{record.final_score}</td>
                    <td className="mono dim">{record.type}</td>
                    <td className="bt-ioc">{fmt(record.ioc)}</td>
                    <td className="dim small">{record.agreement.sources_flagged}/{record.agreement.sources_total} · {record.agreement.consensus}</td>
                    <td className="bt-arrow">▸</td>
                  </tr>
                );
              }
              // Cached but not on the strip — render as a plain row
              // with a hint that clicking enriches.
              return (
                <tr key={value} className="batch-row dim" title="not on recent strip — click to enrich">
                  <td className="bt-score" style={{ borderLeft: "3px solid var(--line)" }}>—</td>
                  <td className="mono dim">cached</td>
                  <td className="bt-ioc">{fmt(value)}</td>
                  <td className="dim small">// re-enrich to show details</td>
                  <td className="bt-arrow">▸</td>
                </tr>
              );
            })}
          </tbody>
        </table>

        <CaseGraph iocs={openMembers.map(m => m.record).filter(Boolean)} />
      </section>
    </div>
  );
}

function CaseGraph({ iocs }) {
  // Simple force-graph-ish static layout connecting IOCs to shared sources.
  const sources = ["VirusTotal", "URLhaus", "Pulsedive", "ThreatFox", "WHOIS", "Heuristics"];
  const w = 720, h = 320;
  const iocPos = iocs.map((r, i) => ({ id: r.id, ioc: r.ioc, score: r.final_score, x: 100, y: 60 + i * (200 / Math.max(1, iocs.length - 1 || 1)) }));
  const srcPos = sources.map((s, i) => ({ id: s, x: w - 100, y: 30 + i * ((h - 60) / (sources.length - 1)) }));
  const edges = [];
  iocs.forEach((r, i) => {
    sources.forEach(s => {
      const mod = r.modules[s];
      if (mod && mod.score > 0) edges.push({ from: iocPos[i], to: srcPos.find(x => x.id === s), score: mod.score });
    });
  });
  return (
    <div className="graph-panel">
      <div className="sec-head"><span className="sec-title glitch" data-text="SHARED INFRASTRUCTURE GRAPH">SHARED INFRASTRUCTURE GRAPH</span><span className="sec-meta dim">IOC ↔ source bipartite · edge = positive score</span></div>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h}>
        {edges.map((e, i) => (
          <line key={i} x1={e.from.x} y1={e.from.y} x2={e.to.x} y2={e.to.y}
            stroke={sevOf(e.score).fg} strokeOpacity="0.25" strokeWidth="1" />
        ))}
        {iocPos.map(p => {
          const s = sevOf(p.score);
          return (
            <g key={p.id}>
              <circle cx={p.x} cy={p.y} r="8" fill={s.fg} fillOpacity="0.2" stroke={s.fg} />
              <text x={p.x - 14} y={p.y + 4} textAnchor="end" fill="#cbd0d6" fontFamily="JetBrains Mono" fontSize="11">{p.ioc.length > 22 ? p.ioc.slice(0,20)+"…" : p.ioc}</text>
            </g>
          );
        })}
        {srcPos.map(p => (
          <g key={p.id}>
            <rect x={p.x - 6} y={p.y - 6} width="12" height="12" fill="#0e131a" stroke="var(--accent)" />
            <text x={p.x + 12} y={p.y + 4} fill="#8a929b" fontFamily="JetBrains Mono" fontSize="11">{p.id}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}

// ─────────── Diff ───────────

function DiffView({ results, diffPair, setDiffPair, fmt }) {
  const a = results.find(r => r.id === diffPair[0]) || results[0];
  const b = results.find(r => r.id === diffPair[1] && r !== a) || results.find(r => r !== a);
  if (!a || !b) {
    return (
      <div className="diff-view">
        <div className="batch-toolbar">
          <span className="bt-title">DIFF · side-by-side</span>
          <span className="dim small">// need two enriched IOCs to compare — enrich another one</span>
        </div>
      </div>
    );
  }
  const allSources = Array.from(new Set([...Object.keys(a.modules), ...Object.keys(b.modules)]));
  return (
    <div className="diff-view">
      <div className="batch-toolbar">
        <span className="bt-title">DIFF · side-by-side</span>
        <div className="bt-group">
          <span className="bt-label">left</span>
          <select className="bt-select" value={a.id} onChange={e => setDiffPair([e.target.value, b.id])}>
            {results.map(r => <option key={r.id} value={r.id}>{r.ioc}</option>)}
          </select>
        </div>
        <div className="bt-group">
          <span className="bt-label">right</span>
          <select className="bt-select" value={b.id} onChange={e => setDiffPair([a.id, e.target.value])}>
            {results.map(r => <option key={r.id} value={r.id}>{r.ioc}</option>)}
          </select>
        </div>
        <span className="dim small">// look for shared infrastructure & matching evidence</span>
      </div>

      <div className="diff-heads">
        <DiffHead r={a} fmt={fmt} side="L" />
        <div className="diff-vs">VS</div>
        <DiffHead r={b} fmt={fmt} side="R" />
      </div>

      <table className="diff-table">
        <thead><tr>
          <th>source</th>
          <th className="r diff-h-ioc" title={a.ioc}>
            <span className="diff-h-side">L</span>{fmt(a.ioc).length > 22 ? fmt(a.ioc).slice(0, 20) + "…" : fmt(a.ioc)}
          </th>
          <th className="ctr">Δ</th>
          <th className="l diff-h-ioc" title={b.ioc}>
            {fmt(b.ioc).length > 22 ? fmt(b.ioc).slice(0, 20) + "…" : fmt(b.ioc)}<span className="diff-h-side r">R</span>
          </th>
          <th>verdict</th>
        </tr></thead>
        <tbody>
          {allSources.map(src => {
            const av = a.modules[src]?.score ?? null;
            const bv = b.modules[src]?.score ?? null;
            const delta = (av ?? 0) - (bv ?? 0);
            return (
              <tr key={src}>
                <td className="src-name">{src}</td>
                <td className="r" style={{color: av != null ? sevOf(av).fg : "#555"}}>{av ?? "—"}</td>
                <td className="ctr"><span className={`delta-pill ${delta === 0 ? "zero" : delta > 0 ? "pos" : "neg"}`}>{delta === 0 ? "·" : (delta > 0 ? "+" : "−") + Math.abs(delta)}</span></td>
                <td className="l" style={{color: bv != null ? sevOf(bv).fg : "#555"}}>{bv ?? "—"}</td>
                <td className="dim small">{Math.abs(delta) < 10 ? "agree" : Math.abs(delta) < 30 ? "minor divergence" : "diverge — investigate"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DiffHead({ r, fmt, side }) {
  const s = sevOf(r.final_score);
  return (
    <div className="diff-head" style={{borderColor: s.fg + "44"}}>
      <div className="dh-tag">{side}</div>
      <div className="dh-score" style={{color: s.fg, textShadow: `0 0 12px ${s.glow}`}}>{r.final_score}</div>
      <div className="dh-ioc">{fmt(r.ioc)}</div>
      <div className="dh-meta dim small">{r.type} · {r.agreement.sources_flagged}/{r.agreement.sources_total} flagged · {r.agreement.consensus}</div>
    </div>
  );
}

// ─────────── Sources Drawer ───────────

function UsageMeter() {
  const [data, setData] = React.useState(null);
  React.useEffect(() => {
    let live = true;
    window.ssApi("GET", "/api/ui/usage").then(r => { if (live) setData(r); }).catch(() => { if (live) setData({ sources: [], failed: true }); });
    return () => { live = false; };
  }, []);
  if (!data) return null;
  const rows = data.sources.filter(s => s.quota || s.today || s.week || s.month || s.held_today);
  const tone = (pct) => pct >= 90 ? "var(--crit, #f43f5e)" : pct >= 70 ? "var(--med)" : "var(--safe)";
  return (
    <div className="drawer-group">
      <div className="drawer-group-head">
        <span>USAGE</span>
        <span className="dim small">· requests sent by this install · day resets 00:00 UTC</span>
      </div>
      <div style={{ padding: "2px 16px 8px" }}>
      {data.failed && <div className="dim small" style={{ padding: "4px 0" }}>// could not load usage</div>}
      {data.enabled === false && <div className="dim small" style={{ padding: "4px 0" }}>// counting is switched off (SHADOWSCOPE_USAGE=0)</div>}
      {!data.failed && rows.length === 0 && <div className="dim small" style={{ padding: "4px 0" }}>// nothing sent yet — counts start with the next lookup</div>}
      {rows.map(s => {
        const q = s.quota;
        return (
          <div key={s.source} style={{ padding: "5px 0", borderBottom: "1px solid var(--line)", fontFamily: "var(--mono)", fontSize: 11.5 }}>
            <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
              <b style={{ minWidth: "13ch" }}>{s.source}</b>
              <span>today <b>{s.today}</b></span>
              <span className="dim">7d {s.week}</span>
              <span className="dim">month {s.month}</span>
              {s.limited_today > 0 && <span style={{ color: "var(--crit, #f43f5e)" }} title="the source answered 429 Too Many Requests">⚠ {s.limited_today} refused (429)</span>}
              {s.failed_today > 0 && <span style={{ color: "var(--med)" }} title="timeouts, connection errors, 5xx or key rejected">{s.failed_today} failed</span>}
              {s.held_today > 0 && <span className="dim" title="held back by ShadowScope's own rate limiter — never sent, costs no quota">{s.held_today} held back</span>}
              {q && <span style={{ marginLeft: "auto", color: tone(q.pct) }}>{q.left} left of {q.limit}/{q.period}{q.assumed ? "*" : ""}</span>}
            </div>
            {q && (
              <div style={{ height: 4, background: "var(--line)", marginTop: 3 }} title={`${q.used} of ${q.limit} this ${q.period}`}>
                <div style={{ height: "100%", width: q.pct + "%", background: tone(q.pct) }} />
              </div>
            )}
          </div>
        );
      })}
      {rows.some(s => s.quota && s.quota.assumed) && (
        <div className="dim small" style={{ padding: "6px 0" }}>
          * assumed free-tier limit. On a different plan? set e.g. SHADOWSCOPE_QUOTAS=virustotal=1000/day,shodan=100/month in .env.
          Counts only what this install sent — other tools using the same key are not seen.
        </div>
      )}
      </div>
    </div>
  );
}

function SourcesDrawer({ onClose }) {
  const [sources, setSources] = React.useState(null);
  const [err, setErr] = React.useState(null);

  React.useEffect(() => {
    let cancelled = false;
    const headers = {};
    try {
      const tok = sessionStorage.getItem("ss_api_token");
      if (tok) headers["Authorization"] = "Bearer " + tok;
    } catch (e) {}
    fetch("/api/ui/sources", { headers })
      .then(r => r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)))
      .then(j => { if (!cancelled) setSources(j); })
      .catch(e => { if (!cancelled) setErr(e.message); });
    return () => { cancelled = true; };
  }, []);

  if (err) {
    return (
      <div className="drawer-scrim" onClick={onClose}>
        <aside className="drawer" onClick={e => e.stopPropagation()}>
          <header className="drawer-head">
            <span className="sec-title glitch" data-text="SOURCES">SOURCES</span>
            <button className="drawer-close" onClick={onClose}>✕  esc</button>
          </header>
          <div className="drawer-body" style={{ padding: "16px" }}>
            <div className="dim">failed to load source status: {err}</div>
          </div>
        </aside>
      </div>
    );
  }

  if (!sources) {
    return (
      <div className="drawer-scrim" onClick={onClose}>
        <aside className="drawer" onClick={e => e.stopPropagation()}>
          <header className="drawer-head">
            <span className="sec-title glitch" data-text="SOURCES · loading…">SOURCES · loading…</span>
            <button className="drawer-close" onClick={onClose}>✕  esc</button>
          </header>
        </aside>
      </div>
    );
  }

  const list = sources.sources || [];
  const grouped = {
    ok: list.filter(s => s.status === "ok"),
    local: list.filter(s => s.status === "local"),
    anonymous: list.filter(s => s.status === "anonymous"),
    no_key: list.filter(s => s.status === "no_key"),
  };
  const dotClass = (status) =>
    status === "ok" ? "ok" :
    status === "local" ? "ok" :
    status === "anonymous" ? "anon" :
    "nokey";

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <aside className="drawer" onClick={e => e.stopPropagation()}>
        <header className="drawer-head">
          <span className="sec-title">SOURCES · {sources.total} configured</span>
          <button className="drawer-close" onClick={onClose}>✕  esc</button>
        </header>
        <div className="drawer-summary">
          <div className="drawer-legend">
            <div><span className="src-dot ok" /> <b>{grouped.ok.length + grouped.local.length}</b> operational (key + local)</div>
            <div><span className="src-dot anon" /> <b>{grouped.anonymous.length}</b> anonymous (no key required)</div>
            <div><span className="src-dot nokey" /> <b>{grouped.no_key.length}</b> missing key</div>
          </div>
        </div>
        <div className="drawer-body">
          <UsageMeter />
          {Object.entries(grouped).map(([k, arr]) => arr.length === 0 ? null : (
            <div key={k} className="drawer-group">
              <div className="drawer-group-head">
                <span className={`src-dot ${dotClass(k)}`} />
                <span>{k.toUpperCase().replace("_"," ")}</span>
                <span className="dim small">· {arr.length}</span>
              </div>
              {arr.map(s => (
                <div key={s.id} className="drawer-row">
                  <span className="dr-name">{s.id}</span>
                  <span className="dr-types">{(s.ioc_types || []).map(t => <span key={t} className="type-pill">{t}</span>)}</span>
                  <span className={`dr-key key-${s.key}`}>{s.key}</span>
                  <span className="dr-lat dim">{s.env || "—"}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </aside>
    </div>
  );
}

function SourcesPie() {
  const counts = [
    { k: "ok", n: window.SOURCES.filter(s => s.status === "ok").length, c: "#7ce3a6" },
    { k: "deg", n: window.SOURCES.filter(s => s.status === "degraded").length, c: "#ffd166" },
    { k: "down", n: window.SOURCES.filter(s => s.status === "down").length, c: "#ff3b6b" },
    { k: "nokey", n: window.SOURCES.filter(s => s.status === "no_key").length, c: "#7a8089" }
  ];
  const total = counts.reduce((a, b) => a + b.n, 0);
  let acc = 0;
  const r = 36, cx = 48, cy = 48;
  return (
    <svg width="96" height="96" viewBox="0 0 96 96">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#ffffff10" strokeWidth="12" />
      {counts.map((s, i) => {
        const len = (s.n / total) * (2 * Math.PI * r);
        const off = -acc;
        acc += len;
        return <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={s.c} strokeWidth="12"
          strokeDasharray={`${len} ${2 * Math.PI * r}`} strokeDashoffset={off}
          transform={`rotate(-90 ${cx} ${cy})`} />;
      })}
      <text x={cx} y={cy + 4} textAnchor="middle" fontFamily="JetBrains Mono" fontSize="16" fill="#cbd0d6" fontWeight="600">{total}</text>
    </svg>
  );
}

// ─────────── Tweaks ───────────

function Tweaks({ accent, setAccent, density, setDensity, patterns, setPatterns, onClose }) {
  return (
    <div className="tweaks-panel">
      <div className="tweaks-head">
        <span>Tweaks</span>
        <button onClick={onClose}>✕</button>
      </div>
      <div className="tweaks-body">
        <div className="tweak-row">
          <label>accent</label>
          <div className="tweak-swatches">
            {[["ember","#ff6b35"],["mint","#3ddc97"],["cyan","#22d3ee"]].map(([k, c]) => (
              <button key={k} className={`swatch ${accent === k ? "on" : ""}`} style={{background: c}} onClick={() => setAccent(k)} title={k} />
            ))}
          </div>
        </div>
        <div className="tweak-row">
          <label>density</label>
          <div className="tweak-pills">
            <button className={density === "normal" ? "on" : ""} onClick={() => setDensity("normal")}>normal</button>
            <button className={density === "dense" ? "on" : ""} onClick={() => setDensity("dense")}>dense</button>
          </div>
        </div>
        <div className="tweak-row">
          <label>severity</label>
          <div className="tweak-pills">
            <button className={!patterns ? "on" : ""} onClick={() => setPatterns(false)}>color</button>
            <button className={patterns ? "on" : ""} onClick={() => setPatterns(true)}>+ pattern</button>
          </div>
        </div>
      </div>
      <div className="tweaks-foot dim">color + pattern improves accessibility for color-blind analysts</div>
    </div>
  );
}


// ---------------------------------------------------------------------------
// Cache — inspect / prune / wipe the SQLite enrichment store.
//
// Mirrors `shadowscope cache stats|prune|clear`. Read-only stats render on
// mount; destructive actions go through a single confirm gate. Auth token
// (if set) is pulled from sessionStorage just like shadowscopeFetch in
// /static/shared/data.js — that way the banner-captured token works here too.
// ---------------------------------------------------------------------------

function _cacheAuthHeaders() {
  const headers = {};
  try {
    const tok = sessionStorage.getItem("ss_api_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
  } catch (e) {}
  return headers;
}

function BackupPanel({ onRestored }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);         // {text, bad}
  const [pending, setPending] = useState(null); // {file, backup, current} after the dry run
  const fileRef = React.useRef(null);
  const say = (text, bad) => setMsg({ text, bad: !!bad });
  const detailOf = async (r) => { try { const j = await r.json(); return (j && typeof j.detail === "string" && j.detail) || ("HTTP " + r.status); } catch (e) { return "HTTP " + r.status; } };
  const line = (c) => `${c.iocs || 0} indicators · ${c.enrichments || 0} cached answers · ${c.ioc_notes || 0} notes · ${c.cases || 0} cases · ${c.watchlist || 0} watched · ${c.user_lists || 0} list entries`;

  const download = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await fetch("/api/ui/backup", { headers: _cacheAuthHeaders() });
      if (!r.ok) throw new Error(await detailOf(r));
      const name = (/filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "shadowscope-backup.db";
      const blob = await r.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      say(`saved ${name} (${(blob.size / 1048576).toFixed(1)} MB) to your downloads`);
    } catch (e) { say(String(e.message || e), true); }
    setBusy(false);
  };

  const upload = (file, dry) => fetch("/api/ui/restore" + (dry ? "?dry_run=true" : ""), {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", ...(dry ? {} : { "X-Confirm": "restore" }), ..._cacheAuthHeaders() },
    body: file,
  });

  const choose = async (file) => {
    if (!file) return;
    setBusy(true); setMsg(null); setPending(null);
    try {
      const r = await upload(file, true);
      if (!r.ok) throw new Error(await detailOf(r));
      const j = await r.json();
      setPending({ file, backup: j.backup, current: j.current });
    } catch (e) { say("cannot use that file: " + String(e.message || e), true); }
    setBusy(false);
  };

  const doRestore = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await upload(pending.file, false);
      if (!r.ok) throw new Error(await detailOf(r));
      const j = await r.json();
      setPending(null);
      say(`restored: ${line(j.restored)}. The previous database was kept as ${j.previous_saved_as} in the data folder. Reload the page to see the restored data everywhere.`);
      onRestored && onRestored();
    } catch (e) { say("restore failed, nothing was replaced: " + String(e.message || e), true); }
    setBusy(false);
  };

  return (
    <section className="cache-panel">
      <h3>backup &amp; restore</h3>
      <div className="dim" style={{ marginBottom: 8 }}>
        one file with everything that is yours: cached answers, score history, verdicts, notes, cases, watchlist, saved filters, block/allow lists.
        API keys are not included.
      </div>
      <div className="cache-form">
        <button className="pill" onClick={download} disabled={busy}>download backup</button>
        <input ref={fileRef} type="file" accept=".db,.bak,.sqlite,application/octet-stream" style={{ display: "none" }}
               onChange={e => { choose(e.target.files && e.target.files[0]); e.target.value = ""; }} />
        <button className="pill warn" onClick={() => fileRef.current && fileRef.current.click()} disabled={busy}>restore from file…</button>
      </div>
      {pending && (
        <div style={{ border: "1px solid var(--warn, #f0c674)", padding: 10, marginTop: 10 }}>
          <div><b>{pending.file.name}</b> is a valid backup{pending.backup.newest ? ` (newest entry ${pending.backup.newest})` : ""}.</div>
          <div className="small" style={{ marginTop: 6 }}>backup holds: {line(pending.backup.counts)}</div>
          <div className="small">here now: {line(pending.current)}</div>
          <div className="small" style={{ marginTop: 6, color: "var(--warn, #f0c674)" }}>
            Restoring replaces everything here with the backup. The current database is saved first as a .bak file next to it, so this can be undone by hand.
          </div>
          <div className="cache-form" style={{ marginTop: 8 }}>
            <button className="pill bad" onClick={doRestore} disabled={busy}>{busy ? "restoring…" : "replace current data with this backup"}</button>
            <button className="pill" onClick={() => setPending(null)} disabled={busy}>cancel</button>
          </div>
        </div>
      )}
      {msg && <div style={{ marginTop: 8, color: msg.bad ? "var(--bad, #ff7474)" : "var(--safe)" }}>// {msg.text}</div>}
    </section>
  );
}

function CacheView() {
  const [stats, setStats] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  // Prune form state.
  const [pruneDays, setPruneDays] = useState("");      // blank → server default
  const [pruneKeep, setPruneKeep] = useState("");      // blank → no cap

  // Clear form state — exactly one of these is sent.
  const [clearSource, setClearSource] = useState("");
  const [clearIoc, setClearIoc] = useState("");

  // Wipe-all confirmation modal state. The action is irreversible — a
  // double-confirm dialog is the wrong UX for that (a stray Enter
  // press sails through both prompts). Type-to-confirm forces the
  // analyst to acknowledge the scope by retyping the magic phrase.
  const [wipeModalOpen, setWipeModalOpen] = useState(false);
  const [wipeTyped, setWipeTyped] = useState("");
  const WIPE_PHRASE = "wipe all";

  const loadStats = () => {
    setErr(null);
    fetch("/api/cache/stats", { headers: _cacheAuthHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)))
      .then(setStats)
      .catch(e => setErr(String(e.message || e)));
  };

  useEffect(() => { loadStats(); }, []);

  const flash = (text) => {
    setMsg(text);
    setTimeout(() => setMsg(null), 4000);
  };

  const postJSON = (path, body) => {
    setBusy(true);
    setErr(null);
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ..._cacheAuthHeaders() },
      body: JSON.stringify(body),
    })
      .then(r => r.json().then(j => ({ ok: r.ok, status: r.status, body: j })))
      .then(({ ok, status, body }) => {
        if (!ok) throw new Error(body.detail || ("HTTP " + status));
        return body;
      })
      .finally(() => setBusy(false));
  };

  const doPrune = () => {
    const payload = {};
    if (pruneDays.trim()) payload.older_than_days = parseFloat(pruneDays);
    if (pruneKeep.trim()) payload.keep_last = parseInt(pruneKeep, 10);
    if (!confirm(
      "Prune rows older than " +
      (payload.older_than_days ?? "RETENTION_DAYS (default 90)") + " days" +
      (payload.keep_last ? ", keep last " + payload.keep_last + " per (ioc,source)" : "") +
      "?"
    )) return;
    postJSON("/api/cache/prune", payload)
      .then(body => {
        flash(
          "pruned " + body.removed_by_age + " by age (" + body.used_older_than_days + "d)" +
          (body.removed_by_keep_last ? ", " + body.removed_by_keep_last + " by keep-last" : "")
        );
        loadStats();
      })
      .catch(e => setErr(String(e.message || e)));
  };

  // Opens the type-to-confirm modal; the actual API call happens in
  // `confirmWipeAll` once the analyst has retyped the magic phrase.
  const doClearAll = () => {
    setWipeTyped("");
    setWipeModalOpen(true);
  };

  const closeWipeModal = () => {
    setWipeModalOpen(false);
    setWipeTyped("");
  };

  const confirmWipeAll = () => {
    if (wipeTyped.trim().toLowerCase() !== WIPE_PHRASE) return;
    closeWipeModal();
    postJSON("/api/cache/clear", { all: true })
      .then(body => { flash("cleared " + body.removed + " row(s) — " + body.scope); loadStats(); })
      .catch(e => setErr(String(e.message || e)));
  };

  const doClearSource = () => {
    const s = clearSource.trim();
    if (!s) { setErr("pick a source first"); return; }
    if (!confirm("Delete every cached row from source '" + s + "'?")) return;
    postJSON("/api/cache/clear", { source: s })
      .then(body => { flash("cleared " + body.removed + " row(s) — " + body.scope); setClearSource(""); loadStats(); })
      .catch(e => setErr(String(e.message || e)));
  };

  const doClearIoc = () => {
    const v = clearIoc.trim();
    if (!v) { setErr("paste an IOC value first"); return; }
    if (!confirm("Delete every cached row for IOC '" + v + "'?")) return;
    postJSON("/api/cache/clear", { ioc: v })
      .then(body => { flash("cleared " + body.removed + " row(s) — " + body.scope); setClearIoc(""); loadStats(); })
      .catch(e => setErr(String(e.message || e)));
  };

  const fmtBytes = (n) => {
    if (n == null) return "—";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1024 / 1024).toFixed(2) + " MB";
  };

  return (
    <div className="cache-view">
      <div className="batch-toolbar">
        <span className="bt-title">CACHE · enrichment maintenance</span>
        <div className="bt-group">
          <button className="pill" onClick={loadStats} disabled={busy}>refresh</button>
          {msg && <span className="bt-label" style={{ color: "var(--ok, #6cf08a)" }}>{msg}</span>}
          {err && <span className="bt-label" style={{ color: "var(--bad, #ff7474)" }}>err: {err}</span>}
        </div>
      </div>

      {!stats && !err && <div className="dim" style={{ padding: 16 }}>loading…</div>}

      {stats && (
        <div className="cache-grid">
          <section className="cache-panel">
            <h3>workspace</h3>
            <table className="kv">
              <tbody>
                <tr><td>DB path</td><td className="mono">{stats.db_path}</td></tr>
                <tr><td>size</td><td>{fmtBytes(stats.db_size_bytes)}</td></tr>
                <tr><td>IOCs</td><td>{stats.ioc_count}</td></tr>
                <tr><td>enrichment rows</td><td>{stats.enrichment_count}</td></tr>
                <tr><td>oldest</td><td className="mono">{stats.oldest_timestamp || "—"}</td></tr>
                <tr><td>newest</td><td className="mono">{stats.newest_timestamp || "—"}</td></tr>
              </tbody>
            </table>
          </section>

          <section className="cache-panel">
            <h3>rows per source</h3>
            {stats.per_source.length === 0
              ? <div className="dim">no rows cached</div>
              : (
                <table className="kv">
                  <tbody>
                    {stats.per_source.map(r => (
                      <tr key={r.source}>
                        <td>{r.source}</td>
                        <td style={{ textAlign: "right" }}>{r.rows}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
          </section>

          <section className="cache-panel">
            <h3>prune</h3>
            <div className="cache-form">
              <label>older than (days)
                <input
                  type="number"
                  step="0.5"
                  placeholder="default: RETENTION_DAYS or 90"
                  value={pruneDays}
                  onChange={e => setPruneDays(e.target.value)}
                />
              </label>
              <label>keep last N per (ioc, source)
                <input
                  type="number"
                  min="0"
                  placeholder="optional cap"
                  value={pruneKeep}
                  onChange={e => setPruneKeep(e.target.value)}
                />
              </label>
              <button className="pill warn" onClick={doPrune} disabled={busy}>prune</button>
            </div>
            <div className="dim" style={{ marginTop: 8 }}>
              age-prune deletes rows older than the cutoff; keep-last caps surviving history per pair.
            </div>
          </section>

          <section className="cache-panel">
            <h3>clear</h3>
            <div className="cache-form">
              <label>by source
                <input
                  type="text"
                  placeholder="e.g. virustotal"
                  value={clearSource}
                  onChange={e => setClearSource(e.target.value)}
                  list="cache-source-list"
                />
                <datalist id="cache-source-list">
                  {stats.per_source.map(r => <option key={r.source} value={r.source} />)}
                </datalist>
              </label>
              <button className="pill warn" onClick={doClearSource} disabled={busy}>clear source</button>

              <label>by IOC value
                <input
                  type="text"
                  placeholder="e.g. 1.1.1.1"
                  value={clearIoc}
                  onChange={e => setClearIoc(e.target.value)}
                />
              </label>
              <button className="pill warn" onClick={doClearIoc} disabled={busy}>clear ioc</button>

              <button className="pill bad" onClick={doClearAll} disabled={busy}>WIPE ALL</button>
            </div>
            <div className="dim" style={{ marginTop: 8 }}>
              destructive — single-source / single-IOC clears confirm once. WIPE ALL requires retyping "{WIPE_PHRASE}" to commit.
            </div>
          </section>

          <BackupPanel onRestored={loadStats} />
        </div>
      )}
      {wipeModalOpen && (
        <div className="wipe-modal-backdrop" onClick={closeWipeModal}>
          <div className="wipe-modal" onClick={e => e.stopPropagation()} role="dialog" aria-modal="true">
            <div className="wipe-modal-head">
              <span className="wipe-modal-title">WIPE ENRICHMENT CACHE</span>
              <button className="wipe-modal-close" onClick={closeWipeModal} aria-label="Close">×</button>
            </div>
            <div className="wipe-modal-body">
              <div className="wipe-modal-stats">
                <span className="dim">scope</span>
                <span>
                  {stats ? stats.enrichment_count : "?"} enrichment rows across {stats ? stats.ioc_count : "?"} IOCs
                </span>
              </div>
              <p>
                This will permanently delete every cached enrichment in the active workspace.
                Refetching what you wipe will burn through your API quotas.
              </p>
              <p className="wipe-modal-warn">
                This <strong>cannot</strong> be undone.
              </p>
              <label className="wipe-modal-confirm">
                Type <code>{WIPE_PHRASE}</code> to enable the button:
                <input
                  type="text"
                  autoFocus
                  value={wipeTyped}
                  onChange={e => setWipeTyped(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === "Enter" && wipeTyped.trim().toLowerCase() === WIPE_PHRASE) confirmWipeAll();
                    if (e.key === "Escape") closeWipeModal();
                  }}
                  placeholder={WIPE_PHRASE}
                  spellCheck={false}
                  autoComplete="off"
                />
              </label>
            </div>
            <div className="wipe-modal-actions">
              <button className="pill" onClick={closeWipeModal} disabled={busy}>cancel</button>
              <button
                className="pill bad"
                onClick={confirmWipeAll}
                disabled={busy || wipeTyped.trim().toLowerCase() !== WIPE_PHRASE}
              >wipe permanently</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
