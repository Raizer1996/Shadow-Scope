// Cinematic Ops — Batch / Watch / Cases / Diff / Sources / Tweaks views.

function BatchView({ results, setActiveIocId, setTab, fmt }) {
  const [sortKey, setSortKey] = useState("score");
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
        <button className="btn-outline">EXPORT .csv</button>
      </div>

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
              <tr key={r.id} className="batch-row" onClick={() => { setActiveIocId(r.id); setTab("enrich"); }}>
                <td className="bt-score" style={{color: s.fg, borderLeft: `3px solid ${s.fg}`}}>{r.final_score}</td>
                <td><span className="tier-mini" style={{color: s.fg, borderColor: s.fg + "55"}}>{s.label}</span></td>
                <td className="mono dim">{r.type}</td>
                <td className="bt-ioc"><Copyable text={fmt(r.ioc)}>{fmt(r.ioc).length > 60 ? fmt(r.ioc).slice(0, 56) + "…" : fmt(r.ioc)}</Copyable></td>
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

// ─────────── Watch (live stream) ───────────

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
    const ts = (r.enriched_at || "").slice(11, 19) || "—";
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
        <span className="bt-title">WATCH · enrichment history</span>
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
        <div className="dim small" style={{ padding: 20 }}>
          // no cases yet — assign an IOC to a case from the Enrich tab to start one
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
        {cases.map(c => {
          const s = sevOf(c.severity);
          return (
            <button key={c.id} className={`case-card ${c.id === openId ? "on" : ""}`} onClick={() => setOpenId(c.id)} style={{ borderLeft: `3px solid ${s.fg}` }}>
              <div className="case-card-top">
                <span className="case-sev" style={{color: s.fg}}>{c.severity}</span>
                <span className="case-iocs dim">{c.ioc_count} IOC</span>
              </div>
              <div className="case-label">{c.label}</div>
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
            <button className="pill warn" style={{ marginLeft: 12 }} onClick={deleteCase}>delete case</button>
          </div>
        </header>
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
  const [a, b] = diffPair.map(id => results.find(r => r.id === id));
  if (!a || !b) {
    return (
      <div className="diff-view">
        <div className="batch-toolbar">
          <span className="bt-title">DIFF · side-by-side</span>
          <span className="dim small">// need two enrichments on the strip — enrich some IOCs first</span>
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
          <select className="bt-select" value={diffPair[0]} onChange={e => setDiffPair([e.target.value, diffPair[1]])}>
            {results.map(r => <option key={r.id} value={r.id}>{r.ioc}</option>)}
          </select>
        </div>
        <div className="bt-group">
          <span className="bt-label">right</span>
          <select className="bt-select" value={diffPair[1]} onChange={e => setDiffPair([diffPair[0], e.target.value])}>
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
