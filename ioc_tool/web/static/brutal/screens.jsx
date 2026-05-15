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

function WatchView({ fmt }) {
  const [feed, setFeed] = useState(window.WATCH_FEED);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    if (paused) return;
    const t = setInterval(() => {
      // Synthetic new tick — rotate the feed.
      setFeed(f => {
        const synth = { ...f[Math.floor(Math.random() * f.length)] };
        synth.ts = new Date().toISOString().slice(11, 19);
        return [synth, ...f].slice(0, 60);
      });
    }, 3800);
    return () => clearInterval(t);
  }, [paused]);

  const filtered = filter === "all" ? feed : feed.filter(f => Math.abs(f.delta) >= 20);

  return (
    <div className="watch-view">
      <div className="watch-toolbar">
        <span className="bt-title">WATCH · live score deltas</span>
        <div className="bt-group">
          <button className={`pill ${filter === "all" ? "on" : ""}`} onClick={() => setFilter("all")}>all</button>
          <button className={`pill ${filter === "big" ? "on" : ""}`} onClick={() => setFilter("big")}>|Δ| ≥ 20</button>
        </div>
        <div className="bt-group">
          <button className={`pill ${paused ? "" : "on"}`} onClick={() => setPaused(false)}>● LIVE</button>
          <button className={`pill ${paused ? "on" : ""}`} onClick={() => setPaused(true)}>⏸ PAUSE</button>
        </div>
        <span className="dim small">tail -f shadowscope.events · {feed.length} lines</span>
      </div>
      <div className="watch-stream">
        {filtered.map((e, i) => {
          const s = sevOf(e.score);
          const up = e.delta > 0;
          return (
            <div key={i} className={`watch-row ${i === 0 && !paused ? "new" : ""}`}>
              <span className="w-ts dim">{e.ts}</span>
              <span className="w-score" style={{color: s.fg}}>{String(e.score).padStart(3, " ")}</span>
              <span className="w-tier" style={{color: s.fg, borderColor: s.fg + "55"}}>{s.label.slice(0,4)}</span>
              <span className="w-type dim">{e.type.padEnd(6, " ")}</span>
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
  const [openId, setOpenId] = useState(window.CASES[0].id);
  const open = window.CASES.find(c => c.id === openId);
  const openIocs = open.iocs.map(id => results.find(r => r.id === id) || window.IOC_DB.find(r => r.id === id)).filter(Boolean);
  return (
    <div className="cases-view">
      <aside className="case-list">
        <div className="sec-head"><span className="sec-title">CASES · {window.CASES.length}</span></div>
        {window.CASES.map(c => {
          const s = sevOf(c.severity);
          return (
            <button key={c.id} className={`case-card ${c.id === openId ? "on" : ""}`} onClick={() => setOpenId(c.id)} style={{ borderLeft: `3px solid ${s.fg}` }}>
              <div className="case-card-top">
                <span className="case-sev" style={{color: s.fg}}>{c.severity}</span>
                <span className="case-iocs dim">{c.iocs.length} IOC</span>
              </div>
              <div className="case-label">{c.label}</div>
              <div className="case-meta dim small">{c.id} · opened {c.opened}</div>
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
            <span className="dim">id:</span> <Copyable text={open.id}>{open.id}</Copyable>
            <span className="dim"> · opened {open.opened}</span>
            <span className="dim"> · cumulative risk</span>{" "}
            <b style={{color: sevOf(open.severity).fg}}>{open.severity}</b>
          </div>
        </header>
        <table className="batch-table">
          <thead><tr><th>score</th><th>type</th><th>indicator</th><th>flagged</th><th></th></tr></thead>
          <tbody>
            {openIocs.map(r => {
              const s = sevOf(r.final_score);
              return (
                <tr key={r.id} className="batch-row" onClick={() => { setActiveIocId(r.id); setTab("enrich"); }}>
                  <td className="bt-score" style={{color: s.fg, borderLeft: `3px solid ${s.fg}`}}>{r.final_score}</td>
                  <td className="mono dim">{r.type}</td>
                  <td className="bt-ioc">{fmt(r.ioc)}</td>
                  <td className="dim small">{r.agreement.sources_flagged}/{r.agreement.sources_total} · {r.agreement.consensus}</td>
                  <td className="bt-arrow">▸</td>
                </tr>
              );
            })}
          </tbody>
        </table>

        <CaseGraph iocs={openIocs} />
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
      <div className="sec-head"><span className="sec-title">SHARED INFRASTRUCTURE GRAPH</span><span className="sec-meta dim">IOC ↔ source bipartite · edge = positive score</span></div>
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
  const [a, b] = diffPair.map(id => results.find(r => r.id === id) || window.IOC_DB.find(r => r.id === id));
  if (!a || !b) return null;
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
        <thead><tr><th>source</th><th className="r">A</th><th className="ctr">Δ</th><th className="l">B</th><th>verdict</th></tr></thead>
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
            <span className="sec-title">SOURCES</span>
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
            <span className="sec-title">SOURCES · loading…</span>
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
