// Brutalist — Enrich view with big mono score block, MITRE strip, WHOIS timeline,
// pivot panel, drill chips, and inline source toggle.

function EnrichView({ ioc, fmt, llm, results, setActiveIocId, disabledSources, setDisabledSources, onPivot }) {
  if (!ioc) return null;

  const modules = Object.entries(ioc.modules);
  const heuristics = ioc.modules.Heuristics?.data || {};
  const flags = [];
  if (heuristics.nrd && heuristics.nrd.age_days != null && heuristics.nrd.age_days < 30) flags.push({ k: "NRD", v: `${heuristics.nrd.age_days}d`, score: heuristics.nrd.score });
  if (heuristics.dga && heuristics.dga.score >= 60) flags.push({ k: "DGA", v: `H=${heuristics.dga.entropy?.toFixed(1)}`, score: heuristics.dga.score });
  if (heuristics.typosquat) flags.push({ k: "TYPOSQUAT", v: `→ ${heuristics.typosquat.match}  d=${heuristics.typosquat.distance}`, score: heuristics.typosquat.score });
  if (heuristics.idn?.mixed_script) flags.push({ k: "IDN", v: `mixed-script`, score: heuristics.idn.score });

  // Compute the (possibly adjusted) composite score
  const adjustedScore = disabledSources.size > 0 ? window.recomputeComposite(ioc, disabledSources) : ioc.final_score;
  const sev = sevOf(adjustedScore);
  const symbolicFlags = window.IOC_FLAGS(ioc);
  const hasGeo = !!(ioc.geo || window.SHODAN_DATA[ioc.id]);

  const toggleSource = (name) => {
    const next = new Set(disabledSources);
    if (next.has(name)) next.delete(name); else next.add(name);
    setDisabledSources(next);
  };
  const resetSources = () => setDisabledSources(new Set());

  return (
    <div className="enrich-view">
      <div className="recent-strip">
        <span className="recent-label">recent ▸</span>
        {results.slice(0, 8).map(r => {
          const s = sevOf(r.final_score);
          return (
            <button key={r.id} className={`recent-pill ${r.id === ioc.id ? "on" : ""}`} onClick={() => setActiveIocId(r.id)}>
              <span className="recent-score" style={{ color: s.fg }}>{r.final_score}</span>
              <span className="recent-ioc">{fmt(r.ioc).length > 24 ? fmt(r.ioc).slice(0, 22) + "…" : fmt(r.ioc)}</span>
            </button>
          );
        })}
      </div>

      <section className="hero">
        <div className="hero-left">
          <div className="hero-ioc-row">
            <span className="hero-type">{ioc.type.toUpperCase()}</span>
            <Copyable text={fmt(ioc.ioc)}>
              <span className="hero-ioc">{fmt(ioc.ioc)}</span>
            </Copyable>
            <span className="hero-time">enriched <Relative iso={ioc.enriched_at} /></span>
          </div>

          {symbolicFlags.length > 0 && <FlagStrip ioc={ioc} />}

          <div className="hero-grid">
            {/* Brutalist score block */}
            <div className="score-block" style={{ borderColor: sev.fg }}>
              <div className="score-top">
                <span>SCORE / 100</span>
                <span className="dim">{ioc.type}</span>
              </div>
              <div className="score-num-big" style={{ color: sev.fg }}>{String(adjustedScore).padStart(2, "0")}</div>
              <div className="score-bar">
                <div className="score-bar-fill" style={{ width: `${adjustedScore}%`, background: sev.fg }} />
                <span className="score-tick" style={{ left: "20%" }} />
                <span className="score-tick" style={{ left: "40%" }} />
                <span className="score-tick" style={{ left: "60%" }} />
                <span className="score-tick" style={{ left: "80%" }} />
              </div>
              <div className="score-tier-banner" style={{ background: sev.fg, color: "var(--bg)" }}>
                <span className="stb-glyph">{sev.label === "CRITICAL" ? "[!!!]" : sev.label === "HIGH" ? "[!!]" : sev.label === "MEDIUM" ? "[!]" : sev.label === "LOW" ? "[·]" : "[ok]"}</span>
                <span className="stb-label glitch" data-text={sev.label}>{sev.label}</span>
              </div>
              {disabledSources.size > 0 && (
                <div className="score-adjusted">
                  <span>ADJUSTED · {disabledSources.size} src excluded</span>
                  <button onClick={resetSources}>reset</button>
                </div>
              )}
            </div>

            <div className="hero-meta">
              <ConsensusChip a={ioc.agreement} />
              {ioc.prev_score !== undefined && <DeltaChip prev={ioc.prev_score} curr={ioc.final_score} />}
              {ioc.case && <CaseChip caseId={ioc.case} />}
              <div className="hero-flags">
                <div className="flags-label">HEURISTICS · local signals</div>
                {flags.length === 0 && <div className="flags-empty">// no flags fired</div>}
                {flags.map((f, i) => {
                  const explanation = window.HEUR_EXPLAIN[f.k] || "";
                  const fullName = {
                    NRD: "Newly Registered Domain",
                    DGA: "Domain Generation Algorithm",
                    TYPOSQUAT: "Typosquat against brand",
                    IDN: "IDN homograph attack"
                  }[f.k] || f.k;
                  return (
                    <div key={i} className="flag-row" title={explanation}>
                      <span className="flag-k" style={{ color: sevOf(f.score).fg }}>{f.k}</span>
                      <span className="flag-v">
                        <span className="flag-fullname">{fullName}</span>
                        <span className="flag-detail dim">{f.v}</span>
                      </span>
                      <span className="flag-bar"><span style={{ width: `${f.score}%`, background: sevOf(f.score).fg }} /></span>
                      <span className="flag-score">{f.score}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div className={`hero-right ${hasGeo ? "has-geo" : ""}`}>
          {hasGeo && <IpCorePanel ioc={ioc} fmt={fmt} />}
          <SpiderChart ioc={ioc} sev={sev} disabledSources={disabledSources} />
          {hasGeo && <NetworkGeoPanel ioc={ioc} />}
        </div>
      </section>

      <MitreStrip ioc={ioc} onPivot={onPivot} />
      <WhoisTimeline ioc={ioc} fmt={fmt} />

      <div className="enrich-split">
        <section className="sources-block">
          <div className="sec-head">
            <span className="sec-title">SOURCE ATTRIBUTION</span>
            <span className="sec-meta">{modules.length} sources queried · ordered by score</span>
            <span className="sec-meta dim">click row → toggle inclusion</span>
          </div>
          <table className="src-table">
            <thead>
              <tr>
                <th style={{ width: "3ch" }}></th>
                <th style={{ width: "14ch" }}>source</th>
                <th style={{ width: "9ch" }}>score</th>
                <th>detail</th>
                <th style={{ width: "8ch" }}>fetched</th>
              </tr>
            </thead>
            <tbody>
              {modules.sort((a, b) => b[1].score - a[1].score).map(([name, mod]) => {
                const s = sevOf(mod.score);
                const off = disabledSources.has(name);
                const f = window.FRESHNESS(name, ioc.id);
                return (
                  <tr key={name} className={`src-row ${mod.score === 0 ? "muted" : ""} ${off ? "off" : ""}`} onClick={() => toggleSource(name)}>
                    <td className="src-toggle"><span className={`src-check ${off ? "off" : "on"}`}>{off ? "✕" : "✓"}</span></td>
                    <td className="src-name">{name}</td>
                    <td className="src-score" style={{ color: off ? "var(--ink-3)" : s.fg }}>
                      <span className="src-score-num">{String(mod.score).padStart(2, "0")}</span>
                      <span className="src-score-bar"><span style={{ width: `${mod.score}%`, background: off ? "var(--line-2)" : s.fg }} /></span>
                    </td>
                    <td className="src-detail">{renderSourceDetail(mod.detail, mod, onPivot)}</td>
                    <td className={`src-fresh ${f.stale ? "stale" : ""}`}>{f.minutes < 60 ? `${f.minutes}m` : `${Math.floor(f.minutes/60)}h`}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>

        <PivotPanel ioc={ioc} results={results} setActiveIocId={setActiveIocId} />
      </div>

      {llm && <LlmVerdict ioc={ioc} fmt={fmt} sev={sev} />}
    </div>
  );
}

// SpiderChart — per-source score polygon. Honors disabled sources (greys out).
function SpiderChart({ ioc, sev, disabledSources = new Set() }) {
  const entries = Object.entries(ioc.modules);
  const N = entries.length;
  const cx = 140, cy = 132, R = 88;

  const angle = (i) => (i / N) * Math.PI * 2 - Math.PI / 2;
  const point = (i, frac) => ({
    x: cx + Math.cos(angle(i)) * R * frac,
    y: cy + Math.sin(angle(i)) * R * frac
  });

  const polyPoints = entries.map(([name, m], i) => {
    const frac = disabledSources.has(name) ? 0.015 : Math.max(0.015, m.score / 100);
    const p = point(i, frac);
    return `${p.x},${p.y}`;
  }).join(" ");

  const rings = [
    { frac: 0.2 }, { frac: 0.4 }, { frac: 0.6 }, { frac: 0.8 }, { frac: 1.0 }
  ];

  return (
    <div className="spider">
      <div className="spider-head">
        <span className="spider-title">SOURCE PROFILE</span>
        <span className="spider-meta">{N} axes · radius = score</span>
      </div>
      <svg viewBox="0 0 280 280" preserveAspectRatio="xMidYMid meet">
        {rings.map(r => (
          <polygon key={r.frac}
            points={entries.map((_, i) => { const p = point(i, r.frac); return `${p.x},${p.y}`; }).join(" ")}
            fill="none"
            stroke={r.frac === 1 ? "#3a3a3a" : "#202020"}
            strokeWidth="1"
          />
        ))}
        <polygon
          points={entries.map((_, i) => { const p = point(i, 0.6); return `${p.x},${p.y}`; }).join(" ")}
          fill="none" stroke="#fb923c" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="3 4"
        />
        <polygon
          points={entries.map((_, i) => { const p = point(i, 0.8); return `${p.x},${p.y}`; }).join(" ")}
          fill="none" stroke="#f43f5e" strokeOpacity="0.4" strokeWidth="1" strokeDasharray="3 4"
        />
        {[20, 40, 60, 80, 100].map((label, i) => (
          <text key={label} x={cx + 3} y={cy - R * (label/100) + 3} fill="#3a3a3a" fontFamily="JetBrains Mono" fontSize="8">{label}</text>
        ))}
        {entries.map(([name], i) => {
          const end = point(i, 1);
          return <line key={"a"+i} x1={cx} y1={cy} x2={end.x} y2={end.y} stroke="#222" strokeWidth="1" />;
        })}
        <polygon points={polyPoints} fill={sev.fg} fillOpacity="0.18" stroke={sev.fg} strokeWidth="1.5" strokeLinejoin="miter" />
        {entries.map(([name, m], i) => {
          const off = disabledSources.has(name);
          const frac = off ? 0.015 : Math.max(0.015, m.score / 100);
          const p = point(i, frac);
          const s = sevOf(m.score);
          return (
            <rect key={"v"+i} x={p.x - 3} y={p.y - 3} width="6" height="6" fill="#0a0a0a" stroke={off ? "var(--line-2)" : s.fg} strokeWidth="1.5" />
          );
        })}
        {entries.map(([name, m], i) => {
          const a = angle(i);
          const labelP = point(i, 1.16);
          const c = Math.cos(a);
          const s2 = Math.sin(a);
          let anchor = "middle";
          if (c > 0.3) anchor = "start";
          else if (c < -0.3) anchor = "end";
          const dy = s2 > 0.5 ? 10 : s2 < -0.5 ? -2 : 4;
          const off = disabledSources.has(name);
          return (
            <g key={"t"+i} style={{ opacity: off ? 0.35 : 1, textDecoration: off ? "line-through" : "none" }}>
              <text x={labelP.x} y={labelP.y + dy - 6} fill="#a8a8a8" fontFamily="JetBrains Mono" fontSize="9" letterSpacing="0.04em" textAnchor={anchor}>{name}</text>
              <text x={labelP.x} y={labelP.y + dy + 6} fill={sevOf(m.score).fg} fontFamily="JetBrains Mono" fontSize="11" fontWeight="800" textAnchor={anchor}>{String(m.score).padStart(2, "0")}</text>
            </g>
          );
        })}
      </svg>
      <div className="spider-legend">
        <span><span className="swatch-line" style={{background: "#fb923c"}}/> threshold 60</span>
        <span><span className="swatch-line" style={{background: "#f43f5e"}}/> threshold 80</span>
      </div>
    </div>
  );
}

function ConsensusChip({ a }) {
  const colorMap = { high: "var(--safe)", medium: "var(--med)", low: "var(--high)", none: "var(--ink-3)" };
  const explain = `Consensus measures source agreement. ${a.sources_flagged} of ${a.sources_total} sources returned a non-zero score. Higher consensus = more trustworthy verdict.`;
  return (
    <div className="chip" title={explain}>
      <span className="chip-label">CONSENSUS</span>
      <div className="consensus-bar">
        {Array.from({ length: a.sources_total }).map((_, i) => (
          <span key={i} className={i < a.sources_flagged ? "on" : "off"} />
        ))}
      </div>
      <span className="chip-val">{a.sources_flagged}/{a.sources_total} <span className="dim">flagged</span> · <b style={{color: colorMap[a.consensus]}}>{a.consensus}</b></span>
      <span className="chip-help" title={explain}>?</span>
    </div>
  );
}

function DeltaChip({ prev, curr }) {
  const delta = curr - prev;
  if (delta === 0 && prev === 0) return null;
  const sign = delta >= 0 ? "+" : "−";
  const color = delta > 0 ? "var(--high)" : delta < 0 ? "var(--safe)" : "var(--ink-3)";
  const explain = `Change in composite score over the last 24 hours. Previous score was ${prev}/100; current is ${curr}/100. Use to spot indicators trending up or decaying.`;
  return (
    <div className="chip" title={explain}>
      <span className="chip-label">SCORE Δ · 24h</span>
      <span className="chip-val" style={{ color, fontWeight: 800 }}>{sign}{Math.abs(delta)}</span>
      <span className="chip-meta"><span className="dim">prev</span> {prev} <span className="dim">→</span> {curr}</span>
      <span className="chip-help" title={explain}>?</span>
    </div>
  );
}

function CaseChip({ caseId }) {
  const c = window.CASES.find(x => x.id === caseId);
  const explain = `This IOC is grouped under an investigation case. Cases let you track related indicators across a campaign and view their cumulative risk.`;
  return (
    <div className="chip" title={explain}>
      <span className="chip-label">CASE</span>
      <span className="chip-val">{c?.label || caseId}</span>
      <span className="chip-meta dim small">{c?.iocs?.length || 1} IOC</span>
      <span className="chip-help" title={explain}>?</span>
    </div>
  );
}

function Copyable({ text, children }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="copyable" onClick={() => { navigator.clipboard?.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200); }}>
      {children}
      <span className={`copy-glyph ${copied ? "ok" : ""}`}>{copied ? "✓" : "⧉"}</span>
    </span>
  );
}

function Relative({ iso }) {
  const d = new Date(iso);
  const now = new Date();
  const diff = Math.max(1, (now - d) / 1000);
  let label;
  if (diff < 60) label = `${Math.floor(diff)}s ago`;
  else if (diff < 3600) label = `${Math.floor(diff / 60)}m ago`;
  else label = `${Math.floor(diff / 3600)}h ago`;
  return <span title={iso}>{label}</span>;
}

function LlmVerdict({ ioc, fmt, sev }) {
  return (
    <section className="llm-block">
      <div className="sec-head">
        <span className="sec-title">NARRATIVE VERDICT</span>
        <span className="sec-meta dim">optional · LLM-generated · NOT part of composite score</span>
      </div>
      <div className="llm-body">
        <p>
          The indicator <b style={{ color: sev.fg }}>{fmt(ioc.ioc)}</b> resolves to a <b>{sev.label.toLowerCase()}</b> risk
          posture. {ioc.agreement.sources_flagged} of {ioc.agreement.sources_total} sources flagged it, with
          {" "}<b>{ioc.agreement.consensus}</b> consensus.{" "}
          {ioc.modules.URLhaus?.score > 0 && <>URLhaus tags it as <b>{ioc.modules.URLhaus.data?.threat || "malicious"}</b>. </>}
          {ioc.modules.Heuristics?.data?.typosquat && <>Local heuristics detected a typosquat against <b>{ioc.modules.Heuristics.data.typosquat.match}</b>. </>}
          {ioc.modules.Heuristics?.data?.nrd?.age_days < 30 && <>The domain is newly registered ({ioc.modules.Heuristics.data.nrd.age_days}d). </>}
          Recommend block at egress and pivot on related infrastructure.
        </p>
        <p className="llm-cite dim">// generated by local llm · do not paste into reports unverified</p>
      </div>
    </section>
  );
}
