// Brutalist — new feature components: MITRE strip, WHOIS timeline,
// alert ticker, pattern overlay, freshness, pivot panel, drill chips, source toggle.

// ─────────── MITRE ATT&CK strip ───────────

function MitreStrip({ ioc, onPivot }) {
  // Find the malware family from any module
  let family = null;
  for (const [_, mod] of Object.entries(ioc.modules)) {
    if (mod.data?.malware) { family = mod.data.malware; break; }
    if (mod.data?.family)  { family = mod.data.family;  break; }
  }
  if (!family) return null;
  const techniques = window.MITRE_MAP[family];
  if (!techniques) return null;

  // Group by tactic
  const byTactic = {};
  techniques.forEach(t => {
    (byTactic[t.tactic] = byTactic[t.tactic] || []).push(t);
  });

  return (
    <section className="mitre-strip">
      <div className="sec-head">
        <span className="sec-title">MITRE ATT&CK</span>
        <span className="sec-meta">{techniques.length} techniques mapped via <DrillChip kind="malware" value={family} onPivot={onPivot} inline /></span>
        <span className="sec-meta dim">attack.mitre.org · derived from family attribution</span>
      </div>
      <div className="mitre-grid">
        {Object.entries(byTactic).map(([tactic, techs]) => (
          <div key={tactic} className="mitre-col">
            <div className="mitre-tactic">{tactic.toUpperCase()}</div>
            <div className="mitre-techs">
              {techs.map(t => (
                <a key={t.id} className="mitre-tech" href={`https://attack.mitre.org/techniques/${t.id}/`} target="_blank" rel="noopener">
                  <span className="mt-id">{t.id}</span>
                  <span className="mt-name">{t.name}</span>
                  <span className="mt-arrow">↗</span>
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

// ─────────── WHOIS lifecycle (vertical, readable) ───────────

function WhoisTimeline({ ioc, fmt }) {
  if (ioc.type !== "domain") return null;
  const whois = ioc.modules.WHOIS?.data;
  if (!whois?.creation_date) return null;

  const created = new Date(whois.creation_date);
  const now = new Date();
  const ageDays = Math.max(0, Math.floor((now - created) / 86400000));

  // Build event timeline (newest first, descending by days-ago)
  const events = [
    { ago: 0,                       label: "ENRICHED",        detail: <Relative iso={ioc.enriched_at} />,                                     glyph: "▶", emphasis: "now",   ts: ioc.enriched_at.slice(0,10) },
    { ago: 1,                       label: "FIRST FLAGGED",   detail: `${ioc.agreement.sources_flagged}/${ioc.agreement.sources_total} sources · ${ioc.agreement.consensus} consensus`, glyph: "▲", emphasis: "alert", ts: dateAgo(1) },
    ageDays > 7  ? { ago: Math.floor(ageDays * 0.35), label: "PASSIVE DNS PICKUP",  detail: "first hosting observation", glyph: "◇", emphasis: null,    ts: dateAgo(Math.floor(ageDays * 0.35)) } : null,
    ageDays > 14 ? { ago: Math.floor(ageDays * 0.7),  label: "NS CHANGE",           detail: "ns1.cloudflare → ns3.suspect.tld", glyph: "◇", emphasis: null,    ts: dateAgo(Math.floor(ageDays * 0.7)) } : null,
    { ago: ageDays,                 label: "REGISTERED",      detail: whois.registrar || "unknown registrar",                                glyph: "◆", emphasis: ageDays < 30 ? "warn" : null, ts: whois.creation_date }
  ].filter(Boolean);

  const nrdRemaining = Math.max(0, 30 - ageDays);

  return (
    <section className="whois-block">
      <div className="sec-head">
        <span className="sec-title">WHOIS · LIFECYCLE</span>
        <span className="sec-meta">domain age <b style={{color: ageDays < 30 ? "var(--high)" : "var(--ink)"}}>{ageDays} days</b></span>
        <span className="sec-meta dim">tracks every observable change since registration</span>
      </div>

      <div className="whois-grid">
        <div className="whois-stats">
          <div className="ws-card">
            <div className="ws-k">REGISTERED</div>
            <div className="ws-v">{whois.creation_date}</div>
            <div className="ws-sub dim">{ageDays}d ago</div>
          </div>
          <div className="ws-card">
            <div className="ws-k">REGISTRAR</div>
            <div className="ws-v">{whois.registrar || "—"}</div>
            <div className="ws-sub dim">whois lookup · {window.FRESHNESS("WHOIS", ioc.id).minutes}m ago</div>
          </div>
          <div className="ws-card">
            <div className="ws-k">NRD STATUS</div>
            <div className="ws-v" style={{color: ageDays < 30 ? "var(--high)" : "var(--safe)"}}>
              {ageDays < 30 ? "IN-ZONE" : "OUT-OF-ZONE"}
            </div>
            <div className="ws-sub dim">
              {ageDays < 30 ? `${nrdRemaining}d until exits NRD window` : `${ageDays - 30}d past NRD window`}
            </div>
          </div>
          <div className="ws-card">
            <div className="ws-k">SCORE CONTRIBUTION</div>
            <div className="ws-v" style={{color: "var(--accent)"}}>+{ioc.modules.WHOIS?.score || 0}</div>
            <div className="ws-sub dim">whois module weight</div>
          </div>
        </div>

        <div className="whois-tl">
          <div className="wtl-label">EVENT TIMELINE</div>
          {events.map((e, i) => (
            <div key={i} className={`wtl-event ${e.emphasis || ""}`}>
              <span className="wtl-rail"><span className="wtl-glyph">{e.glyph}</span></span>
              <span className="wtl-ago">{e.ago === 0 ? "now" : `−${e.ago}d`}</span>
              <span className="wtl-body">
                <span className="wtl-label-event">{e.label}</span>
                <span className="wtl-detail">{e.detail}</span>
              </span>
              <span className="wtl-date dim">{e.ts}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function dateAgo(days) {
  const d = new Date(Date.now() - days * 86400000);
  return d.toISOString().slice(0, 10);
}

// ─────────── Header alert ticker ───────────

function AlertTicker({ feed, setActiveIoc, setTab, fmt }) {
  // Take all CRITICAL/HIGH from feed, repeat for marquee continuity
  const alerts = feed.filter(f => f.score >= 60).slice(0, 14);
  if (alerts.length === 0) return null;

  const onClick = (a) => {
    // Try to map back to IOC_DB
    const match = window.IOC_DB.find(r => r.ioc.startsWith(a.ioc.slice(0, 10)) || a.ioc.startsWith(r.ioc.slice(0, 10)));
    if (match) { setActiveIoc(match.id); setTab("enrich"); }
  };

  return (
    <div className="ticker">
      <div className="ticker-prefix">
        <span className="ticker-pulse" />
        <span>LIVE · CRIT/HIGH</span>
      </div>
      <div className="ticker-track">
        <div className="ticker-row">
          {[...alerts, ...alerts].map((a, i) => {
            const s = sevOf(a.score);
            return (
              <span key={i} className="ticker-item" onClick={() => onClick(a)}>
                <span className="ti-score" style={{color: s.fg, borderColor: s.fg}}>{a.score}</span>
                <span className="ti-ioc">{fmt(a.ioc)}</span>
                <span className="ti-delta" style={{color: a.delta > 0 ? "var(--high)" : "var(--safe)"}}>
                  {a.delta > 0 ? "↑+" : a.delta < 0 ? "↓" : "·"}{a.delta !== 0 && Math.abs(a.delta)}
                </span>
                <span className="ti-sep">│</span>
              </span>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─────────── Pivot panel: related IOCs ───────────

function PivotPanel({ ioc, results, setActiveIocId }) {
  // Find related IOCs by case match + shared malware family
  const sameCase = ioc.case ? window.IOC_DB.filter(r => r.case === ioc.case && r.id !== ioc.id) : [];
  const family = Object.values(ioc.modules).find(m => m.data?.malware)?.data?.malware ||
                 Object.values(ioc.modules).find(m => m.data?.family)?.data?.family;
  const sameFamily = family ? window.IOC_DB.filter(r => {
    if (r.id === ioc.id) return false;
    return Object.values(r.modules).some(m => m.data?.malware === family || m.data?.family === family);
  }) : [];

  // Same WHOIS registrar
  const registrar = ioc.modules.WHOIS?.data?.registrar;
  const sameRegistrar = registrar ? window.IOC_DB.filter(r => {
    if (r.id === ioc.id) return false;
    return r.modules.WHOIS?.data?.registrar === registrar;
  }) : [];

  const groups = [
    sameCase.length      && { title: "SAME CASE",      pivot: ioc.case || "—",        items: sameCase },
    sameFamily.length    && { title: "SAME FAMILY",    pivot: family,                  items: sameFamily },
    sameRegistrar.length && { title: "SAME REGISTRAR", pivot: registrar,               items: sameRegistrar }
  ].filter(Boolean);

  if (groups.length === 0) {
    return (
      <aside className="pivot-panel">
        <div className="sec-head">
          <span className="sec-title">RELATED</span>
          <span className="sec-meta dim">no pivots</span>
        </div>
        <div className="pivot-empty">// no related infrastructure found<br/>// in current intel corpus</div>
      </aside>
    );
  }

  return (
    <aside className="pivot-panel">
      <div className="sec-head">
        <span className="sec-title">RELATED</span>
        <span className="sec-meta">{groups.reduce((n, g) => n + g.items.length, 0)} IOCs across {groups.length} pivots</span>
      </div>
      {groups.map(g => (
        <div key={g.title} className="pivot-group">
          <div className="pivot-group-head">
            <span className="pgh-title">{g.title}</span>
            <span className="pgh-pivot">{g.pivot}</span>
          </div>
          {g.items.map(r => {
            const s = sevOf(r.final_score);
            return (
              <button key={r.id} className="pivot-row" onClick={() => setActiveIocId(r.id)}>
                <span className="pr-score" style={{color: s.fg, borderColor: s.fg}}>{r.final_score}</span>
                <span className="pr-type">{r.type}</span>
                <span className="pr-ioc">{r.ioc.length > 28 ? r.ioc.slice(0, 26) + "…" : r.ioc}</span>
                <span className="pr-arrow">▸</span>
              </button>
            );
          })}
        </div>
      ))}
    </aside>
  );
}

// ─────────── Drill-down chip ───────────

function DrillChip({ kind, value, onPivot, inline }) {
  const meta = window.PIVOT_KINDS[kind] || {};
  return (
    <span
      role="button"
      tabIndex={0}
      className={`drill-chip ${inline ? "inline" : ""}`}
      onClick={(e) => { e.stopPropagation(); e.preventDefault(); onPivot && onPivot(kind, value); }}
      onMouseDown={(e) => { e.stopPropagation(); }}
      onKeyDown={(e) => { if (e.key === "Enter") { e.stopPropagation(); onPivot && onPivot(kind, value); } }}
      title={`pivot on ${meta.label || kind} → ${value}`}
    >
      <span className="dc-glyph" style={{color: meta.color}}>{meta.glyph}</span>
      <span className="dc-value">{value}</span>
    </span>
  );
}

// Parse a source detail string into chips where possible.
function renderSourceDetail(detail, mod, onPivot) {
  // Structured detail: malware= / tag= / threat= / registrar / count
  const parts = [];
  if (mod.data?.malware) {
    parts.push(<DrillChip key="m" kind="malware" value={mod.data.malware} onPivot={onPivot} />);
    if (mod.data.confidence_level) parts.push(<span key="mc" className="src-meta-inline">conf {mod.data.confidence_level}</span>);
    return <div className="src-detail-rich">{parts}</div>;
  }
  if (mod.data?.family) {
    parts.push(<DrillChip key="m" kind="malware" value={mod.data.family} onPivot={onPivot} />);
    return <div className="src-detail-rich">{parts}</div>;
  }
  if (mod.data?.tags?.length) {
    if (mod.data.threat) parts.push(<span key="t" className="src-meta-inline">threat=<b>{mod.data.threat}</b></span>);
    mod.data.tags.forEach((tag, i) => parts.push(<DrillChip key={"tg"+i} kind="tag" value={tag} onPivot={onPivot} />));
    return <div className="src-detail-rich">{parts}</div>;
  }
  if (mod.data?.threat) {
    parts.push(<span key="t" className="src-meta-inline">threat=<b>{mod.data.threat}</b></span>);
    return <div className="src-detail-rich">{parts}</div>;
  }
  if (mod.data?.registrar) {
    parts.push(<span key="r" className="src-meta-inline">created {mod.data.creation_date}</span>);
    parts.push(<DrillChip key="rg" kind="registrar" value={mod.data.registrar} onPivot={onPivot} />);
    return <div className="src-detail-rich">{parts}</div>;
  }
  // Fallback to raw detail string
  return <span>{detail}</span>;
}

// ─────────── Composite recompute when sources are toggled ───────────

function recomputeComposite(ioc, disabled) {
  // Composite ≈ weighted max of enabled sources with positive scores
  const enabled = Object.entries(ioc.modules).filter(([name, _]) => !disabled.has(name));
  const scores = enabled.map(([_, m]) => m.score).filter(s => s > 0);
  if (scores.length === 0) return 0;
  const max = Math.max(...scores);
  // small agreement boost
  const flagged = scores.length;
  const boost = Math.min(8, flagged * 1.5);
  return Math.min(100, Math.round(max + boost - (scores.length === 1 ? 6 : 0)));
}

// ─────────── Color-blind pattern overlay helper ───────────
// Adds an SVG pattern definition into the DOM so severity colors get hatched fills.
function PatternDefs() {
  return (
    <svg width="0" height="0" style={{position: "absolute"}} aria-hidden="true">
      <defs>
        <pattern id="pat-safe" patternUnits="userSpaceOnUse" width="6" height="6">
          <rect width="6" height="6" fill="#4ade80" /><circle cx="3" cy="3" r="1" fill="#0a0a0a" />
        </pattern>
        <pattern id="pat-low" patternUnits="userSpaceOnUse" width="6" height="6">
          <rect width="6" height="6" fill="#60a5fa" /><rect x="0" y="2" width="6" height="2" fill="#0a0a0a" />
        </pattern>
        <pattern id="pat-med" patternUnits="userSpaceOnUse" width="6" height="6">
          <rect width="6" height="6" fill="#fbbf24" />
          <path d="M0,6 L6,0" stroke="#0a0a0a" strokeWidth="1.5" />
        </pattern>
        <pattern id="pat-high" patternUnits="userSpaceOnUse" width="6" height="6">
          <rect width="6" height="6" fill="#fb923c" />
          <path d="M0,0 L6,6 M0,6 L6,0" stroke="#0a0a0a" strokeWidth="1" />
        </pattern>
        <pattern id="pat-crit" patternUnits="userSpaceOnUse" width="6" height="6">
          <rect width="6" height="6" fill="#f43f5e" />
          <rect x="0" y="0" width="3" height="3" fill="#0a0a0a" />
          <rect x="3" y="3" width="3" height="3" fill="#0a0a0a" />
        </pattern>
      </defs>
    </svg>
  );
}

window.recomputeComposite = recomputeComposite;

// ─────────── Geo + Shodan panel (right of spider) ───────────

function GeoShodanPanel({ ioc }) {
  const data = window.SHODAN_DATA[ioc.id];
  if (!data) return null;

  // Equirectangular projection — 360w × 180h viewBox keeps math trivial
  const W = 360, H = 180;
  const project = (lon, lat) => ({
    x: ((lon + 180) / 360) * W,
    y: ((90 - lat) / 180) * H
  });
  const pos = project(data.lon, data.lat);

  // Dense dot grid — 144x72 = 10,368 candidate cells, ~3000 over land
  const GX = 144, GY = 72;
  const dots = [];
  for (let i = 0; i < GX; i++) {
    for (let j = 0; j < GY; j++) {
      const lon = (i / GX) * 360 - 180;
      const lat = 90 - (j / GY) * 180;
      if (!isLand(lon, lat)) continue;
      const p = project(lon, lat);
      dots.push({ x: p.x, y: p.y });
    }
  }

  return (
    <div className="geo-panel">
      <div className="geo-head">
        <span className="geo-title">NETWORK · GEO</span>
        <span className="geo-meta">shodan · maxmind · {dots.length.toLocaleString()} land cells</span>
      </div>
      <div className="geo-map">
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
          {/* Graticule — meridians + parallels at 30° */}
          {[-150,-120,-90,-60,-30,0,30,60,90,120,150].map(lon => {
            const x = ((lon + 180) / 360) * W;
            return <line key={"m"+lon} x1={x} y1="0" x2={x} y2={H} stroke="#171717" strokeWidth="0.4" />;
          })}
          {[-60,-30,0,30,60].map(lat => {
            const y = ((90 - lat) / 180) * H;
            return <line key={"p"+lat} x1="0" y1={y} x2={W} y2={y} stroke="#171717" strokeWidth="0.4" />;
          })}
          {/* Equator + prime meridian bolder */}
          <line x1="0" y1={H/2} x2={W} y2={H/2} stroke="#262626" strokeWidth="0.6" />
          <line x1={W/2} y1="0" x2={W/2} y2={H} stroke="#262626" strokeWidth="0.6" />
          {/* Tropics + arctic circles (dashed) */}
          {[23.5, -23.5, 66.5, -66.5].map(lat => {
            const y = ((90 - lat) / 180) * H;
            return <line key={"tr"+lat} x1="0" y1={y} x2={W} y2={y} stroke="#202020" strokeWidth="0.3" strokeDasharray="1 2" />;
          })}

          {/* Land dots */}
          {dots.map((d, i) => (
            <rect key={i} x={d.x} y={d.y} width="1.2" height="1.2" fill="#3a3a3a" />
          ))}

          {/* Highlight cells near target — emphasis */}
          {dots.filter(d => Math.hypot(d.x - pos.x, d.y - pos.y) < 18).map((d, i) => (
            <rect key={"h"+i} x={d.x} y={d.y} width="1.2" height="1.2" fill="var(--accent)" opacity="0.5" />
          ))}

          {/* Crosshair */}
          <line x1={pos.x} y1="0" x2={pos.x} y2={H} stroke="var(--accent)" strokeOpacity="0.35" strokeWidth="0.5" strokeDasharray="2 2" />
          <line x1="0" y1={pos.y} x2={W} y2={pos.y} stroke="var(--accent)" strokeOpacity="0.35" strokeWidth="0.5" strokeDasharray="2 2" />

          {/* Pulse */}
          <circle cx={pos.x} cy={pos.y} r="2" fill="none" stroke="var(--accent)" strokeWidth="0.8">
            <animate attributeName="r" from="2" to="14" dur="2.4s" repeatCount="indefinite" />
            <animate attributeName="stroke-opacity" from="1" to="0" dur="2.4s" repeatCount="indefinite" />
          </circle>
          {/* Target dot */}
          <circle cx={pos.x} cy={pos.y} r="2.5" fill="var(--accent)" />
          <rect x={pos.x - 1.5} y={pos.y - 1.5} width="3" height="3" fill="var(--bg)" />
          <rect x={pos.x - 0.6} y={pos.y - 0.6} width="1.2" height="1.2" fill="var(--accent)" />

          {/* Country code label near point */}
          <g transform={`translate(${pos.x + 6}, ${pos.y - 4})`}>
            <rect x="0" y="-6" width={data.country.length * 4 + 4} height="8" fill="var(--accent)" />
            <text x="2" y="0" fill="var(--bg)" fontFamily="JetBrains Mono" fontSize="6" fontWeight="800">{data.country}</text>
          </g>
        </svg>
        <div className="geo-coords">
          <span>{data.lat.toFixed(4)}° N · {data.lon.toFixed(4)}° E</span>
        </div>
        <div className="geo-scale">
          <span className="gs-tick">0</span>
          <span className="gs-line" />
          <span className="gs-tick">EQUATOR</span>
          <span className="gs-line" />
          <span className="gs-tick">{W}°</span>
        </div>
      </div>

      <div className="geo-meta-grid">
        <div className="gm-row">
          <span className="gm-k">COUNTRY</span>
          <span className="gm-v">
            <span className="flag-cc">{data.country}</span> {data.country_name}
          </span>
        </div>
        <div className="gm-row">
          <span className="gm-k">CITY</span>
          <span className="gm-v">{data.city}</span>
        </div>
        <div className="gm-row">
          <span className="gm-k">ASN</span>
          <span className="gm-v"><Copyable text={data.asn}>{data.asn}</Copyable></span>
        </div>
        <div className="gm-row">
          <span className="gm-k">ORG</span>
          <span className="gm-v">{data.org}</span>
        </div>
        {data.hostnames.length > 0 && (
          <div className="gm-row">
            <span className="gm-k">RDNS</span>
            <span className="gm-v">{data.hostnames.join(", ")}</span>
          </div>
        )}
      </div>

      <div className="ports-block">
        <div className="ports-head">
          <span className="ports-title">OPEN PORTS</span>
          <span className="ports-meta">{data.ports.length} services · last scan 4h ago</span>
        </div>
        <div className="ports-list">
          {data.ports.map(p => {
            const s = sevOf(p.risk);
            return (
              <div key={p.port} className="port-row" title={p.banner}>
                <span className="port-num" style={{borderColor: s.fg, color: s.fg}}>{p.port}</span>
                <span className="port-svc">{p.service}</span>
                <span className="port-banner">{p.banner}</span>
                <span className="port-risk" style={{color: s.fg}}>{p.risk > 0 ? `risk ${p.risk}` : "·"}</span>
              </div>
            );
          })}
        </div>
      </div>

      {data.tags.length > 0 && (
        <div className="geo-tags">
          {data.tags.map(t => <span key={t} className="geo-tag">#{t}</span>)}
        </div>
      )}
    </div>
  );
}

// Land-mask — more accurate continent boundaries.
function isLand(lon, lat) {
  // ─ NORTH AMERICA ─
  // Alaska
  if (lon >= -170 && lon <= -141 && lat >= 54 && lat <= 71) return true;
  // Yukon / NWT / mainland Canada
  if (lon >= -141 && lon <= -53 && lat >= 49 && lat <= 70) {
    if (lon > -75 && lat > 60) return lat <= 67; // Quebec
    if (lon > -65 && lat < 55) return false; // Atlantic
    return true;
  }
  // Lower 48 + Mexico
  if (lon >= -125 && lon <= -67 && lat >= 25 && lat <= 49) {
    if (lon < -120 && lat < 32) return false; // baja gap
    return true;
  }
  // Baja California
  if (lon >= -118 && lon <= -109 && lat >= 22 && lat <= 33) return true;
  // Mexico mainland
  if (lon >= -109 && lon <= -86 && lat >= 14 && lat <= 33) return true;
  // Central America
  if (lon >= -92 && lon <= -77 && lat >= 8 && lat <= 18) return true;
  // Greenland
  if (lon >= -55 && lon <= -22 && lat >= 60 && lat <= 83) return true;
  // Caribbean (sparse — Cuba, Hispaniola)
  if (lon >= -85 && lon <= -74 && lat >= 19 && lat <= 23) return true; // Cuba
  if (lon >= -75 && lon <= -68 && lat >= 17 && lat <= 20) return true; // Hispaniola

  // ─ SOUTH AMERICA ─
  if (lon >= -82 && lon <= -34 && lat >= -56 && lat <= 13) {
    // tapered Patagonia
    if (lat < -38 && lon < -72) return false;
    if (lat < -50 && lon > -65) return false;
    return true;
  }

  // ─ EUROPE ─
  // Iberian + France + Italy + Balkans + central
  if (lon >= -10 && lon <= 30 && lat >= 36 && lat <= 60) return true;
  // British Isles
  if (lon >= -10 && lon <= 2 && lat >= 50 && lat <= 60) return true;
  // Scandinavia
  if (lon >= 4 && lon <= 32 && lat >= 55 && lat <= 71) return true;
  // Russia (west)
  if (lon >= 30 && lon <= 60 && lat >= 42 && lat <= 70) return true;

  // ─ AFRICA ─
  // North Africa
  if (lon >= -17 && lon <= 36 && lat >= 4 && lat <= 36) return true;
  // Horn of Africa
  if (lon >= 36 && lon <= 52 && lat >= 0 && lat <= 18) return true;
  // Central + southern
  if (lon >= 8 && lon <= 42 && lat >= -36 && lat <= 4) return true;
  // West Africa coast bulge
  if (lon >= -17 && lon <= 8 && lat >= -6 && lat <= 16) return true;
  // Madagascar
  if (lon >= 43 && lon <= 51 && lat >= -26 && lat <= -12) return true;

  // ─ ASIA ─
  // Middle East
  if (lon >= 34 && lon <= 65 && lat >= 12 && lat <= 42) return true;
  // Russia (siberia) — wide band
  if (lon >= 60 && lon <= 180 && lat >= 50 && lat <= 75) return true;
  // China + Mongolia
  if (lon >= 73 && lon <= 135 && lat >= 18 && lat <= 50) return true;
  // India / subcontinent
  if (lon >= 68 && lon <= 92 && lat >= 7 && lat <= 36) return true;
  // SE Asia (Thailand, Vietnam)
  if (lon >= 92 && lon <= 110 && lat >= 5 && lat <= 28) return true;
  // Korea + Japan
  if (lon >= 124 && lon <= 146 && lat >= 30 && lat <= 46) return true;
  // Indonesia / Philippines (sparse archipelago)
  if (lon >= 95 && lon <= 142 && lat >= -10 && lat <= 6) {
    // skip a couple sea gaps
    if (lon > 105 && lon < 110 && lat > -2 && lat < 3) return false;
    return true;
  }
  // Philippines
  if (lon >= 117 && lon <= 127 && lat >= 5 && lat <= 19) return true;

  // ─ OCEANIA ─
  if (lon >= 113 && lon <= 154 && lat >= -39 && lat <= -10) return true;
  // New Zealand
  if (lon >= 165 && lon <= 179 && lat >= -47 && lat <= -34) return true;
  // PNG
  if (lon >= 140 && lon <= 152 && lat >= -10 && lat <= -2) return true;

  return false;
}

// ─────────── Flag strip (symbolic indicators) ───────────

function FlagStrip({ ioc }) {
  const flags = window.IOC_FLAGS(ioc);
  if (flags.length === 0) return null;
  return (
    <div className="flag-strip">
      {flags.map(f => (
        <div key={f.k} className="iflag" style={{borderColor: f.color, color: f.color}} title={f.title}>
          <span className="iflag-glyph">{f.glyph}</span>
          <span className="iflag-label">{f.label}</span>
        </div>
      ))}
    </div>
  );
}

// ─────────── Explainer popover wrapper ───────────

function Explain({ text, children }) {
  return (
    <span className="explain">
      {children}
      <span className="explain-icon" title={text}>?</span>
    </span>
  );
}

// ─────────── Boot screen / cold-start animation ───────────

function BootScreen({ onDone }) {
  const [lines, setLines] = useState([]);
  const [done, setDone] = useState(false);

  useEffect(() => {
    const seq = [
      { t: 50,   text: "[boot] shadowscope v0.9.2 · ioc enrichment", cls: "" },
      { t: 150,  text: "[boot] loading config /etc/shadowscope.yml …  ok", cls: "" },
      { t: 250,  text: "[boot] initializing heuristics engine …       ok", cls: "" },
      { t: 350,  text: "[probe] VirusTotal           api.virustotal.com   ok  412ms", cls: "ok" },
      { t: 420,  text: "[probe] AbuseIPDB            api.abuseipdb.com    ok  188ms", cls: "ok" },
      { t: 480,  text: "[probe] URLhaus              urlhaus-api.abuse.ch ok   95ms", cls: "ok" },
      { t: 530,  text: "[probe] ThreatFox            threatfox-api.abuse  ok  142ms", cls: "ok" },
      { t: 580,  text: "[probe] Pulsedive            pulsedive.com        ok  280ms", cls: "ok" },
      { t: 630,  text: "[probe] CISA KEV · NVD · EPSS                    ok", cls: "ok" },
      { t: 690,  text: "[probe] crt.sh · WHOIS · MISP · OpenPhish        ok", cls: "ok" },
      { t: 740,  text: "[probe] GreyNoise            api.greynoise.io     deg 1340ms", cls: "warn" },
      { t: 790,  text: "[probe] Shodan               api.shodan.io        no key", cls: "warn" },
      { t: 840,  text: "[probe] AlienVault OTX                            no key", cls: "warn" },
      { t: 890,  text: "[probe] IPQualityScore                            ✕ unreachable", cls: "err" },
      { t: 980,  text: "[boot] 18/21 sources operational", cls: "" },
      { t: 1060, text: "[boot] worker pool · 8 threads", cls: "" },
      { t: 1140, text: "[boot] watch loop · 12 IOCs tracked", cls: "" },
      { t: 1220, text: "[boot] ready ▌", cls: "ok-bold" }
    ];
    let cancelled = false;
    seq.forEach(s => setTimeout(() => { if (!cancelled) setLines(prev => [...prev, s]); }, s.t));
    setTimeout(() => { if (!cancelled) setDone(true); }, 1500);
    setTimeout(() => { if (!cancelled) onDone(); }, 2200);
    return () => { cancelled = true; };
  }, []);

  return (
    <div className={`boot-screen ${done ? "fading" : ""}`}>
      <div className="boot-inner">
        <div className="boot-brand">
          <svg width="56" height="56" viewBox="0 0 28 28" fill="none">
            <circle cx="14" cy="14" r="10.5" stroke="var(--ink)" strokeWidth="0.8" strokeOpacity="0.4" fill="none" />
            <path d="M 2 8 L 2 2 L 8 2"   stroke="var(--ink)" strokeWidth="2" />
            <path d="M 26 8 L 26 2 L 20 2" stroke="var(--ink)" strokeWidth="2" />
            <path d="M 2 20 L 2 26 L 8 26" stroke="var(--ink)" strokeWidth="2" />
            <path d="M 26 20 L 26 26 L 20 26" stroke="var(--ink)" strokeWidth="2" />
            <rect x="13.5" y="6"  width="1" height="3" fill="var(--ink)" />
            <rect x="13.5" y="19" width="1" height="3" fill="var(--ink)" />
            <rect x="6"  y="13.5" width="3" height="1" fill="var(--ink)" />
            <rect x="19" y="13.5" width="3" height="1" fill="var(--ink)" />
            <polygon points="9,9 14,9 9,14" fill="var(--accent)" />
            <polygon points="19,19 14,19 19,14" fill="var(--accent)" />
          </svg>
          <div className="boot-wordmark">
            <span className="bw-name">SHADOWSCOPE</span>
            <span className="bw-tag">// indicator of compromise · enrichment</span>
          </div>
        </div>
        <div className="boot-log">
          {lines.map((l, i) => (
            <div key={i} className={`boot-line boot-${l.cls}`}>{l.text}</div>
          ))}
        </div>
      </div>
    </div>
  );
}

window.GeoShodanPanel = GeoShodanPanel;
window.FlagStrip = FlagStrip;
window.Explain = Explain;
window.BootScreen = BootScreen;
