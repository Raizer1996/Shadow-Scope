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

  // Build event timeline from real WHOIS / agreement / enrichment data.
  // Decorative "PASSIVE DNS PICKUP" / "NS CHANGE" placeholders from the
  // mock prototype are removed — they would lie about events we can't
  // observe. Real change-tracking lands once watch-mode persists deltas.
  const updated = Array.isArray(whois.updated_date) ? whois.updated_date[0] : whois.updated_date;
  const expires = Array.isArray(whois.expiration_date) ? whois.expiration_date[0] : whois.expiration_date;
  const events = [
    { ago: 0, label: "ENRICHED", detail: <Relative iso={ioc.enriched_at} />, glyph: "▶", emphasis: "now", ts: ioc.enriched_at.slice(0,10) },
    ioc.agreement.sources_flagged > 0 ? { ago: 1, label: "SOURCES FLAGGED", detail: `${ioc.agreement.sources_flagged}/${ioc.agreement.sources_total} · ${ioc.agreement.consensus} consensus`, glyph: "▲", emphasis: ioc.agreement.consensus === "high" ? "alert" : null, ts: dateAgo(1) } : null,
    updated ? { ago: Math.floor((now - new Date(updated)) / 86400000), label: "WHOIS UPDATED", detail: "registry record modified", glyph: "◇", emphasis: null, ts: String(updated).slice(0, 10) } : null,
    { ago: ageDays, label: "REGISTERED", detail: whois.registrar || "unknown registrar", glyph: "◆", emphasis: ageDays < 30 ? "warn" : null, ts: String(whois.creation_date).slice(0, 10) },
    expires ? { ago: -Math.floor((new Date(expires) - now) / 86400000), label: "EXPIRES", detail: "registration valid until", glyph: "◇", emphasis: null, ts: String(expires).slice(0, 10) } : null,
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

// ─────────── CVE feature block (NVD / EPSS / CISA KEV) ───────────
//
// Surfaces the CVE-specific data that the per-source rows can't fit:
// the description, CVSS vector, CWE list, affected products, and any
// KEV ransomware flag. Renders only for ioc.type === "cve".

function CveBlock({ ioc }) {
  if (ioc.type !== "cve") return null;
  const nvd = ioc.modules.NVD?.data || {};
  const epss = ioc.modules.EPSS?.data || {};
  const kev = ioc.modules.KEV?.data || {};

  const desc = ((nvd.descriptions || []).find(d => d.lang === "en") || {}).value || "";
  const cvssBlock = ((nvd.metrics || {}).cvssMetricV31 || [])[0] || {};
  const cvss = cvssBlock.cvssData || {};
  const cwes = (nvd.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(v => v.startsWith("CWE-"));
  const refs = (nvd.references || []).slice(0, 6);

  const epssProb = epss.epss != null ? Math.round(epss.epss * 10000) / 100 : null;
  const epssPct = epss.percentile != null ? Math.round(epss.percentile * 10000) / 100 : null;

  const ransomware = kev.knownRansomwareCampaignUse === "Known";
  const inKev = Boolean(kev.cveID || kev.vulnerabilityName);

  if (!desc && !cvss.baseScore && !inKev && epssProb == null) return null;

  return (
    <section className="cve-block">
      <div className="sec-head">
        <span className="sec-title">CVE · INTELLIGENCE</span>
        <span className="sec-meta">{ioc.ioc} · NVD + EPSS + CISA KEV</span>
      </div>

      <div className="cve-grid">
        {cvss.baseScore != null && (
          <div className="cve-card">
            <div className="ws-k">CVSS v3.1</div>
            <div className="ws-v" style={{ color: cvss.baseScore >= 9 ? "var(--bad)" : cvss.baseScore >= 7 ? "var(--high)" : cvss.baseScore >= 4 ? "var(--med)" : "var(--safe)" }}>
              {cvss.baseScore} <span className="dim">/ 10</span>
            </div>
            <div className="ws-sub dim">{cvss.baseSeverity}</div>
          </div>
        )}
        {epssProb != null && (
          <div className="cve-card">
            <div className="ws-k">EPSS</div>
            <div className="ws-v" style={{ color: epssProb >= 50 ? "var(--bad)" : epssProb >= 10 ? "var(--high)" : "var(--ink)" }}>{epssProb}%</div>
            <div className="ws-sub dim">{epssPct}% percentile</div>
          </div>
        )}
        {inKev && (
          <div className="cve-card" style={{ borderColor: "var(--bad)" }}>
            <div className="ws-k">CISA KEV</div>
            <div className="ws-v" style={{ color: "var(--bad)" }}>LISTED</div>
            <div className="ws-sub dim">{kev.dateAdded ? `added ${kev.dateAdded}` : ""}</div>
          </div>
        )}
        {ransomware && (
          <div className="cve-card" style={{ borderColor: "var(--crit)" }}>
            <div className="ws-k">RANSOMWARE</div>
            <div className="ws-v" style={{ color: "var(--crit)" }}>KNOWN-USED</div>
            <div className="ws-sub dim">in ransomware campaigns</div>
          </div>
        )}
      </div>

      {cvss.vectorString && (
        <div className="cve-vector">
          <span className="ws-k">VECTOR</span>
          <code className="cve-vector-v">{cvss.vectorString}</code>
        </div>
      )}

      {desc && (
        <div className="cve-desc">
          <span className="ws-k">DESCRIPTION</span>
          <p>{desc}</p>
        </div>
      )}

      {cwes.length > 0 && (
        <div className="cve-cwes">
          <span className="ws-k">CWE</span>
          <span className="cve-cwes-list">
            {cwes.map(cwe => <a key={cwe} href={`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-","")}.html`} target="_blank" rel="noreferrer" className="cwe-chip">{cwe}</a>)}
          </span>
        </div>
      )}

      {refs.length > 0 && (
        <div className="cve-refs">
          <div className="ws-k">REFERENCES · {(nvd.references || []).length}</div>
          <div className="cve-refs-list">
            {refs.map((r, i) => {
              const tags = (r.tags || []).slice(0, 3).join(" · ") || "link";
              return (
                <a key={i} href={r.url} target="_blank" rel="noreferrer" className="cve-ref">
                  <span className="cve-ref-tag">{tags}</span>
                  <span className="cve-ref-url">{r.url}</span>
                </a>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}

// ─────────── Certificate-transparency subdomain expander (crt.sh) ───────────

function CrtshBlock({ ioc, fmt }) {
  if (ioc.type !== "domain") return null;
  const data = ioc.modules["crt.sh"]?.data;
  if (!data || !data.total) return null;

  const subs = (data.unique_subdomains || []);
  const issuers = (data.top_issuers || []).slice(0, 5);
  const mr = data.most_recent || {};

  const [showAll, setShowAll] = React.useState(false);
  const visible = showAll ? subs : subs.slice(0, 16);

  return (
    <section className="crtsh-block">
      <div className="sec-head">
        <span className="sec-title">CERTIFICATE TRANSPARENCY</span>
        <span className="sec-meta">{data.total} certificates · {data.subdomain_count} unique subdomains</span>
        <span className="sec-meta dim">via crt.sh</span>
      </div>

      <div className="crtsh-grid">
        {mr.not_before && (
          <div className="cve-card">
            <div className="ws-k">MOST RECENT</div>
            <div className="ws-v">{String(mr.not_before).slice(0, 10)}</div>
            <div className="ws-sub dim">{(mr.issuer || "").slice(0, 36)}</div>
          </div>
        )}
        {issuers.length > 0 && (
          <div className="cve-card crtsh-issuers">
            <div className="ws-k">TOP ISSUERS</div>
            <div className="crtsh-issuer-list">
              {issuers.map(i => (
                <div key={i.issuer} className="crtsh-issuer-row">
                  <span className="ci-count">{i.count}</span>
                  <span className="ci-name">{i.issuer.replace(/^.*?CN=/, "").slice(0, 38)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {subs.length > 0 && (
        <div className="crtsh-subs">
          <div className="ws-k">SUBDOMAINS · {subs.length} sample of {data.subdomain_count}</div>
          <div className="crtsh-sub-list">
            {visible.map(s => <span key={s} className="dr-sub">{fmt(s)}</span>)}
          </div>
          {subs.length > 16 && (
            <button className="crtsh-toggle" onClick={() => setShowAll(s => !s)}>
              {showAll ? "show fewer" : `show all ${subs.length}`}
            </button>
          )}
        </div>
      )}
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

// ─────────── IP Core + Network Geo (split-panel, Leaflet-backed) ───────────
//
// IpCorePanel renders the IP identity column (country, ASN, org, hostnames,
// open ports, tags). NetworkGeoPanel renders the Leaflet map. Both consume
// ioc.geo (live backend) when present, and fall back to the mock
// window.SHODAN_DATA[ioc.id] used by the design prototype so screenshots
// still render with the canned eight-IOC set.

function _geoFor(ioc) {
  if (ioc.geo && (ioc.geo.lat != null || ioc.geo.country)) return ioc.geo;
  const mock = window.SHODAN_DATA && window.SHODAN_DATA[ioc.id];
  if (mock) {
    return {
      country: mock.country,
      country_name: mock.country_name,
      city: mock.city,
      region: mock.region || "",
      lat: mock.lat,
      lon: mock.lon,
      asn: mock.asn,
      org: mock.org,
      hostnames: mock.hostnames || [],
      ports: (mock.ports || []).map(p => typeof p === "object" ? p : { port: p }),
      tags: mock.tags || []
    };
  }
  return null;
}

function IpCorePanel({ ioc, fmt }) {
  const g = _geoFor(ioc);
  if (!g) return null;
  const ports = g.ports || [];
  return (
    <div className="ip-core-panel">
      <div className="ipc-head">
        <span className="ipc-title">IP CORE</span>
        <span className="ipc-meta">identity · routing</span>
      </div>
      <div className="ipc-grid">
        {g.country && (
          <div className="ipc-row">
            <span className="ipc-k">COUNTRY</span>
            <span className="ipc-v">
              <span className="flag-cc">{g.country}</span>{g.country_name ? " " + g.country_name : ""}
            </span>
          </div>
        )}
        {g.city && (
          <div className="ipc-row">
            <span className="ipc-k">CITY</span>
            <span className="ipc-v">{g.city}{g.region ? " · " + g.region : ""}</span>
          </div>
        )}
        {g.asn && (
          <div className="ipc-row">
            <span className="ipc-k">ASN</span>
            <span className="ipc-v"><Copyable text={String(g.asn)}>{g.asn}</Copyable></span>
          </div>
        )}
        {g.org && (
          <div className="ipc-row">
            <span className="ipc-k">ORG</span>
            <span className="ipc-v">{g.org}</span>
          </div>
        )}
        {g.hostnames && g.hostnames.length > 0 && (
          <div className="ipc-row">
            <span className="ipc-k">RDNS</span>
            <span className="ipc-v">{g.hostnames.filter(Boolean).join(", ")}</span>
          </div>
        )}
      </div>

      {ports.length > 0 && (
        <div className="ipc-ports">
          <div className="ipc-ports-head">
            <span className="ipc-ports-title">OPEN PORTS</span>
            <span className="ipc-ports-meta">{ports.length} services</span>
          </div>
          <div className="ipc-ports-list">
            {ports.slice(0, 8).map((p, i) => {
              const port = typeof p === "object" ? p.port : p;
              const svc = (typeof p === "object" && p.service) ? p.service : "";
              const risk = (typeof p === "object" && typeof p.risk === "number") ? p.risk : 0;
              const s = sevOf(risk);
              return (
                <div key={port + ":" + i} className="port-row" title={typeof p === "object" ? p.banner : ""}>
                  <span className="port-num" style={{ borderColor: s.fg, color: s.fg }}>{port}</span>
                  <span className="port-svc">{svc || "·"}</span>
                  <span className="port-risk" style={{ color: s.fg }}>{risk > 0 ? `r${risk}` : ""}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {g.tags && g.tags.length > 0 && (
        <div className="ipc-tags">
          {g.tags.slice(0, 6).map(t => <span key={t} className="geo-tag">#{t}</span>)}
        </div>
      )}
    </div>
  );
}

// Leaflet map panel — real OpenStreetMap tiles. Initialised once per IOC
// via useEffect; cleaned up when the IOC changes so we don't leak handles.
function NetworkGeoPanel({ ioc }) {
  const g = _geoFor(ioc);
  const ref = React.useRef(null);
  const mapRef = React.useRef(null);

  React.useEffect(() => {
    if (!g || g.lat == null || g.lon == null) return;
    if (typeof L === "undefined") return;  // Leaflet not loaded — silent skip
    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
    }
    const map = L.map(ref.current, {
      center: [g.lat, g.lon],
      zoom: 4,
      zoomControl: true,
      attributionControl: true,
      preferCanvas: true,
    });
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
      attribution: '© OSM',
      className: "ss-tile",
    }).addTo(map);
    L.circleMarker([g.lat, g.lon], {
      radius: 8,
      color: getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#ff6b35",
      weight: 2,
      fillOpacity: 0.5,
    }).addTo(map).bindPopup(`<b>${ioc.ioc}</b><br>${g.city || ""} ${g.country || ""}`);
    mapRef.current = map;
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [ioc.id, g && g.lat, g && g.lon]);

  if (!g) return null;
  return (
    <div className="net-geo-panel">
      <div className="ngp-head">
        <span className="ngp-title">NETWORK GEO</span>
        <span className="ngp-meta">
          {g.lat != null && g.lon != null
            ? `${g.lat.toFixed(3)}° · ${g.lon.toFixed(3)}°`
            : "no coords"}
        </span>
      </div>
      <div ref={ref} className="ngp-map" />
    </div>
  );
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
