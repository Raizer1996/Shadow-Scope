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
        <span className="sec-title glitch" data-text="MITRE ATT&CK">MITRE ATT&CK</span>
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
        <span className="sec-title glitch" data-text="WHOIS · LIFECYCLE">WHOIS · LIFECYCLE</span>
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

// ─────────── Named-threat strip ───────────
//
// Cross-source aggregation of *named* threat attribution: OTX pulse
// adversaries + malware families, VirusTotal popular_threat_classification,
// Pulsedive threats, ThreatFox malware, URLhaus threat + tags. The
// strip de-duplicates and shows the analyst at a glance "what is this
// IOC actually attributed to?" without needing to expand every source.

const THREAT_KINDS = {
  adversary: { label: "ADV",   className: "tk-adv"   },
  family:    { label: "FAM",   className: "tk-fam"   },
  threat:    { label: "THR",   className: "tk-thr"   },
  tag:       { label: "TAG",   className: "tk-tag"   },
};

function collectThreats(ioc) {
  const out = [];
  const push = (kind, value, source) => {
    if (!value) return;
    const v = typeof value === "string" ? value : (value.name || value.target || value.display_name || "");
    if (!v) return;
    const norm = String(v).trim();
    if (!norm) return;
    out.push({ kind, value: norm, source });
  };

  // OTX — adversary attribution + malware families from pulses
  const otx = ioc.modules.OTX?.data;
  if (otx) {
    const pulses = (otx.pulse_info?.pulses || []).slice(0, 25);
    for (const p of pulses) {
      if (p.adversary) push("adversary", p.adversary, "OTX");
      for (const mf of (p.malware_families || [])) push("family", mf, "OTX");
      for (const tag of (p.tags || []).slice(0, 3)) push("tag", tag, "OTX");
    }
  }

  // VirusTotal — popular_threat_classification
  const vt = ioc.modules.VirusTotal?.data;
  if (vt) {
    const ptc = vt.popular_threat_classification || {};
    if (ptc.suggested_threat_label) push("family", ptc.suggested_threat_label, "VT");
    for (const cat of (ptc.popular_threat_category || []).slice(0, 3)) push("threat", cat, "VT");
    for (const tag of (vt.tags || []).slice(0, 6)) push("tag", tag, "VT");
  }

  // Pulsedive — threats array
  const pd = ioc.modules.Pulsedive?.data;
  if (pd) {
    for (const t of (pd.threats || []).slice(0, 6)) push("threat", t, "Pulsedive");
  }

  // ThreatFox — malware family
  const tf = ioc.modules.ThreatFox?.data;
  if (tf?.malware) push("family", tf.malware, "ThreatFox");

  // URLhaus — threat + tags
  const uh = ioc.modules.URLhaus?.data;
  if (uh) {
    if (uh.threat) push("threat", uh.threat, "URLhaus");
    for (const tag of (uh.tags || []).slice(0, 3)) push("tag", tag, "URLhaus");
  }

  // MalwareBazaar — signature / malware family
  const mb = ioc.modules.MalwareBazaar?.data;
  if (mb) {
    if (mb.signature) push("family", mb.signature, "MalwareBazaar");
    for (const tag of (mb.tags || []).slice(0, 3)) push("tag", tag, "MalwareBazaar");
  }

  // De-dup, keep first-seen ordering, with priority adversary > family > threat > tag
  const order = { adversary: 0, family: 1, threat: 2, tag: 3 };
  const seen = new Map();
  for (const t of out) {
    const key = t.kind + ":" + t.value.toLowerCase();
    if (!seen.has(key) || order[t.kind] < order[seen.get(key).kind]) {
      seen.set(key, t);
    }
  }
  return Array.from(seen.values()).sort((a, b) => order[a.kind] - order[b.kind]);
}

function NamedThreatStrip({ ioc, compact = false }) {
  const threats = collectThreats(ioc);
  if (threats.length === 0) return null;

  const adv = threats.filter(t => t.kind === "adversary");
  const fam = threats.filter(t => t.kind === "family");
  const thr = threats.filter(t => t.kind === "threat");
  // Tag count caps lower in compact mode — hero-meta is real-estate constrained.
  const tag = threats.filter(t => t.kind === "tag").slice(0, compact ? 6 : 12);

  return (
    <section className={`threat-strip ${compact ? "threat-strip-compact" : ""}`}>
      <div className="ts-head">
        <span className={compact ? "sec-title-sm" : "sec-title glitch"} data-text="NAMED ATTRIBUTION">NAMED ATTRIBUTION</span>
        <span className="sec-meta">{adv.length} adv · {fam.length} fam · {thr.length} threat · {tag.length} tag</span>
        {!compact && (
          <span className="sec-meta dim">de-duplicated across OTX / VT / Pulsedive / ThreatFox / URLhaus / MalwareBazaar</span>
        )}
      </div>
      <div className="ts-body">
        {adv.length > 0 && <ThreatRow kind="adversary" items={adv} />}
        {fam.length > 0 && <ThreatRow kind="family"    items={fam} />}
        {thr.length > 0 && <ThreatRow kind="threat"    items={thr} />}
        {tag.length > 0 && <ThreatRow kind="tag"       items={tag} />}
      </div>
    </section>
  );
}

function ThreatRow({ kind, items }) {
  const k = THREAT_KINDS[kind] || { label: "?" };
  return (
    <div className="ts-row">
      <span className={`ts-kind ${k.className}`}>{k.label}</span>
      <div className="ts-chips">
        {items.map(t => (
          <span key={t.value} className={`ts-chip ${k.className}`} title={`reported by ${t.source}`}>
            <span className="ts-chip-val">{t.value}</span>
            <span className="ts-chip-src">{t.source}</span>
          </span>
        ))}
      </div>
    </div>
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
  const core = ioc.core || null;

  const desc = ((nvd.descriptions || []).find(d => d.lang === "en") || {}).value || "";
  const cvssBlock = ((nvd.metrics || {}).cvssMetricV31 || [])[0] || {};
  const cvss = cvssBlock.cvssData || {};
  const cwes = Array.from(new Set((nvd.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(v => v.startsWith("CWE-"))));
  const refs = (nvd.references || []).slice(0, 6);

  const epssProb = epss.epss != null ? Math.round(epss.epss * 10000) / 100 : null;
  const epssPct = epss.percentile != null ? Math.round(epss.percentile * 10000) / 100 : null;
  const epssRank = core?.epss?.rank_text || (epssPct != null ? `${epssPct}% percentile` : "");

  const ransomware = kev.knownRansomwareCampaignUse === "Known";
  const inKev = Boolean(kev.cveID || kev.vulnerabilityName);
  const kevDue = core?.kev?.due_date || kev.dueDate || "";
  const kevAction = core?.kev?.required_action || kev.requiredAction || "";
  const kevVendor = core?.kev?.vendor || kev.vendorProject || "";
  const kevProduct = core?.kev?.product || kev.product || "";

  const affected = core?.affected || [];

  if (!desc && !cvss.baseScore && !inKev && epssProb == null) return null;

  return (
    <section className="cve-block">
      <div className="sec-head">
        <span className="sec-title glitch" data-text="CVE · INTELLIGENCE">CVE · INTELLIGENCE</span>
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
            <div className="ws-sub dim">{epssRank}</div>
          </div>
        )}
        {inKev && (
          <div className="cve-card" style={{ borderColor: "var(--bad)" }}>
            <div className="ws-k">CISA KEV</div>
            <div className="ws-v" style={{ color: "var(--bad)" }}>LISTED</div>
            <div className="ws-sub dim">
              {kev.dateAdded ? `added ${kev.dateAdded}` : ""}
              {kevDue ? <><br/>patch by {kevDue}</> : null}
            </div>
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

      {inKev && (kevVendor || kevProduct || kevAction) && (
        <div className="cve-kev-detail">
          <span className="ws-k">CISA KEV DETAIL</span>
          <div className="cve-kev-body">
            {(kevVendor || kevProduct) && (
              <div className="cve-kev-row"><b>Affected:</b> {kevVendor} {kevProduct}</div>
            )}
            {kevAction && <div className="cve-kev-row"><b>Required action:</b> {kevAction}</div>}
            {core?.kev?.known_ransomware && (
              <div className="cve-kev-row" style={{ color: "var(--crit)" }}>
                <b>Known used in ransomware campaigns.</b>
              </div>
            )}
          </div>
        </div>
      )}

      {affected.length > 0 && (
        <div className="cve-affected">
          <span className="ws-k">AFFECTED PRODUCTS · {affected.length}</span>
          <div className="cve-affected-list">
            {affected.slice(0, 12).map((cpe, i) => (
              <code key={i} className="cpe-chip" title={cpe}>{cpe}</code>
            ))}
            {affected.length > 12 && <span className="dim">… +{affected.length - 12} more</span>}
          </div>
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

// ─────────── Hash Core — file identity, family, sandbox, campaign ───────────

function HashCorePanel({ ioc }) {
  if (ioc.type !== "hash") return null;
  const c = ioc.core || {};
  const id = c.identity || {};
  const fm = c.file_meta || {};
  const det = c.detections || {};
  const vt = det.vt_stats || {};
  const totalEngines = ["malicious", "suspicious", "undetected", "harmless"]
    .reduce((s, k) => s + (vt[k] || 0), 0);
  const mal = vt.malicious || 0;
  if (!id.sha256 && !id.sha1 && !id.md5 && !c.families?.length && !c.campaigns?.length) return null;
  const fmtSize = n => n == null ? "" :
    n < 1024 ? `${n} B` :
    n < 1048576 ? `${(n/1024).toFixed(1)} KB` :
    `${(n/1048576).toFixed(2)} MB`;

  return (
    <section className="hash-core-panel">
      <div className="sec-head">
        <span className="sec-title glitch" data-text="HASH CORE">HASH CORE</span>
        <span className="sec-meta">file identity · family · detection</span>
      </div>

      <div className="hash-grid">
        {id.sha256 && <div className="hash-row"><span className="ws-k">SHA256</span><Copyable text={id.sha256}><code className="hash-v">{id.sha256}</code></Copyable></div>}
        {id.sha1 && <div className="hash-row"><span className="ws-k">SHA1</span><Copyable text={id.sha1}><code className="hash-v">{id.sha1}</code></Copyable></div>}
        {id.md5 && <div className="hash-row"><span className="ws-k">MD5</span><Copyable text={id.md5}><code className="hash-v">{id.md5}</code></Copyable></div>}
        {id.tlsh && <div className="hash-row"><span className="ws-k">TLSH</span><code className="hash-v">{id.tlsh}</code></div>}
        {id.ssdeep && <div className="hash-row"><span className="ws-k">SSDEEP</span><code className="hash-v">{id.ssdeep}</code></div>}
        {id.authentihash && <div className="hash-row"><span className="ws-k">AUTHHASH</span><code className="hash-v">{id.authentihash}</code></div>}

        {fm.magic && <div className="hash-row"><span className="ws-k">FILE TYPE</span><span className="hash-v">{fm.magic}</span></div>}
        {fm.file_type && fm.file_type !== fm.magic && <div className="hash-row"><span className="ws-k">CATEGORY</span><span className="hash-v">{fm.file_type}{fm.magika ? <span className="dim"> · {fm.magika}</span> : null}</span></div>}
        {fm.file_size != null && <div className="hash-row"><span className="ws-k">SIZE</span><span className="hash-v">{fmtSize(fm.file_size)}</span></div>}
        {fm.meaningful_name && <div className="hash-row"><span className="ws-k">PRIMARY NAME</span><span className="hash-v">{fm.meaningful_name}</span></div>}
        {fm.names?.length > 0 && (
          <div className="hash-row">
            <span className="ws-k">FILENAMES · {fm.names.length}</span>
            <span className="hash-v">{fm.names.slice(0, 6).map((n, i) => <span key={i} className="filename-chip">{n}</span>)}
              {fm.names.length > 6 && <span className="dim"> +{fm.names.length - 6}</span>}
            </span>
          </div>
        )}
        {(fm.first_submission || fm.last_submission) && (
          <div className="hash-row">
            <span className="ws-k">SEEN</span>
            <span className="hash-v dim">
              {fm.first_submission ? `first ${typeof fm.first_submission === 'number' ? new Date(fm.first_submission*1000).toISOString().slice(0,10) : fm.first_submission}` : ""}
              {fm.last_submission ? ` · last ${typeof fm.last_submission === 'number' ? new Date(fm.last_submission*1000).toISOString().slice(0,10) : fm.last_submission}` : ""}
            </span>
          </div>
        )}
      </div>

      {totalEngines > 0 && (
        <div className="hash-detect">
          <span className="ws-k">VT VERDICT</span>
          <span className="hash-v">
            <span style={{ color: mal >= 10 ? "var(--bad)" : mal > 0 ? "var(--high)" : "var(--ink)" }}>
              {mal} / {totalEngines} engines malicious
            </span>
            {det.threatfox_confidence != null && <span className="dim"> · ThreatFox conf {det.threatfox_confidence}</span>}
            {det.mb_submissions != null && <span className="dim"> · MB submissions {det.mb_submissions}</span>}
          </span>
        </div>
      )}

      {(c.families?.length > 0) && (
        <div className="hash-family">
          <span className="ws-k">FAMILY</span>
          <span className="hash-v">
            {c.families.map(f => <span key={f} className="family-chip">{f}</span>)}
            {c.family_sources && Object.keys(c.family_sources).length > 0 && (
              <span className="dim"> · sources: {Object.keys(c.family_sources).join(", ")}</span>
            )}
          </span>
        </div>
      )}

      {c.yara_hits?.length > 0 && (
        <div className="hash-yara">
          <span className="ws-k">YARA · {c.yara_hits.length}</span>
          <div className="yara-list">
            {c.yara_hits.map((y, i) => (
              <div key={i} className="yara-row">
                <span className="yara-rule">{y.rule}</span>
                {y.author && <span className="dim"> by {y.author}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {(c.pe?.imphash || c.pe?.sections > 0) && (
        <div className="hash-pe">
          <span className="ws-k">PE</span>
          <span className="hash-v">
            {c.pe.imphash && <code>imphash={c.pe.imphash}</code>}
            {c.pe.sections > 0 && <span className="dim"> · {c.pe.sections} sections</span>}
          </span>
        </div>
      )}

      {c.tags?.length > 0 && (
        <div className="hash-tags">
          <span className="ws-k">TAGS</span>
          <span className="hash-v">{c.tags.slice(0, 20).map(t => <span key={t} className="geo-tag">#{t}</span>)}</span>
        </div>
      )}

      {c.c2_pivot && (
        <div className="hash-c2">
          <span className="ws-k">C2 PIVOT</span>
          <span className="hash-v"><Copyable text={c.c2_pivot}><code>{c.c2_pivot}</code></Copyable> <span className="dim">(SSLBL)</span></span>
        </div>
      )}

      {c.campaigns?.length > 0 && (
        <div className="hash-campaigns">
          <span className="ws-k">CAMPAIGNS · OTX · {c.campaigns.length}</span>
          <div className="campaigns-list">
            {c.campaigns.slice(0, 6).map((p, i) => (
              <div key={i} className="campaign-row">
                <span className="campaign-name">{p.name}</span>
                {p.adversary && <span className="dim"> · {p.adversary}</span>}
                {p.malware_families?.length > 0 && (
                  <span className="campaign-fams">
                    {p.malware_families.slice(0, 4).map(f => <span key={f} className="family-chip-sm">{f}</span>)}
                  </span>
                )}
                {p.attack_ids?.length > 0 && (
                  <span className="campaign-ttps">
                    {p.attack_ids.slice(0, 4).map(a => <span key={a} className="ttp-chip">{a}</span>)}
                  </span>
                )}
              </div>
            ))}
            {c.campaigns.length > 6 && <span className="dim">… +{c.campaigns.length - 6} more</span>}
          </div>
        </div>
      )}
    </section>
  );
}

// ─────────── Domain Core — categories, popularity, TLS, payloads, campaigns ───────────

function DomainCorePanel({ ioc }) {
  if (ioc.type !== "domain") return null;
  const c = ioc.core || {};
  const det = c.detections || {};
  const tls = c.tls || {};
  const hasAny = (c.tls && (tls.subject_cn || tls.issuer_cn || tls.jarm))
    || c.payloads?.length
    || c.campaigns?.length
    || Object.keys(c.categories || {}).length
    || Object.keys(c.popularity || {}).length
    || c.dns_records?.length
    || (det.vt && Object.keys(det.vt).length)
    || det.threatfox_family || det.urlscan_verdict || det.pulsedive_risk;
  if (!hasAny) return null;

  const cats = Object.entries(c.categories || {});
  const popularity = Object.entries(c.popularity || {});

  return (
    <section className="domain-core-panel">
      <div className="sec-head">
        <span className="sec-title glitch" data-text="DOMAIN CORE">DOMAIN CORE</span>
        <span className="sec-meta">classification · TLS · attribution</span>
      </div>

      {(tls.subject_cn || tls.issuer_cn || tls.jarm) && (
        <div className="domain-row">
          <span className="ws-k">TLS CERT</span>
          <span className="ws-v">
            {tls.subject_cn ? <>CN={tls.subject_cn}{" "}</> : null}
            {tls.issuer_cn ? <span className="dim">issuer={tls.issuer_cn}{" "}</span> : null}
            {tls.not_after ? <span className="dim">exp={tls.not_after}</span> : null}
            {tls.jarm ? <div className="dim">JARM={tls.jarm}</div> : null}
          </span>
        </div>
      )}

      {cats.length > 0 && (
        <div className="domain-row">
          <span className="ws-k">CATEGORIES · {cats.length}</span>
          <span className="ws-v">{cats.slice(0, 8).map(([src, cat]) => <span key={src} className="cat-chip" title={src}>{cat}</span>)}</span>
        </div>
      )}

      {popularity.length > 0 && (
        <div className="domain-row">
          <span className="ws-k">POPULARITY</span>
          <span className="ws-v">{popularity.map(([src, info]) => {
            const rank = (info && info.rank != null) ? info.rank : info;
            return <span key={src} className="rank-chip">{src}: #{rank}</span>;
          })}</span>
        </div>
      )}

      {(det.vt && Object.keys(det.vt).length > 0 || det.threatfox_family || det.urlscan_verdict || det.pulsedive_risk) && (
        <div className="domain-row">
          <span className="ws-k">DETECTIONS</span>
          <span className="ws-v">
            {det.vt?.malicious != null && (
              <span className="det-chip det-vt">VT: {det.vt.malicious}/{(det.vt.malicious||0)+(det.vt.suspicious||0)+(det.vt.undetected||0)+(det.vt.harmless||0)}</span>
            )}
            {det.threatfox_family && <span className="det-chip det-tf">ThreatFox: {det.threatfox_family}</span>}
            {det.urlscan_verdict && <span className="det-chip det-us">URLscan: {det.urlscan_verdict}</span>}
            {det.pulsedive_risk && <span className="det-chip det-pd">Pulsedive: {det.pulsedive_risk}</span>}
          </span>
        </div>
      )}

      {c.dns_records?.length > 0 && (
        <div className="domain-row">
          <span className="ws-k">DNS · {c.dns_records.length}</span>
          <div className="dns-list">
            {c.dns_records.slice(0, 8).map((r, i) => (
              <code key={i} className="dns-row">
                <span className="dns-type">{r.type}</span> {r.value} {r.ttl ? <span className="dim">ttl={r.ttl}</span> : null}
              </code>
            ))}
          </div>
        </div>
      )}

      {c.payloads?.length > 0 && (
        <div className="domain-row">
          <span className="ws-k">URLHAUS PAYLOADS · {c.payloads.length}</span>
          <div className="payload-list">
            {c.payloads.map((p, i) => (
              <div key={i} className="payload-row">
                <code className="payload-sha">{(p.sha256 || "").slice(0, 16)}…</code>
                {p.signature && <span className="family-chip">{p.signature}</span>}
                {p.filename && <span className="dim">{p.filename}</span>}
                {p.filetype && <span className="dim">· {p.filetype}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {c.campaigns?.length > 0 && (
        <div className="domain-row">
          <span className="ws-k">CAMPAIGNS · OTX · {c.campaigns.length}</span>
          <div className="campaigns-list">
            {c.campaigns.slice(0, 6).map((p, i) => (
              <div key={i} className="campaign-row">
                <span className="campaign-name">{p.name}</span>
                {p.adversary && <span className="dim"> · {p.adversary}</span>}
                {p.malware_families?.length > 0 && (
                  <span className="campaign-fams">
                    {p.malware_families.slice(0, 4).map(f => <span key={f} className="family-chip-sm">{f}</span>)}
                  </span>
                )}
              </div>
            ))}
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
        <span className="sec-title glitch" data-text="CERTIFICATE TRANSPARENCY">CERTIFICATE TRANSPARENCY</span>
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

function AlertTicker({ results, setActiveIoc, setTab, fmt }) {
  // Derived directly from the recent strip — every record there is a
  // real cached enrichment. We surface only HIGH+ (≥60) so the ticker
  // reads as an alert stream, not a generic activity log. Delta uses
  // `prev_score` → `final_score` to show movement; first-seen records
  // have prev_score == final_score, so delta = 0 reads as steady.
  const alerts = (results || [])
    .filter(r => r.final_score >= 60)
    .slice(0, 14)
    .map(r => ({
      id: r.id,
      ioc: r.ioc,
      type: r.type,
      score: r.final_score,
      delta: r.final_score - (r.prev_score ?? r.final_score),
    }));
  if (alerts.length === 0) return null;

  const onClick = (a) => {
    setActiveIoc(a.id);
    setTab("enrich");
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
              <span key={`${a.id}-${i}`} className="ticker-item" onClick={() => onClick(a)}>
                <span className="ti-score" style={{color: s.fg, borderColor: s.fg}}>{a.score}</span>
                <span className="ti-ioc">{fmt(a.ioc)}</span>
                <span className="ti-delta" style={{color: a.delta > 0 ? "var(--high)" : a.delta < 0 ? "var(--safe)" : "var(--ink-3)"}}>
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

function PivotPanel({ ioc, results, setResults, setActiveIocId }) {
  // Find related IOCs. First pull whatever is already on the recent
  // strip (instant render, free), then query /api/ui/pivot in the
  // background to widen the corpus across the whole cache. Backend
  // hits get merged in, dedup'd by id, and clicking one adds it to
  // the strip so the score panels can render it.
  const corpus = (results || []).filter(r => r.id !== ioc.id);
  const family = Object.values(ioc.modules).find(m => m.data?.malware)?.data?.malware ||
                 Object.values(ioc.modules).find(m => m.data?.family)?.data?.family;
  const registrar = ioc.modules.WHOIS?.data?.registrar;
  const stripCase       = ioc.case ? corpus.filter(r => r.case === ioc.case) : [];
  const stripFamily     = family ? corpus.filter(r =>
    Object.values(r.modules).some(m => m.data?.malware === family || m.data?.family === family)
  ) : [];
  const stripRegistrar  = registrar ? corpus.filter(r =>
    r.modules.WHOIS?.data?.registrar === registrar
  ) : [];

  const [cacheFamily, setCacheFamily] = React.useState([]);
  const [cacheRegistrar, setCacheRegistrar] = React.useState([]);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (!window.shadowscopePivot) return;
    const tasks = [];
    if (family) {
      tasks.push(window.shadowscopePivot("malware", family, { exclude: ioc.ioc, limit: 12 })
        .then(rows => setCacheFamily(rows || []))
        .catch(() => setCacheFamily([])));
    } else {
      setCacheFamily([]);
    }
    if (registrar) {
      tasks.push(window.shadowscopePivot("registrar", registrar, { exclude: ioc.ioc, limit: 12 })
        .then(rows => setCacheRegistrar(rows || []))
        .catch(() => setCacheRegistrar([])));
    } else {
      setCacheRegistrar([]);
    }
    if (tasks.length) {
      setLoading(true);
      Promise.allSettled(tasks).finally(() => setLoading(false));
    }
  }, [ioc.id, family, registrar]);

  // Dedup helper — backend hits take precedence over strip-only matches
  // because they carry the full module shape from cache.
  const mergeUnique = (a, b) => {
    const seen = new Set();
    const out = [];
    for (const r of [...b, ...a]) {
      if (seen.has(r.id) || r.id === ioc.id) continue;
      seen.add(r.id);
      out.push(r);
    }
    return out;
  };

  const sameCase      = stripCase;  // no cache-wide case lookup yet
  const sameFamily    = mergeUnique(stripFamily, cacheFamily);
  const sameRegistrar = mergeUnique(stripRegistrar, cacheRegistrar);

  // Clicking a backend hit may target an IOC that isn't on the strip
  // yet. Prepend it so the rest of the dashboard (score panels,
  // sources, geo) has a record to render.
  const navigate = (r) => {
    if (setResults && !results.find(x => x.id === r.id)) {
      setResults(prev => [r, ...prev.filter(x => x.id !== r.id)]);
    }
    setActiveIocId(r.id);
  };

  const groups = [
    sameCase.length      && { title: "SAME CASE",      pivot: ioc.case || "—",        items: sameCase },
    sameFamily.length    && { title: "SAME FAMILY",    pivot: family,                  items: sameFamily },
    sameRegistrar.length && { title: "SAME REGISTRAR", pivot: registrar,               items: sameRegistrar }
  ].filter(Boolean);

  if (groups.length === 0) {
    return (
      <aside className="pivot-panel">
        <div className="sec-head">
          <span className="sec-title glitch" data-text="RELATED">RELATED</span>
          <span className="sec-meta dim">{loading ? "scanning cache…" : "no pivots"}</span>
        </div>
        <div className="pivot-empty">// no related infrastructure found<br/>// in current intel corpus</div>
      </aside>
    );
  }

  return (
    <aside className="pivot-panel">
      <div className="sec-head">
        <span className="sec-title glitch" data-text="RELATED">RELATED</span>
        <span className="sec-meta">
          {groups.reduce((n, g) => n + g.items.length, 0)} IOCs across {groups.length} pivots
          {loading && <span className="dim"> · scanning…</span>}
        </span>
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
              <button key={r.id} className="pivot-row" onClick={() => navigate(r)}>
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
// ``ioc.geo`` which the backend synthesises from Shodan + IPinfo modules.
// The panels are hidden upstream (``hasGeo``) when geo is absent, so this
// helper only needs to return either the real block or ``null``.

function _geoFor(ioc) {
  if (ioc.geo && (ioc.geo.lat != null || ioc.geo.country)) return ioc.geo;
  return null;
}

// ─────────── Threat Surface — cross-source consensus matrix ───────────
//
// One row per canonical flag. OR-logic verdict (any source says yes →
// verdict yes), with per-source attribution shown beside.
//
// Each FLAGS entry returns { confirmed: [source...], denied: [source...] }
// where confirmed sources fired the flag; denied ones explicitly returned
// false (so we can show "checked but clean").
//
// "RELATIONS" row dedups operator / hosting-provider / hostname strings
// across the same modules and surfaces the most common form.

const _ORG_KEYS = [
  // (source-id, picker)
  ["Shodan",      (d) => d.org || d.isp],
  ["IPinfo",      (d) => d.org],
  ["AbuseIPDB",   (d) => d.isp],
  ["AbstractAPI", (d) => (d.asn || {}).name || (d.company || {}).name],
  ["ASN",         (d) => d.name],
];

function _collectFlag(ioc, probes) {
  // probes :: [(source, picker, isPositive?)]
  // picker returns true/false; isPositive defaults to identity
  const confirmed = [];
  const denied = [];
  for (const [src, pick, positive] of probes) {
    const data = (ioc.modules[src] || {}).data;
    if (!data) continue;
    let v;
    try { v = pick(data); } catch (e) { continue; }
    if (v === undefined || v === null) continue;
    const yes = positive ? positive(v) : !!v;
    if (yes) confirmed.push(src);
    else denied.push(src);
  }
  return { confirmed, denied };
}

function _collectOperators(ioc) {
  // Returns [{ name, sources: [src...] }] dedup'd case-insensitively.
  const map = new Map();
  for (const [src, pick] of _ORG_KEYS) {
    const data = (ioc.modules[src] || {}).data;
    if (!data) continue;
    let v;
    try { v = pick(data); } catch (e) { continue; }
    if (!v || typeof v !== "string") continue;
    const norm = v.trim();
    if (!norm) continue;
    const key = norm.toLowerCase();
    if (!map.has(key)) map.set(key, { name: norm, sources: [] });
    map.get(key).sources.push(src);
  }
  return Array.from(map.values()).sort((a, b) => b.sources.length - a.sources.length);
}

function _collectHostnames(ioc) {
  // Union across Shodan / IPinfo / AbuseIPDB; dedup'd lowercase.
  const set = new Set();
  for (const src of ["Shodan", "IPinfo", "AbuseIPDB"]) {
    const d = (ioc.modules[src] || {}).data || {};
    if (Array.isArray(d.hostnames)) d.hostnames.forEach(h => h && set.add(String(h).toLowerCase()));
    if (typeof d.hostname === "string") set.add(d.hostname.toLowerCase());
  }
  return Array.from(set);
}

function ThreatSurfacePanel({ ioc }) {
  const flagDefs = [
    { k: "TOR",     color: "var(--crit)", probes: [
      ["TOR",         (d) => d.is_tor],
      ["AbuseIPDB",   (d) => d.isTor],
      ["AbstractAPI", (d) => (d.security || {}).is_tor],
      ["IPinfo",      (d) => (d.privacy || {}).tor],
    ]},
    { k: "VPN",     color: "var(--bad)", probes: [
      ["IPQS",        (d) => d.vpn],
      ["AbstractAPI", (d) => (d.security || {}).is_vpn],
      ["IPinfo",      (d) => (d.privacy || {}).vpn],
    ]},
    { k: "PROXY",   color: "var(--bad)", probes: [
      ["IPQS",        (d) => d.proxy],
      ["AbstractAPI", (d) => (d.security || {}).is_proxy],
      ["IPinfo",      (d) => (d.privacy || {}).proxy],
    ]},
    { k: "RELAY",   color: "var(--high)", probes: [
      ["AbstractAPI", (d) => (d.security || {}).is_relay],
    ]},
    { k: "HOSTING", color: "var(--ink-2)", probes: [
      ["AbstractAPI", (d) => (d.security || {}).is_hosting],
      ["Shodan",      (d) => Array.isArray(d.tags) && d.tags.includes("cloud")],
    ]},
    { k: "MOBILE",  color: "var(--ink-2)", probes: [
      ["AbstractAPI", (d) => (d.security || {}).is_mobile],
    ]},
    { k: "ABUSER",  color: "var(--bad)", probes: [
      ["AbstractAPI", (d) => (d.security || {}).is_abuse],
      ["AbuseIPDB",   (d) => (d.abuseConfidenceScore || 0) >= 25],
    ]},
    { k: "SCANNER", color: "var(--bad)", probes: [
      ["GreyNoise",   (d) => d.classification === "malicious"],
    ]},
    { k: "RIOT",    color: "var(--safe)", probes: [
      ["GreyNoise",   (d) => d.riot === true],
    ]},
    { k: "ANYCAST", color: "var(--ink-2)", probes: [
      ["IPinfo",      (d) => d.anycast || d.is_anycast],
    ]},
  ];

  const rows = flagDefs
    .map(def => ({ ...def, result: _collectFlag(ioc, def.probes) }))
    // Only show flags that were either confirmed by ≥1 source, OR
    // explicitly checked and denied by ≥2 sources (so the analyst sees
    // "we checked Tor with 3 sources and they all said no"). Skip
    // flags with zero coverage entirely.
    // Only show flags that ≥1 source confirmed. Per user feedback,
    // "checked and clean" denied rows add noise without value —
    // analysts only care about what fired.
    .filter(r => r.result.confirmed.length > 0);

  const operators = _collectOperators(ioc);
  const hostnames = _collectHostnames(ioc);

  if (rows.length === 0 && operators.length === 0 && hostnames.length === 0) return null;

  return (
    <div className="threat-surface">
      <div className="ts-head">
        <span className="ts-title">THREAT SURFACE</span>
        <span className="ts-meta">cross-source consensus · OR-merge</span>
      </div>
      {rows.length > 0 && (
        <div className="ts-flag-rows">
          {rows.map(r => (
            <div key={r.k} className="ts-flag-row yes">
              <span className="ts-flag-name" style={{ color: r.color }}>
                ✓ {r.k}
              </span>
              <span className="ts-source-chips">
                {r.result.confirmed.map(s => (
                  <span key={"y"+s} className="ts-source-chip confirmed" style={{ borderColor: r.color, color: r.color }}>{s}</span>
                ))}
              </span>
            </div>
          ))}
        </div>
      )}
      {(operators.length > 0 || hostnames.length > 0) && (
        <div className="ts-relations">
          {operators.length > 0 && (
            <div className="ts-rel-row">
              <span className="ts-rel-k">OPERATOR</span>
              <span className="ts-rel-v">
                {operators.slice(0, 2).map(o => (
                  <span key={o.name} className="ts-rel-chip">
                    <span className="ts-rel-name">{o.name}</span>
                    <span className="ts-rel-src">{o.sources.join(" · ")}</span>
                  </span>
                ))}
              </span>
            </div>
          )}
          {hostnames.length > 0 && (
            <div className="ts-rel-row">
              <span className="ts-rel-k">RDNS</span>
              <span className="ts-rel-v ts-rel-hostnames">
                {hostnames.slice(0, 4).map(h => <Copyable key={h} text={h}><span className="ts-host">{h}</span></Copyable>)}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function IpCorePanel({ ioc, fmt }) {
  const g = _geoFor(ioc);
  if (!g) return null;
  const ports = g.ports || [];
  const anon = ioc.anon || null;
  const core = ioc.core || null;
  const allHosts = Array.from(new Set([
    ...((g.hostnames || []).filter(Boolean)),
    ...((core?.hostnames_extra || []).filter(Boolean)),
  ]));
  // Passive-DNS first-seen / last-seen — info-only single-line row.
  const pdns = ioc.modules?.PDNS?.data || null;
  const pdnsFirst = pdns?.first_seen ? String(pdns.first_seen).slice(0, 10) : null;
  const pdnsLast  = pdns?.last_seen  ? String(pdns.last_seen).slice(0, 10)  : null;
  const pdnsAge   = (pdns && typeof pdns.age_days === "number") ? pdns.age_days : null;
  const pdnsRecs  = pdns?.record_count || 0;

  return (
    <div className="ip-core-panel">
      <div className="ipc-head">
        <span className="ipc-title glitch" data-text="IP CORE">IP CORE</span>
        <span className="ipc-meta">identity · routing</span>
      </div>
      <ThreatSurfacePanel ioc={ioc} />
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
        {allHosts.length > 0 && (
          <div className="ipc-row">
            <span className="ipc-k">RDNS</span>
            <span className="ipc-v">{allHosts.join(", ")}</span>
          </div>
        )}
        {(pdnsFirst || pdnsLast) && (
          <div className="ipc-row">
            <span className="ipc-k">PDNS</span>
            <span className="ipc-v">
              {pdnsFirst ? <>first <b>{pdnsFirst}</b></> : null}
              {pdnsLast ? <span className="dim">{" · "}last {pdnsLast}</span> : null}
              {pdnsAge != null ? <span className="dim">{" · "}{pdnsAge}d</span> : null}
              {pdnsRecs > 0 ? <span className="dim">{" · "}{pdnsRecs} records</span> : null}
              <span className="dim">{" · Mnemonic"}</span>
            </span>
          </div>
        )}
        {core?.rdap_cidr && (
          <div className="ipc-row">
            <span className="ipc-k">NETWORK</span>
            <span className="ipc-v">{core.rdap_cidr}{core.network_rir ? " · " + core.network_rir : ""}</span>
          </div>
        )}
        {core?.usage_type && (
          <div className="ipc-row">
            <span className="ipc-k">USAGE</span>
            <span className="ipc-v">
              {core.usage_type}
              <span className="dim"> · {Object.keys(core.usage_sources || {}).join(", ")}</span>
            </span>
          </div>
        )}
        {core?.abuse_confidence != null && (
          <div className="ipc-row">
            <span className="ipc-k">ABUSE</span>
            <span className="ipc-v" style={{ color: core.abuse_confidence >= 75 ? "var(--bad)" : core.abuse_confidence >= 25 ? "var(--med)" : "var(--ink)" }}>
              {core.abuse_confidence}/100 (AbuseIPDB)
              {core.fraud_score != null ? <span className="dim"> · IPQS fraud {core.fraud_score}</span> : null}
            </span>
          </div>
        )}
        {core?.abuse_contact && (
          <div className="ipc-row">
            <span className="ipc-k">ABUSE CONTACT</span>
            <span className="ipc-v"><Copyable text={core.abuse_contact}>{core.abuse_contact}</Copyable></span>
          </div>
        )}
        {(core?.ssl_cert || core?.jarm) && (
          <div className="ipc-row">
            <span className="ipc-k">TLS</span>
            <span className="ipc-v">
              {core.ssl_cert?.subject_cn ? <>CN={core.ssl_cert.subject_cn}{" "}</> : null}
              {core.ssl_cert?.issuer_cn ? <span className="dim">issuer={core.ssl_cert.issuer_cn}{" "}</span> : null}
              {core.ssl_cert?.expires ? <span className="dim">exp={core.ssl_cert.expires}</span> : null}
              {core.jarm ? <div className="dim">JARM={core.jarm}</div> : null}
            </span>
          </div>
        )}
        {core?.os && (
          <div className="ipc-row">
            <span className="ipc-k">OS</span>
            <span className="ipc-v">{core.os} <span className="dim">(Censys)</span></span>
          </div>
        )}
        {core?.software?.length > 0 && (
          <div className="ipc-row">
            <span className="ipc-k">SOFTWARE</span>
            <span className="ipc-v">
              {core.software.slice(0, 6).map((s, i) => <span key={i} className="cat-chip">{s}</span>)}
              {core.software.length > 6 && <span className="dim"> +{core.software.length - 6}</span>}
              <span className="dim"> · Censys</span>
            </span>
          </div>
        )}
        {core?.censys?.service_count > 0 && (
          <div className="ipc-row">
            <span className="ipc-k">CENSYS</span>
            <span className="ipc-v">
              {core.censys.service_count} services
              {core.censys.bgp_prefix ? <span className="dim"> · BGP {core.censys.bgp_prefix}</span> : null}
              {core.censys.last_updated_at ? <span className="dim"> · scanned {core.censys.last_updated_at.slice(0,10)}</span> : null}
            </span>
          </div>
        )}
      </div>

      {anon && (
        <div className="ipc-anon">
          <div className="ipc-anon-head">
            <span className="ipc-anon-title">ANONYMIZATION</span>
            <span className="ipc-anon-meta">cross-source consensus</span>
          </div>
          <div className="ipc-anon-grid">
            {anon.is_tor && (
              <div className="anon-chip anon-tor" title={`Confirmed by: ${(anon.confidence_sources?.tor || []).join(", ")}`}>
                <span className="anon-k">TOR</span>
                <span className="anon-v">{anon.tor_hostname || "exit relay"}</span>
                <span className="anon-cnt">{(anon.confidence_sources?.tor || []).length} src</span>
              </div>
            )}
            {anon.is_vpn && (
              <div className="anon-chip anon-vpn" title={`Confirmed by: ${(anon.confidence_sources?.vpn || []).join(", ")}`}>
                <span className="anon-k">VPN</span>
                <span className="anon-v">{anon.vpn_brand || "unknown brand"}</span>
                <span className="anon-cnt">{(anon.confidence_sources?.vpn || []).length} src</span>
              </div>
            )}
            {anon.is_proxy && (
              <div className="anon-chip anon-proxy">
                <span className="anon-k">PROXY</span>
                <span className="anon-cnt">{(anon.confidence_sources?.proxy || []).length} src</span>
              </div>
            )}
            {anon.is_residential_proxy && (
              <div className="anon-chip anon-resproxy">
                <span className="anon-k">RESIDENTIAL PROXY</span>
              </div>
            )}
            {anon.is_relay && (
              <div className="anon-chip anon-relay">
                <span className="anon-k">RELAY</span>
              </div>
            )}
            {anon.is_hosting && (
              <div className="anon-chip anon-hosting">
                <span className="anon-k">HOSTING</span>
              </div>
            )}
            {anon.is_mobile && (
              <div className="anon-chip anon-mobile">
                <span className="anon-k">MOBILE</span>
              </div>
            )}
          </div>
        </div>
      )}

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
//
// Multi-IOC: when ``results`` is provided, every enriched IOC with geo data
// gets its own beacon, sized & colored by score tier. The active IOC's
// beacon is bigger and stays centered.
function NetworkGeoPanel({ ioc, results, setActiveIocId }) {
  const g = _geoFor(ioc);
  const ref = React.useRef(null);
  const mapRef = React.useRef(null);

  // Build beacon DOM for one IOC. Centralised so active + secondary beacons
  // share the same structure — they only differ via the ``active`` class.
  const buildBeacon = (rec, active) => {
    const score = rec.final_score || 0;
    const sev = sevOf(score);
    const color = sev.fg;
    const tierLabel = sev.label;
    const anon = rec.anon || {};
    // Anonymization glyph: TOR > VPN > residential proxy > proxy.
    let glyph = "";
    let glyphTitle = "";
    if (anon.is_tor) { glyph = "⊙"; glyphTitle = `Tor exit — ${anon.tor_hostname || "anonymized"}`; }
    else if (anon.is_vpn) { glyph = "⛨"; glyphTitle = `VPN — ${anon.vpn_brand || "anonymized"}`; }
    else if (anon.is_residential_proxy) { glyph = "⇄"; glyphTitle = "Residential proxy"; }
    else if (anon.is_proxy) { glyph = "⇄"; glyphTitle = "Proxy"; }
    const glyphHtml = glyph
      ? `<span class="ss-beacon-glyph" title="${glyphTitle.replace(/"/g, "&quot;")}">${glyph}</span>`
      : "";
    return `
      <div class="ss-beacon ${active ? "active" : ""}" style="--beacon-color: ${color};" data-tier="${tierLabel}">
        <span class="ss-beacon-ring r1"></span>
        <span class="ss-beacon-ring r2"></span>
        <span class="ss-beacon-ring r3"></span>
        <span class="ss-beacon-crosshair-v"></span>
        <span class="ss-beacon-crosshair-h"></span>
        <span class="ss-beacon-dot"></span>
        ${glyphHtml}
        <span class="ss-beacon-score">${score}</span>
      </div>`;
  };

  // Build enriched popup HTML for one IOC.
  const buildPopup = (rec, recGeo) => {
    const score = rec.final_score || 0;
    const sev = sevOf(score);
    const flags = (window.IOC_FLAGS ? window.IOC_FLAGS(rec) : []).slice(0, 4);
    const portObjs = (recGeo.ports || []).filter(p => typeof p === "object");
    const portCount = portObjs.length || (recGeo.ports || []).length;
    const topPorts = portObjs.slice(0, 4)
      .map(p => `<code>${p.port}/${p.service || "·"}</code>`)
      .join(" ");
    const flagsHtml = flags.length
      ? `<div class="ss-pop-flags">${flags.map(f => `<span class="ss-pop-flag" style="color:${f.color};border-color:${f.color}">${f.glyph} ${f.label}</span>`).join("")}</div>`
      : "";
    return `
      <div class="ss-pop">
        <div class="ss-pop-head">
          <span class="ss-pop-ioc">${rec.ioc}</span>
          <span class="ss-pop-score" style="color:${sev.fg};border-color:${sev.fg}">${score}</span>
        </div>
        <div class="ss-pop-row"><span class="ss-pop-k">LOC</span> ${recGeo.city || "—"} ${recGeo.country || ""}</div>
        ${recGeo.asn ? `<div class="ss-pop-row"><span class="ss-pop-k">ASN</span> ${recGeo.asn} ${recGeo.org ? `<span class="dim">· ${recGeo.org}</span>` : ""}</div>` : ""}
        ${portCount ? `<div class="ss-pop-row"><span class="ss-pop-k">PORTS</span> ${portCount}${topPorts ? ` · ${topPorts}` : ""}</div>` : ""}
        ${flagsHtml}
      </div>`;
  };

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

    // Build the set of secondary beacons from the rest of the enriched
    // session. Active IOC always gets a beacon (drawn last → on top).
    const everyOtherIoc = (results || []).filter(r => {
      if (!r || r.id === ioc.id) return false;
      const rg = r.geo;
      return rg && rg.lat != null && rg.lon != null;
    });

    const allLatLngs = [[g.lat, g.lon]];
    everyOtherIoc.forEach(rec => {
      const rg = rec.geo;
      const icon = L.divIcon({
        html: buildBeacon(rec, false),
        className: "ss-beacon-icon ss-beacon-icon-small",
        iconSize: [36, 36],
        iconAnchor: [18, 18],
      });
      const m = L.marker([rg.lat, rg.lon], { icon }).addTo(map)
        .bindPopup(buildPopup(rec, rg));
      m.on("mouseover", () => m.openPopup());
      m.on("click", () => { if (setActiveIocId) setActiveIocId(rec.id); });
      allLatLngs.push([rg.lat, rg.lon]);
    });

    // Active beacon (always last, always animated, bigger).
    const activeIcon = L.divIcon({
      html: buildBeacon(ioc, true),
      className: "ss-beacon-icon",
      iconSize: [60, 60],
      iconAnchor: [30, 30],
    });
    const activeMarker = L.marker([g.lat, g.lon], { icon: activeIcon, zIndexOffset: 1000 }).addTo(map)
      .bindPopup(buildPopup(ioc, g));
    activeMarker.on("mouseover", () => activeMarker.openPopup());

    // Auto-fit to include every plotted beacon, with a generous padding so
    // beacons aren't clipped at the edges.
    if (allLatLngs.length > 1) {
      map.fitBounds(allLatLngs, { padding: [40, 40], maxZoom: 6 });
    }

    mapRef.current = map;
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [ioc.id, g && g.lat, g && g.lon, (results || []).length, ioc.final_score, JSON.stringify(ioc.anon || {})]);

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

window.IpCorePanel = IpCorePanel;
window.NetworkGeoPanel = NetworkGeoPanel;
window.FlagStrip = FlagStrip;
window.Explain = Explain;
window.BootScreen = BootScreen;
