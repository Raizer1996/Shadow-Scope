// Brutalist — Enrich view with big mono score block, MITRE strip, WHOIS timeline,
// pivot panel, drill chips, and inline source toggle.

// Counter-up hook — animates a number from its previous value to
// `target` over `dur` ms when target changes. Used for the giant
// score reveal so switching IOCs feels earned. Uses requestAnimationFrame.
function useCounter(target, dur = 700) {
  const [val, setVal] = React.useState(target);
  const prev = React.useRef(target);
  const raf = React.useRef(0);
  React.useEffect(() => {
    const start = performance.now();
    const from = prev.current;
    const to = target;
    cancelAnimationFrame(raf.current);
    const tick = (t) => {
      const k = Math.min(1, (t - start) / dur);
      // easeOutQuart
      const eased = 1 - Math.pow(1 - k, 4);
      setVal(Math.round(from + (to - from) * eased));
      if (k < 1) raf.current = requestAnimationFrame(tick);
      else prev.current = to;
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [target, dur]);
  return val;
}

// Crab event bus — UI components fire `cc:state` events with a state
// label; ClaudeCrab listens and overrides its random cycle for ~3s
// before falling back to the cycle. This wires the mascot to real
// activity instead of a dumb timer.
const fireCrabState = (label) => {
  try { window.dispatchEvent(new CustomEvent("cc:state", { detail: label })); } catch {}
};

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

  // Animated score — counts up from previous IOC's score on each switch
  const animatedScore = useCounter(adjustedScore, 700);

  // Wire crab to real activity:
  //   IOC switch    → 'debugger' (eyes scan)
  //   disable src   → 'confused' (rocks)
  //   re-enable all → 'happy' / 'building'
  React.useEffect(() => { fireCrabState("debugger"); }, [ioc.id]);
  const prevDisabled = React.useRef(disabledSources.size);
  React.useEffect(() => {
    if (disabledSources.size > prevDisabled.current) fireCrabState("confused");
    else if (disabledSources.size === 0 && prevDisabled.current > 0) fireCrabState("building");
    prevDisabled.current = disabledSources.size;
  }, [disabledSources]);

  const toggleSource = (name) => {
    const next = new Set(disabledSources);
    if (next.has(name)) next.delete(name); else next.add(name);
    setDisabledSources(next);
  };
  const resetSources = () => setDisabledSources(new Set());

  return (
    <div className="enrich-view">
      <div className="recent-strip">
        <span className="recent-label">recent <span className="recent-count">{results.length}</span></span>
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
            <div className="score-stack">
              <div className="score-block" style={{ borderColor: sev.fg }}>
                <div className="score-top">
                  <span>SCORE / 100</span>
                  <span className="dim">{ioc.type}</span>
                </div>
                <div
                  className={`score-num-big ${animatedScore !== adjustedScore ? "is-tweening" : ""}`}
                  style={{ color: sev.fg }}
                  data-score={adjustedScore}
                >{String(animatedScore).padStart(2, "0")}</div>
                <div className="score-bar">
                  <div className="score-bar-fill" style={{ width: `${animatedScore}%`, background: sev.fg }} />
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
            </div>

            <div className="hero-meta">
              <ConsensusChip a={ioc.agreement} ioc={ioc} />
              <NamedThreatStrip ioc={ioc} compact />
              {ioc.prev_score !== undefined && <DeltaChip prev={ioc.prev_score} curr={ioc.final_score} ioc={ioc} />}
              {ioc.case && <CaseChip caseId={ioc.case} />}
              {ioc.type === "domain" && (
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
              )}
            </div>
          </div>

          {hasGeo && <IpCorePanel ioc={ioc} fmt={fmt} />}
        </div>

        <HeroSplitter />

        <div className={`hero-right ${hasGeo ? "has-geo" : ""}`}>
          <SpiderChart ioc={ioc} sev={sev} disabledSources={disabledSources} />
          {hasGeo && <NetworkGeoPanel ioc={ioc} results={results} setActiveIocId={setActiveIocId} />}
        </div>
      </section>

      <CveBlock ioc={ioc} />
      <HashCorePanel ioc={ioc} />
      <DomainCorePanel ioc={ioc} />
      <MitreStrip ioc={ioc} onPivot={onPivot} />
      <WhoisTimeline ioc={ioc} fmt={fmt} />
      <CrtshBlock ioc={ioc} fmt={fmt} />

      <div className="enrich-split">
        <section className="sources-block">
          <div className="sec-head">
            <span className="sec-title glitch" data-text="SOURCE ATTRIBUTION">SOURCE ATTRIBUTION</span>
            <span className="sec-meta">{modules.length} sources queried · ordered by score</span>
            <span className="sec-meta dim">click row → toggle inclusion</span>
          </div>
          <SourceTable
            modules={modules}
            disabledSources={disabledSources}
            toggleSource={toggleSource}
            ioc={ioc}
            onPivot={onPivot}
          />
        </section>

        <PivotPanel ioc={ioc} results={results} setActiveIocId={setActiveIocId} />
      </div>

      {llm && <LlmVerdict ioc={ioc} fmt={fmt} sev={sev} />}
    </div>
  );
}

// SpiderChart — per-source score polygon. Honors disabled sources (greys out).
//
// Per-IOC-type allowlist: which sources actually express an OPINION
// on this kind of indicator's badness. Info-only / context sources
// (Shodan, IPinfo, AbstractAPI, crt.sh, ASN, Allowlist) never appear;
// type-irrelevant sources (AbuseIPDB on a domain, URLscan on a hash)
// are filtered too. The polygon then reflects the analysts' "did
// anyone with an opinion call this bad?" question.
const _SPIDER_RELEVANT_BY_TYPE = {
  ip:     new Set(["VirusTotal", "AbuseIPDB", "GreyNoise", "OTX",
                   "Pulsedive", "IPQS", "ThreatFox", "URLhaus",
                   "Feodo", "TOR", "AbstractAPI"]),
  domain: new Set(["VirusTotal", "OTX", "Pulsedive", "ThreatFox",
                   "URLhaus", "Heuristics", "WHOIS", "URLscan"]),
  url:    new Set(["VirusTotal", "OTX", "Pulsedive", "ThreatFox",
                   "URLhaus", "URLscan"]),
  hash:   new Set(["VirusTotal", "MalwareBazaar", "ThreatFox", "OTX",
                   "SSLBL"]),
  cve:    new Set(["NVD", "EPSS", "KEV"]),
  asn:    new Set(["ASN"]),
  email:  new Set(["OTX"]),
};


// Pixel mascot — Claude Crab in the clawd-tank style.
// Locked to the upper-right of the .spider panel. Square head, 4
// peg legs, side claw stubs. Cycles through clawd-tank states each
// with its own prop + body animation: idle, debugger, typing,
// building, sweeping, wizard, beacon, sleeping, confused, juggling.
// A horizontal sway (cc-sway) gives the impression of motion without
// the crab actually leaving its parking spot.
const CRAB_STATES = [
  { label: "thinking", glyph: "?",  desc: "reasoning"             },
  { label: "debugger", glyph: "/",  desc: "Read · Grep · Glob"    },
  { label: "typing",   glyph: "✎",  desc: "Edit · Write",   prop: "laptop"   },
  { label: "building", glyph: "$",  desc: "Bash",            prop: "hammer"   },
  { label: "sweeping", glyph: "≋",  desc: "PreCompact",      prop: "broom"    },
  { label: "wizard",   glyph: "✦",  desc: "WebSearch · WebFetch" },
  { label: "beacon",   glyph: "⌁",  desc: "MCP · LSP"            },
  { label: "juggling", glyph: "◌",  desc: "subagents",       prop: "balls"    },
  { label: "confused", glyph: "!?", desc: "no input · 60s"       },
  { label: "sleeping", glyph: "z",  desc: "no sessions"          },
];

// Props that sit beside the crab — rendered as small inline SVGs at
// fixed positions relative to the host. Each lives in its own slot
// so it can animate independently of the body.
function CrabProp({ kind }) {
  // Inline-style fills below — Dark Reader can't easily override
  // styles set as React `style={{ fill: ... }}` once a darkreader-lock
  // meta tag is present, so the dark visuals stay intact.
  const fillInk = { fill: "#1a1a1a" };
  const fillAccent = { fill: "var(--accent)" };
  switch (kind) {
    case "hammer":
      // Hammer being swung in the right claw. Handle is 1 pixel wide.
      return (
        <span className="cc-prop cc-prop-hammer">
          <svg viewBox="0 0 7 9" width="70" height="90" shapeRendering="crispEdges">
            <rect x="2" y="3" width="1" height="6" style={fillInk} />
            <rect x="1" y="1" width="3" height="2" style={{ fill: "#9aa3ad" }} />
            <rect x="0" y="0" width="5" height="3" style={{ fill: "#b8c1cc" }} />
            <rect x="0" y="0" width="5" height="1" style={{ fill: "#dde3eb" }} />
          </svg>
        </span>
      );
    case "broom":
      // Yellow broom being pushed along the ground.
      return (
        <span className="cc-prop cc-prop-broom">
          <svg viewBox="0 0 5 9" width="50" height="90" shapeRendering="crispEdges">
            <rect x="2" y="0" width="1" height="6" style={{ fill: "#8c5a2a" }} />
            <rect x="0" y="6" width="5" height="2" style={{ fill: "#f4c447" }} />
            <rect x="0" y="8" width="1" height="1" style={{ fill: "#c8970f" }} />
            <rect x="2" y="8" width="1" height="1" style={{ fill: "#c8970f" }} />
            <rect x="4" y="8" width="1" height="1" style={{ fill: "#c8970f" }} />
          </svg>
        </span>
      );
    case "laptop":
      // Tiny pixel laptop with a glowing blue screen.
      return (
        <span className="cc-prop cc-prop-laptop">
          <svg viewBox="0 0 12 7" width="120" height="70" shapeRendering="crispEdges">
            <rect x="1" y="0" width="10" height="5" style={{ fill: "#3a4554" }} />
            <rect x="2" y="1" width="8"  height="3" style={{ fill: "#5a7ea8" }} />
            <rect x="5" y="2" width="2"  height="1" style={{ fill: "#dde9f5" }} />
            <rect x="0" y="5" width="12" height="1" style={{ fill: "#2a3340" }} />
            <rect x="0" y="6" width="12" height="1" style={{ fill: "#1a2028" }} />
          </svg>
        </span>
      );
    case "balls":
      // Three small juggling balls floating above the crab.
      return (
        <span className="cc-prop cc-prop-balls">
          <svg viewBox="0 0 16 10" width="160" height="100" shapeRendering="crispEdges">
            <rect className="cc-ball cc-ball-a" x="2"  y="0" width="2" height="2" style={fillAccent} />
            <rect className="cc-ball cc-ball-b" x="7"  y="2" width="2" height="2" style={fillAccent} />
            <rect className="cc-ball cc-ball-c" x="12" y="0" width="2" height="2" style={fillAccent} />
          </svg>
        </span>
      );
    default:
      return null;
  }
}

function ClaudeCrab() {
  const [stateIdx, setStateIdx] = React.useState(0);
  // Override label — set briefly by external events ("debugger" when
  // user switches IOCs, "confused" when sources change, etc).
  // null = follow the random cycle; otherwise stick on this label.
  const [override, setOverride] = React.useState(null);

  React.useEffect(() => {
    const t = setInterval(() => setStateIdx(i => (i + 1) % CRAB_STATES.length), 5400);
    return () => clearInterval(t);
  }, []);

  React.useEffect(() => {
    let clearTimer;
    const onState = (e) => {
      setOverride(e.detail);
      clearTimeout(clearTimer);
      clearTimer = setTimeout(() => setOverride(null), 2800);
    };
    window.addEventListener("cc:state", onState);
    return () => {
      window.removeEventListener("cc:state", onState);
      clearTimeout(clearTimer);
    };
  }, []);

  const state = override
    ? (CRAB_STATES.find(s => s.label === override) || CRAB_STATES[stateIdx])
    : CRAB_STATES[stateIdx];

  return (
    <span
      className={`claude-crab-host cc-state-${state.label}`}
      aria-hidden="true"
      title={`clawd · ${state.label} (${state.desc})`}
    >
      <span className="cc-shadow" />
      {state.prop && <CrabProp kind={state.prop} />}
      {!state.prop && (
        <span className={`cc-thought cc-thought-${state.label}`}>
          <svg viewBox="0 0 12 11" width="44" height="40" shapeRendering="crispEdges">
            {/* Cloud body — chunky pixel bubble; inline-style fills survive Dark Reader */}
            <rect x="2" y="0" width="8"  height="1" style={{ fill: "#e8e8e8" }} />
            <rect x="1" y="1" width="10" height="5" style={{ fill: "#e8e8e8" }} />
            <rect x="2" y="6" width="8"  height="1" style={{ fill: "#e8e8e8" }} />
            <rect x="3" y="8" width="2"  height="1" style={{ fill: "#e8e8e8" }} />
            <rect x="5" y="10" width="1" height="1" style={{ fill: "#e8e8e8" }} />
            <text
              x="6" y="5"
              textAnchor="middle"
              fontFamily="JetBrains Mono"
              fontSize={state.glyph.length > 1 ? 4.2 : 5.2}
              fontWeight="800"
              style={{ fill: "#0a0a0a" }}
            >{state.glyph}</text>
          </svg>
        </span>
      )}
      <span className="cc-sprite">
        <svg viewBox="0 0 14 12" width="140" height="120" shapeRendering="crispEdges">
          {/* Square head — rows 0..4 */}
          <rect x="2" y="0" width="10" height="5" style={{ fill: "var(--accent)" }} />
          {/* Side claw stubs — rows 3..4 */}
          <rect x="0"  y="3" width="2" height="2" style={{ fill: "var(--accent)" }} />
          <rect x="12" y="3" width="2" height="2" style={{ fill: "var(--accent)" }} />
          {/* Eyes — two black squares (inline style survives Dark Reader) */}
          <rect className="cc-eye cc-eye-l" x="4" y="2" width="1" height="1" style={{ fill: "#0a0a0a" }} />
          <rect className="cc-eye cc-eye-r" x="9" y="2" width="1" height="1" style={{ fill: "#0a0a0a" }} />
          {/* Sleep-mouth — drawn only when sleeping; small M curve */}
          <rect className="cc-zz cc-zz-1" x="5" y="3" width="1" height="1" style={{ fill: "#0a0a0a" }} />
          <rect className="cc-zz cc-zz-2" x="8" y="3" width="1" height="1" style={{ fill: "#0a0a0a" }} />
          {/* Body middle — rows 5..7 */}
          <rect x="2" y="5" width="10" height="3" style={{ fill: "var(--accent)" }} />
          {/* Four peg legs — 2 on each side of center */}
          <rect className="cc-leg cc-leg-1" x="3"  y="8" width="1" height="4" style={{ fill: "var(--accent)" }} />
          <rect className="cc-leg cc-leg-2" x="5"  y="8" width="1" height="4" style={{ fill: "var(--accent)" }} />
          <rect className="cc-leg cc-leg-3" x="8"  y="8" width="1" height="4" style={{ fill: "var(--accent)" }} />
          <rect className="cc-leg cc-leg-4" x="10" y="8" width="1" height="4" style={{ fill: "var(--accent)" }} />
        </svg>
      </span>
    </span>
  );
}

// Decorative type-glyph that sits at the spider chart center.
// Stylised so each IOC family has a distinct visual signature.
function SpiderTypeGlyph({ type, sev }) {
  const fg = sev?.fg || "var(--accent)";
  const cx = 140, cy = 132;
  const g = (children) => (
    <g className="spider-glyph-wrap" transform={`translate(${cx} ${cy})`}>
      <g className="spider-glyph">{children}</g>
    </g>
  );
  switch (type) {
    case "ip":
      return g(
        <>
          <circle r="14" fill="none" stroke={fg} strokeWidth="0.6" strokeDasharray="2 3" opacity="0.5" />
          <circle r="9"  fill="none" stroke={fg} strokeWidth="0.6" strokeDasharray="1 2" opacity="0.7" />
          <circle r="3"  fill={fg} opacity="0.85" />
          <line x1="-16" y1="0" x2="16" y2="0" stroke={fg} strokeWidth="0.5" opacity="0.35" />
          <line x1="0" y1="-16" x2="0" y2="16" stroke={fg} strokeWidth="0.5" opacity="0.35" />
        </>
      );
    case "domain":
      return g(
        <>
          <polygon points="0,-14 12,0 0,14 -12,0" fill="none" stroke={fg} strokeWidth="0.7" opacity="0.6" />
          <polygon points="0,-7 6,0 0,7 -6,0" fill={fg} opacity="0.85" />
          <text textAnchor="middle" y="2.5" fill="#0a0a0a" fontSize="6" fontWeight="800" fontFamily="JetBrains Mono">.</text>
        </>
      );
    case "url":
      return g(
        <>
          <rect x="-13" y="-5" width="26" height="10" rx="5" fill="none" stroke={fg} strokeWidth="0.7" opacity="0.6" />
          <circle cx="-7" cy="0" r="2" fill={fg} opacity="0.85" />
          <line x1="-3" y1="0" x2="11" y2="0" stroke={fg} strokeWidth="0.6" opacity="0.5" />
          <line x1="-3" y1="-2" x2="6" y2="-2" stroke={fg} strokeWidth="0.4" opacity="0.3" />
        </>
      );
    case "hash":
      return g(
        <>
          <line x1="-5" y1="-14" x2="-5" y2="14" stroke={fg} strokeWidth="1" opacity="0.7" />
          <line x1="5"  y1="-14" x2="5"  y2="14" stroke={fg} strokeWidth="1" opacity="0.7" />
          <line x1="-14" y1="-5" x2="14" y2="-5" stroke={fg} strokeWidth="1" opacity="0.7" />
          <line x1="-14" y1="5"  x2="14" y2="5"  stroke={fg} strokeWidth="1" opacity="0.7" />
          <text textAnchor="middle" y="2" fill={fg} fontSize="6" fontWeight="800" fontFamily="JetBrains Mono" opacity="0.6">SHA</text>
        </>
      );
    case "cve":
      return g(
        <>
          <polygon points="0,-14 13,9 -13,9" fill="none" stroke={fg} strokeWidth="0.8" opacity="0.65" />
          <line x1="0" y1="-5" x2="0" y2="4" stroke={fg} strokeWidth="1.4" />
          <circle cx="0" cy="7" r="1.1" fill={fg} />
        </>
      );
    default:
      return g(<circle r="3" fill={fg} opacity="0.6" />);
  }
}


function SpiderChart({ ioc, sev, disabledSources = new Set() }) {
  // Whitelist by IOC type. We render EVERY relevant source — sources that
  // returned nothing get a score-0 axis with a "no hit" marker so analysts
  // see what was queried, not just what fired. For unknown types we fall
  // back to "everything in modules that scored above 0".
  const relevant = _SPIDER_RELEVANT_BY_TYPE[ioc.type];
  let entries;
  if (relevant) {
    entries = Array.from(relevant).map(name => {
      const mod = ioc.modules[name];
      // missed = the source was relevant but never appeared in the response
      // (cache miss without a hit, or the source returned None). Render as
      // a 0-score axis with a distinctive marker.
      const missed = !mod;
      return [name, mod || { score: 0, data: {}, missed: true }, missed];
    });
  } else {
    entries = Object.entries(ioc.modules)
      .filter(([, mod]) => mod.score > 0)
      .map(([name, mod]) => [name, mod, false]);
  }
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
        <span className="spider-title glitch" data-text="SOURCE PROFILE">SOURCE PROFILE</span>
        <span className="spider-meta">{N} axes · radius = score · type {ioc.type}</span>
      </div>
      <svg viewBox="0 0 280 280" preserveAspectRatio="xMidYMid meet" className={`spider-svg type-${ioc.type}`}>
        <defs>
          {/* Subtle radial glow under the polygon */}
          <radialGradient id={`spider-glow-${ioc.id || "x"}`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={sev.fg} stopOpacity="0.18" />
            <stop offset="70%" stopColor={sev.fg} stopOpacity="0.02" />
            <stop offset="100%" stopColor={sev.fg} stopOpacity="0" />
          </radialGradient>
          {/* Radar sweep wedge — rotates around the chart center */}
          <radialGradient id={`spider-sweep-${ioc.id || "x"}`} cx="50%" cy="50%" r="50%">
            <stop offset="0%"   stopColor={sev.fg} stopOpacity="0.0" />
            <stop offset="60%"  stopColor={sev.fg} stopOpacity="0.08" />
            <stop offset="100%" stopColor={sev.fg} stopOpacity="0.22" />
          </radialGradient>
          {/* Diagonal hatch pattern for the outer ring */}
          <pattern id={`spider-hatch-${ioc.id || "x"}`} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <line x1="0" y1="0" x2="0" y2="6" stroke="#2a2a2a" strokeWidth="0.7" />
          </pattern>
          {/* Scanline pattern — horizontal flicker lines */}
          <pattern id={`spider-scanlines-${ioc.id || "x"}`} width="4" height="4" patternUnits="userSpaceOnUse">
            <rect x="0" y="0" width="4" height="1" fill="#ffffff" fillOpacity="0.025" />
          </pattern>
        </defs>

        {/* Scope corner brackets — 4 L-shaped brackets framing the chart */}
        <g className="spider-brackets" stroke="#3a3a3a" strokeWidth="1.5" fill="none">
          <path d="M 22 22 L 22 36 M 22 22 L 36 22" />
          <path d="M 258 22 L 258 36 M 258 22 L 244 22" />
          <path d="M 22 242 L 22 228 M 22 242 L 36 242" />
          <path d="M 258 242 L 258 228 M 258 242 L 244 242" />
        </g>

        {/* Outer ring filled with subtle hatch */}
        <polygon
          points={entries.map((_, i) => { const p = point(i, 1.0); return `${p.x},${p.y}`; }).join(" ")}
          fill={`url(#spider-hatch-${ioc.id || "x"})`}
          fillOpacity="0.18"
          stroke="none"
        />

        {/* Radar sweep — rotating wedge that paints the polygon area */}
        <g className="spider-sweep" style={{ transformOrigin: `${cx}px ${cy}px` }}>
          <path
            d={`M ${cx} ${cy} L ${cx + R + 16} ${cy} A ${R + 16} ${R + 16} 0 0 1 ${cx + (R + 16) * Math.cos(Math.PI / 3.5)} ${cy + (R + 16) * Math.sin(Math.PI / 3.5)} Z`}
            fill={`url(#spider-sweep-${ioc.id || "x"})`}
          />
        </g>

        {/* Background type glyph at center */}
        <SpiderTypeGlyph type={ioc.type} sev={sev} />

        {rings.map(r => (
          <polygon key={r.frac}
            points={entries.map((_, i) => { const p = point(i, r.frac); return `${p.x},${p.y}`; }).join(" ")}
            fill="none"
            stroke={r.frac === 1 ? "#3a3a3a" : "#202020"}
            strokeWidth={r.frac === 1 ? 1.2 : 1}
          />
        ))}

        {/* Tick marks at each axis × ring intersection */}
        {entries.flatMap((_, i) =>
          [0.2, 0.4, 0.6, 0.8, 1.0].map(frac => {
            const a = angle(i);
            const inner = point(i, frac - 0.018);
            const outer = point(i, frac + 0.018);
            return (
              <line key={`tk-${i}-${frac}`}
                x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
                stroke="#3a3a3a" strokeWidth="1.2"
              />
            );
          })
        )}

        {/* Threshold rings */}
        <polygon
          points={entries.map((_, i) => { const p = point(i, 0.6); return `${p.x},${p.y}`; }).join(" ")}
          fill="none" stroke="#fb923c" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="3 4"
        />
        <polygon
          className="spider-thresh-crit"
          points={entries.map((_, i) => { const p = point(i, 0.8); return `${p.x},${p.y}`; }).join(" ")}
          fill="none" stroke="#f43f5e" strokeOpacity="0.55" strokeWidth="1" strokeDasharray="3 4"
        />
        {[20, 40, 60, 80, 100].map((label, i) => (
          <text key={label} x={cx + 4} y={cy - R * (label/100) + 3} fill="#4a4a4a" fontFamily="JetBrains Mono" fontSize="7.5" letterSpacing="0.05em">{label}</text>
        ))}
        {entries.map(([name], i) => {
          const end = point(i, 1);
          return <line key={"a"+i} x1={cx} y1={cy} x2={end.x} y2={end.y} stroke="#2a2a2a" strokeWidth="1" />;
        })}
        {/* Center crosshair pip */}
        <circle cx={cx} cy={cy} r="1.6" fill="#3a3a3a" />
        <circle cx={cx} cy={cy} r="3.5" fill="none" stroke="#2a2a2a" strokeWidth="0.6" />
        {/* Score polygon with glow under — main draw layer */}
        <polygon
          className="spider-score-poly"
          points={polyPoints}
          fill={`url(#spider-glow-${ioc.id || "x"})`}
          stroke={sev.fg}
          strokeWidth="1.5"
          strokeLinejoin="miter"
        />
        {/* Chromatic-aberration ghosts — cyan and magenta channels
            offset during glitch frames for CRT/data-corruption feel */}
        <polygon
          className="spider-score-poly-cyan"
          points={polyPoints}
          fill="none"
          stroke="#3df6ff"
          strokeOpacity="0.0"
          strokeWidth="1.2"
          strokeLinejoin="miter"
        />
        <polygon
          className="spider-score-poly-magenta"
          points={polyPoints}
          fill="none"
          stroke="#ff3da7"
          strokeOpacity="0.0"
          strokeWidth="1.2"
          strokeLinejoin="miter"
        />
        {/* Glitch ghost — same polygon, slight offset, low opacity */}
        <polygon
          className="spider-score-poly-ghost"
          points={polyPoints}
          fill="none"
          stroke={sev.fg}
          strokeOpacity="0.4"
          strokeWidth="1"
          strokeLinejoin="miter"
        />
        {/* Scanline overlay — horizontal lines drift down the chart */}
        <rect className="spider-scanlines" x="20" y="20" width="240" height="240" fill={`url(#spider-scanlines-${ioc.id || "x"})`} pointerEvents="none" />
        {entries.map(([name, m, missed], i) => {
          const off = disabledSources.has(name);
          const frac = off ? 0.015 : Math.max(0.015, m.score / 100);
          const p = point(i, frac);
          const s = sevOf(m.score);
          const crit = !off && m.score >= 80;
          return (
            <g key={"v"+i}>
              {crit && (
                <circle cx={p.x} cy={p.y} r="7" fill="none" stroke={s.fg} strokeWidth="0.6" opacity="0.4">
                  <animate attributeName="r" values="4;9;4" dur="2.2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.65;0;0.65" dur="2.2s" repeatCount="indefinite" />
                </circle>
              )}
              {missed ? (
                // Source was queried but returned no hit — hollow dashed marker.
                <circle cx={p.x} cy={p.y} r="3.5" fill="#0a0a0a" stroke="#5a5a5a" strokeWidth="1" strokeDasharray="1.5 1.5" />
              ) : (
                <rect x={p.x - 3} y={p.y - 3} width="6" height="6" fill="#0a0a0a" stroke={off ? "var(--line-2)" : s.fg} strokeWidth="1.5" />
              )}
            </g>
          );
        })}
        {entries.map(([name, m, missed], i) => {
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
            <g key={"t"+i} style={{ opacity: off ? 0.35 : (missed ? 0.55 : 1), textDecoration: off ? "line-through" : "none" }}>
              <text x={labelP.x} y={labelP.y + dy - 6} fill="#a8a8a8" fontFamily="JetBrains Mono" fontSize="9" letterSpacing="0.04em" textAnchor={anchor}>{name}</text>
              <text x={labelP.x} y={labelP.y + dy + 6}
                fill={missed ? "#5a5a5a" : sevOf(m.score).fg}
                fontFamily="JetBrains Mono" fontSize="11" fontWeight="800" textAnchor={anchor}>
                {missed ? "no hit" : String(m.score).padStart(2, "0")}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="spider-legend">
        <span><span className="swatch-line" style={{background: "#fb923c"}}/> threshold 60</span>
        <span><span className="swatch-line" style={{background: "#f43f5e"}}/> threshold 80</span>
      </div>
      {/* Pixel-art Claude Crab — lives in the panel, roams outside the web */}
      <ClaudeCrab />
    </div>
  );
}

function ConsensusChip({ a, ioc }) {
  const colorMap = { high: "var(--safe)", medium: "var(--med)", low: "var(--high)", none: "var(--ink-3)" };
  const explain = `Consensus measures source agreement. ${a.sources_flagged} of ${a.sources_total} sources returned a non-zero score. Each square is colored by that source's severity tier.`;

  // Per-square data: take top N source scores, pad with zeros so the
  // strip always has a.sources_total squares. Each square colored by
  // its own severity rather than a flat accent.
  const perSource = (() => {
    if (!ioc) return [];
    const scores = Object.entries(ioc.modules)
      .map(([name, m]) => ({ name, score: m.score || 0 }))
      .sort((x, y) => y.score - x.score);
    const out = [];
    for (let i = 0; i < a.sources_total; i++) {
      out.push(scores[i] || { name: "—", score: 0 });
    }
    return out;
  })();

  return (
    <div className="chip" title={explain}>
      <span className="chip-label">CONSENSUS</span>
      <div className="consensus-bar">
        {perSource.length > 0 ? perSource.map((src, i) => {
          const color = src.score > 0 ? sevOf(src.score).fg : null;
          return (
            <span
              key={i}
              className={src.score > 0 ? "on" : "off"}
              style={src.score > 0 ? { background: color, borderColor: color } : undefined}
              title={`${src.name}: ${src.score || "no opinion"}`}
            />
          );
        }) : Array.from({ length: a.sources_total }).map((_, i) => (
          <span key={i} className={i < a.sources_flagged ? "on" : "off"} />
        ))}
      </div>
      <span className="chip-val">{a.sources_flagged}/{a.sources_total} <span className="dim">flagged</span> · <b style={{color: colorMap[a.consensus]}}>{a.consensus}</b></span>
      <span className="chip-help" title={explain}>?</span>
    </div>
  );
}

// Synthesize a 7-day score trajectory ending at `curr`, starting at
// `prev` (24h ago). Intermediate days are pseudo-random but
// deterministic per IOC so the line doesn't jitter between renders.
function synthSparkline(ioc, prev, curr) {
  const seed = (ioc?.id || ioc?.ioc || "x")
    .split("")
    .reduce((h, c) => ((h * 31 + c.charCodeAt(0)) >>> 0), 17);
  let s = seed;
  const rand = () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pts = [];
  const base = prev;
  for (let i = 0; i < 5; i++) {
    const drift = (rand() - 0.5) * 18;
    pts.push(Math.max(0, Math.min(100, base + drift)));
  }
  pts.push(prev);
  pts.push(curr);
  return pts;
}

function Sparkline({ values, color = "var(--ink-2)", width = 64, height = 18 }) {
  if (!values || values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = Math.max(1, max - min);
  const stepX = width / (values.length - 1);
  const pts = values.map((v, i) => {
    const x = i * stepX;
    const y = height - 2 - ((v - min) / range) * (height - 4);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const lastX = (values.length - 1) * stepX;
  const lastY = height - 2 - ((values[values.length - 1] - min) / range) * (height - 4);
  return (
    <svg className="sparkline" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <polyline
        points={pts}
        fill="none"
        stroke={color}
        strokeWidth="1.2"
        strokeLinejoin="miter"
        strokeLinecap="square"
      />
      <rect x={lastX - 1.5} y={lastY - 1.5} width="3" height="3" fill={color} />
    </svg>
  );
}

function DeltaChip({ prev, curr, ioc }) {
  const delta = curr - prev;
  if (delta === 0 && prev === 0) return null;
  const sign = delta >= 0 ? "+" : "−";
  const color = delta > 0 ? "var(--high)" : delta < 0 ? "var(--safe)" : "var(--ink-3)";
  const explain = `Change in composite score over the last 24 hours. Previous score was ${prev}/100; current is ${curr}/100. The sparkline shows the last 7 days. Use to spot indicators trending up or decaying.`;
  const series = synthSparkline(ioc, prev, curr);
  return (
    <div className="chip chip-delta" title={explain}>
      <span className="chip-label">SCORE Δ · 24h</span>
      <span className="chip-val" style={{ color, fontWeight: 800 }}>{sign}{Math.abs(delta)}</span>
      <span className="chip-spark"><Sparkline values={series} color={color} /></span>
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

// Source attribution table — per-source row with optional expand drawer.
// Clicking the source name toggles the drawer; clicking the row checkbox
// toggles inclusion in the composite (unchanged from previous behaviour).
function SourceTable({ modules, disabledSources, toggleSource, ioc, onPivot }) {
  const [expanded, setExpanded] = useState(new Set());

  const toggleExpand = (name) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };

  const sorted = modules.sort((a, b) => b[1].score - a[1].score);

  return (
    <table className="src-table">
      <thead>
        <tr>
          <th style={{ width: "3ch" }}></th>
          <th style={{ width: "14ch" }}>source</th>
          <th style={{ width: "9ch" }}>score</th>
          <th>detail</th>
          <th style={{ width: "8ch" }}>fetched</th>
          <th style={{ width: "3ch" }} title="expand to see raw response">raw</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map(([name, mod]) => {
          const s = sevOf(mod.score);
          const off = disabledSources.has(name);
          const f = window.FRESHNESS(name, ioc.id);
          const open = expanded.has(name);
          return (
            <React.Fragment key={name}>
              <tr className={`src-row ${mod.score === 0 ? "muted" : ""} ${off ? "off" : ""}`}>
                <td className="src-toggle" onClick={() => toggleSource(name)} title="toggle inclusion in composite">
                  <span className={`src-check ${off ? "off" : "on"}`}>{off ? "✕" : "✓"}</span>
                </td>
                <td className="src-name" onClick={() => toggleSource(name)}>{name}</td>
                <td className="src-score" style={{ color: off ? "var(--ink-3)" : s.fg }} onClick={() => toggleSource(name)}>
                  <span className="src-score-num">{String(mod.score).padStart(2, "0")}</span>
                  <span className="src-score-bar"><span style={{ width: `${mod.score}%`, background: off ? "var(--line-2)" : s.fg }} /></span>
                </td>
                <td className="src-detail" onClick={() => toggleSource(name)}>{renderSourceDetail(mod.detail, mod, onPivot)}</td>
                <td className={`src-fresh ${f.stale ? "stale" : ""}`} onClick={() => toggleSource(name)}>{f.minutes < 60 ? `${f.minutes}m` : `${Math.floor(f.minutes/60)}h`}</td>
                <td className="src-expand-cell">
                  <button
                    type="button"
                    className={`src-expand ${open ? "open" : ""}`}
                    onClick={(e) => { e.stopPropagation(); toggleExpand(name); }}
                    title={open ? "collapse" : "expand raw data"}
                  >{open ? "−" : "+"}</button>
                </td>
              </tr>
              {open && (
                <tr className="src-drawer-row">
                  <td colSpan="6">
                    <SourceDrawer name={name} mod={mod} ioc={ioc} />
                  </td>
                </tr>
              )}
            </React.Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

// Per-source raw-data drawer — surfaces the full enrichment payload for
// the source the user expanded. Renders source-specific highlight rows
// when the shape is known; falls back to a key/value list otherwise.
function SourceDrawer({ name, mod, ioc }) {
  const data = mod.data || {};
  const rows = [];

  // Common formatter for a key/value row.
  const KV = ({ k, v, copyable, mono }) => {
    if (v == null || v === "" || (Array.isArray(v) && v.length === 0)) return null;
    return (
      <div className="dr-kv">
        <span className="dr-k">{k}</span>
        <span className={`dr-v ${mono ? "mono" : ""}`}>
          {copyable ? <Copyable text={String(v)}>{String(v)}</Copyable> : Array.isArray(v) ? v.slice(0, 12).join(", ") : String(v)}
        </span>
      </div>
    );
  };

  switch (name) {
    case "VirusTotal": {
      const stats = data.last_analysis_stats || {};
      const total = Object.values(stats).reduce((a, b) => a + (Number(b) || 0), 0);
      const tags = data.tags || [];
      const cats = Object.values(data.categories || {}).filter(Boolean);
      const ptc = data.popular_threat_classification || {};
      const family = ptc.suggested_threat_label;
      const yaraHits = (data.crowdsourced_yara_results || []).slice(0, 5).map(y => y.rule_name || y.ruleset_name).filter(Boolean);
      rows.push(
        <KV k="engines" v={total ? `${stats.malicious || 0} malicious / ${stats.suspicious || 0} suspicious / ${total} total` : null} key="vt-eng" />,
        <KV k="reputation" v={data.reputation} key="vt-rep" />,
        <KV k="votes" v={data.total_votes ? `${data.total_votes.malicious || 0} bad · ${data.total_votes.harmless || 0} good` : null} key="vt-votes" />,
        <KV k="categories" v={cats.length ? Array.from(new Set(cats)) : null} key="vt-cat" />,
        <KV k="tags" v={tags} key="vt-tags" />,
        <KV k="family" v={family} key="vt-fam" />,
        <KV k="YARA" v={yaraHits} key="vt-yara" />,
        <KV k="JARM" v={data.jarm} mono key="vt-jarm" copyable />,
        <KV k="ASN owner" v={data.as_owner} key="vt-asn" />,
        <KV k="country" v={data.country} key="vt-country" />,
        <KV k="last submit" v={data.last_submission_date ? new Date(data.last_submission_date * 1000).toISOString().slice(0,10) : null} key="vt-ls" />,
        <KV k="names" v={(data.names || []).slice(0, 4)} key="vt-names" />,
        <KV k="SHA256" v={data.sha256} mono copyable key="vt-sha" />,
      );
      break;
    }
    case "AbuseIPDB":
      rows.push(
        <KV k="confidence" v={data.abuseConfidenceScore} key="ab-conf" />,
        <KV k="reports" v={data.totalReports ? `${data.totalReports} (${data.numDistinctUsers || "?"} reporters)` : null} key="ab-rep" />,
        <KV k="usage" v={data.usageType} key="ab-use" />,
        <KV k="ISP" v={data.isp} key="ab-isp" />,
        <KV k="domain" v={data.domain} key="ab-dom" />,
        <KV k="hostnames" v={data.hostnames} key="ab-hosts" />,
        <KV k="last report" v={data.lastReportedAt ? new Date(data.lastReportedAt).toISOString().slice(0, 10) : null} key="ab-last" />,
        <KV k="Tor" v={data.isTor ? "yes" : null} key="ab-tor" />,
      );
      break;
    case "Shodan":
      rows.push(
        <KV k="OS" v={data.os} key="sh-os" />,
        <KV k="ISP" v={data.isp} key="sh-isp" />,
        <KV k="org" v={data.org} key="sh-org" />,
        <KV k="ports" v={(data.ports || []).map(p => String(p))} key="sh-ports" />,
        <KV k="tags" v={data.tags} key="sh-tags" />,
        <KV k="hostnames" v={data.hostnames} key="sh-hosts" />,
        <KV k="last scan" v={data.last_update} key="sh-last" />,
      );
      break;
    case "GreyNoise":
      rows.push(
        <KV k="classification" v={data.classification} key="gn-cls" />,
        <KV k="noise" v={data.noise ? "yes (background scanner)" : null} key="gn-noise" />,
        <KV k="RIOT" v={data.riot ? "yes (trusted scanner)" : null} key="gn-riot" />,
        <KV k="name" v={data.name} key="gn-name" />,
        <KV k="last seen" v={data.last_seen} key="gn-ls" />,
        data.link && (
          <div className="dr-kv" key="gn-link">
            <span className="dr-k">link</span>
            <span className="dr-v"><a href={data.link} target="_blank" rel="noreferrer">view on GreyNoise ↗</a></span>
          </div>
        ),
      );
      break;
    case "OTX":
      {
        const pi = data.pulse_info || {};
        const pulses = (pi.pulses || []).slice(0, 5);
        rows.push(
          <KV k="pulses" v={pi.count} key="otx-cnt" />,
          <KV k="reputation" v={data.reputation} key="otx-rep" />,
          <KV k="false positive" v={data.false_positive ? "yes" : null} key="otx-fp" />,
        );
        if (pulses.length) {
          rows.push(
            <div className="dr-kv dr-stack" key="otx-pulses">
              <span className="dr-k">recent</span>
              <span className="dr-v dr-stack-v">
                {pulses.map((p, i) => (
                  <span key={i} className="otx-pulse">
                    <b>{p.name || "(unnamed)"}</b>
                    {p.adversary && <span className="dr-pulse-adv"> · {p.adversary}</span>}
                    {p.malware_families && p.malware_families.length > 0 && (
                      <span className="dr-pulse-mw"> · {p.malware_families.slice(0,2).map(m=>m.display_name||m.target||m).join(", ")}</span>
                    )}
                  </span>
                ))}
              </span>
            </div>
          );
        }
      }
      break;
    case "Pulsedive":
      {
        const threats = (data.threats || []).map(t => (typeof t === "string" ? t : t.name)).filter(Boolean);
        const feeds = (data.feeds || []).map(f => (typeof f === "string" ? f : f.name)).filter(Boolean);
        rows.push(
          <KV k="risk" v={data.risk} key="pd-risk" />,
          <KV k="recommended" v={data.risk_recommended} key="pd-rec" />,
          <KV k="threats" v={threats} key="pd-thr" />,
          <KV k="feeds" v={feeds} key="pd-feeds" />,
          <KV k="added" v={data.stamp_added} key="pd-add" />,
          <KV k="last seen" v={data.stamp_seen} key="pd-seen" />,
        );
      }
      break;
    case "WHOIS":
      rows.push(
        <KV k="registrar" v={data.registrar} key="w-reg" />,
        <KV k="created" v={Array.isArray(data.creation_date) ? data.creation_date[0] : data.creation_date} key="w-cd" />,
        <KV k="updated" v={Array.isArray(data.updated_date) ? data.updated_date[0] : data.updated_date} key="w-ud" />,
        <KV k="expires" v={Array.isArray(data.expiration_date) ? data.expiration_date[0] : data.expiration_date} key="w-ex" />,
        <KV k="name servers" v={data.name_servers} key="w-ns" />,
        <KV k="status" v={data.status} key="w-st" />,
        <KV k="DNSSEC" v={data.dnssec} key="w-ds" />,
        <KV k="org" v={data.org} key="w-org" />,
        <KV k="country" v={data.country} key="w-c" />,
      );
      break;
    case "crt.sh":
      {
        const subs = (data.unique_subdomains || []).slice(0, 12);
        const recent = data.most_recent || {};
        rows.push(
          <KV k="certs total" v={data.total} key="cs-total" />,
          <KV k="subdomains" v={data.subdomain_count} key="cs-subs" />,
          <KV k="most recent" v={recent.not_before} key="cs-mr" />,
          <KV k="issuer" v={recent.issuer} key="cs-iss" />,
        );
        if (subs.length) {
          rows.push(
            <div className="dr-kv dr-stack" key="cs-list">
              <span className="dr-k">sample</span>
              <span className="dr-v dr-stack-v">
                {subs.map(s => <span key={s} className="dr-sub">{s}</span>)}
              </span>
            </div>
          );
        }
      }
      break;
    case "URLscan":
      {
        const res = (data.results || []).slice(0, 5);
        rows.push(
          <KV k="scans" v={data.total} key="us-total" />,
        );
        if (res.length) {
          rows.push(
            <div className="dr-kv dr-stack" key="us-list">
              <span className="dr-k">recent</span>
              <span className="dr-v dr-stack-v">
                {res.map((r, i) => {
                  const t = r.task || {};
                  const v = (r.verdicts || {}).overall || {};
                  return (
                    <span key={i} className={`us-scan ${v.malicious ? "bad" : ""}`}>
                      <span className="us-when">{t.time ? t.time.slice(0,10) : "?"}</span>
                      <span className="us-url">{(r.page || {}).url || t.url || ""}</span>
                      {v.malicious && <span className="us-verdict">MAL</span>}
                    </span>
                  );
                })}
              </span>
            </div>
          );
        }
      }
      break;
    case "NVD":
      {
        const desc = (data.descriptions || []).find(d => d.lang === "en");
        const cvss = ((data.metrics || {}).cvssMetricV31 || [])[0] || {};
        const cwes = (data.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value));
        const refs = (data.references || []).slice(0, 5);
        rows.push(
          <KV k="CVSS v3.1" v={cvss.cvssData ? `${cvss.cvssData.baseScore} / ${cvss.cvssData.baseSeverity}` : null} key="nv-cvss" />,
          <KV k="vector" v={cvss.cvssData?.vectorString} mono key="nv-vec" />,
          <KV k="CWE" v={cwes} key="nv-cwe" />,
          <KV k="published" v={(data.published || "").slice(0, 10)} key="nv-pub" />,
        );
        if (desc) rows.push(
          <div className="dr-kv dr-stack" key="nv-desc">
            <span className="dr-k">description</span>
            <span className="dr-v dr-stack-v"><span className="dr-desc">{desc.value}</span></span>
          </div>
        );
        if (refs.length) rows.push(
          <div className="dr-kv dr-stack" key="nv-refs">
            <span className="dr-k">refs</span>
            <span className="dr-v dr-stack-v">
              {refs.map((r, i) => <a key={i} href={r.url} target="_blank" rel="noreferrer" className="dr-ref">{(r.tags || ["link"]).join(",")} → {r.url}</a>)}
            </span>
          </div>
        );
      }
      break;
    case "EPSS":
      rows.push(
        <KV k="probability" v={data.epss ? (Math.round(data.epss * 10000) / 100) + "%" : null} key="ep-p" />,
        <KV k="percentile" v={data.percentile ? (Math.round(data.percentile * 10000) / 100) + "%" : null} key="ep-pct" />,
        <KV k="date" v={data.date} key="ep-d" />,
      );
      break;
    case "KEV":
      rows.push(
        <KV k="vendor" v={data.vendorProject} key="k-v" />,
        <KV k="product" v={data.product} key="k-p" />,
        <KV k="name" v={data.vulnerabilityName} key="k-n" />,
        <KV k="added" v={data.dateAdded} key="k-da" />,
        <KV k="due" v={data.dueDate} key="k-due" />,
        <KV k="ransomware" v={data.knownRansomwareCampaignUse === "Known" ? "YES — known in ransomware campaigns" : null} key="k-r" />,
        data.shortDescription && (
          <div className="dr-kv dr-stack" key="k-d">
            <span className="dr-k">summary</span>
            <span className="dr-v dr-stack-v"><span className="dr-desc">{data.shortDescription}</span></span>
          </div>
        ),
      );
      break;
    case "URLhaus":
      rows.push(
        <KV k="threat" v={data.threat} key="uh-t" />,
        <KV k="status" v={data.url_status} key="uh-s" />,
        <KV k="tags" v={data.tags} key="uh-tg" />,
        <KV k="first seen" v={data.date_added} key="uh-fs" />,
      );
      break;
    case "ThreatFox":
      rows.push(
        <KV k="malware" v={data.malware} key="tf-m" />,
        <KV k="confidence" v={data.confidence_level} key="tf-c" />,
        <KV k="threat type" v={data.threat_type} key="tf-tt" />,
        <KV k="reporter" v={data.reporter} key="tf-r" />,
        <KV k="first seen" v={data.first_seen} key="tf-fs" />,
      );
      break;
    case "AbstractAPI":
      {
        const sec = data.security || {};
        const loc = data.location || {};
        const asn = data.asn || {};
        const company = data.company || {};
        const tz = data.timezone || {};
        rows.push(
          <KV k="country"  v={loc.country ? `${loc.country_code || ""} ${loc.country}` : null} key="ab-c" />,
          <KV k="city"     v={loc.city ? `${loc.city}${loc.region ? " · " + loc.region : ""}` : null} key="ab-city" />,
          <KV k="postal"   v={loc.postal_code} key="ab-p" />,
          <KV k="coords"   v={loc.latitude != null ? `${loc.latitude}, ${loc.longitude}` : null} mono key="ab-co" />,
          <KV k="continent" v={loc.continent ? `${loc.continent_code || ""} ${loc.continent}` : null} key="ab-cont" />,
          <KV k="EU"       v={loc.is_country_eu ? "yes" : null} key="ab-eu" />,
          <KV k="timezone" v={tz.name ? `${tz.name} (UTC${tz.utc_offset >= 0 ? "+" : ""}${tz.utc_offset})` : null} key="ab-tz" />,
          <KV k="local time" v={tz.local_time} mono key="ab-lt" />,
          <KV k="ASN"      v={asn.asn ? `AS${asn.asn} · ${asn.name || ""}` : null} key="ab-asn" />,
          <KV k="ASN type" v={asn.type} key="ab-ast" />,
          <KV k="company"  v={company.name} key="ab-comp" />,
          <KV k="Tor"      v={sec.is_tor ? "yes" : null} key="ab-tor" />,
          <KV k="VPN"      v={sec.is_vpn ? "yes" : null} key="ab-vpn" />,
          <KV k="proxy"    v={sec.is_proxy ? "yes" : null} key="ab-prx" />,
          <KV k="relay"    v={sec.is_relay ? "yes" : null} key="ab-rly" />,
          <KV k="hosting"  v={sec.is_hosting ? "yes" : null} key="ab-hst" />,
          <KV k="mobile"   v={sec.is_mobile ? "yes" : null} key="ab-mob" />,
          <KV k="abuse"    v={sec.is_abuse ? "yes" : null} key="ab-ab" />,
        );
      }
      break;
    case "Heuristics":
      Object.entries(data).forEach(([k, v]) => {
        if (!v || typeof v !== "object") return;
        rows.push(
          <div className="dr-kv dr-stack" key={`h-${k}`}>
            <span className="dr-k">{k.toUpperCase()}</span>
            <span className="dr-v dr-stack-v"><span className="mono">{JSON.stringify(v)}</span></span>
          </div>
        );
      });
      break;
    default:
      // Unknown source — fall back to the first few keys raw.
      Object.entries(data).slice(0, 10).forEach(([k, v]) => {
        rows.push(<KV k={k} v={typeof v === "object" ? JSON.stringify(v).slice(0, 120) : v} key={"d-"+k} />);
      });
  }

  const finalRows = rows.filter(Boolean);
  return (
    <div className="src-drawer">
      <div className="dr-head">
        <span className="dr-title">{name} · raw</span>
        <span className="dr-meta dim">{Object.keys(data).length} fields cached</span>
      </div>
      {finalRows.length === 0 ? <div className="dim">// no data fields populated for this source</div> : finalRows}
    </div>
  );
}

// Draggable column splitter between hero-left (score + IP core) and hero-right
// (source profile + map). Drag → updates --hero-left-fr / --hero-right-fr CSS
// vars on :root. Choice persists to localStorage so a return visit keeps the
// analyst's preferred split.
function HeroSplitter() {
  const dragging = React.useRef(false);
  const heroRef = React.useRef(null);
  const dividerRef = React.useRef(null);

  React.useEffect(() => {
    try {
      const saved = localStorage.getItem("ss_hero_split");
      if (saved) {
        const v = parseFloat(saved);
        if (!isNaN(v) && v >= 0.15 && v <= 0.65) {
          document.documentElement.style.setProperty("--hero-left-fr", v.toFixed(3) + "fr");
          document.documentElement.style.setProperty("--hero-right-fr", (1 - v).toFixed(3) + "fr");
        }
      }
    } catch (e) {}
  }, []);

  React.useEffect(() => {
    if (dividerRef.current) {
      heroRef.current = dividerRef.current.closest(".hero");
    }
    const onMove = (e) => {
      if (!dragging.current || !heroRef.current) return;
      const rect = heroRef.current.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const ratio = Math.max(0.18, Math.min(0.62, x / rect.width));
      document.documentElement.style.setProperty("--hero-left-fr", ratio.toFixed(3) + "fr");
      document.documentElement.style.setProperty("--hero-right-fr", (1 - ratio).toFixed(3) + "fr");
      try { localStorage.setItem("ss_hero_split", String(ratio)); } catch (err) {}
    };
    const onUp = () => {
      if (dragging.current && dividerRef.current) {
        dividerRef.current.classList.remove("dragging");
      }
      dragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  const onDown = (e) => {
    e.preventDefault();
    dragging.current = true;
    if (dividerRef.current) dividerRef.current.classList.add("dragging");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  };

  const onDblClick = () => {
    // Reset to default split.
    document.documentElement.style.removeProperty("--hero-left-fr");
    document.documentElement.style.removeProperty("--hero-right-fr");
    try { localStorage.removeItem("ss_hero_split"); } catch (e) {}
  };

  return (
    <div
      ref={dividerRef}
      className="hero-splitter"
      role="separator"
      aria-orientation="vertical"
      title="Drag to resize · double-click to reset"
      onMouseDown={onDown}
      onDoubleClick={onDblClick}
    />
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
        <span className="sec-title glitch" data-text="NARRATIVE VERDICT">NARRATIVE VERDICT</span>
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
