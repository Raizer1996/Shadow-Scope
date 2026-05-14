import argparse
import os
import sys
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from ..core import (
    database,
    defang as defang_mod,
    enrich,
    extractor,
    llm as llm_mod,
    output as output_mod,
    parser,
)
from ..modules import (
    abuseipdb,  # noqa: F401  (imported for side-effect parity with previous CLI)
    filescan_io,
    hybrid_analysis,
    joe_sandbox,
    shodan_mod,
    vt,  # noqa: F401
)
from . import banner

console = Console()
# Separate console pinned to stderr — used when stdout must stay parse-clean
# (e.g. `--json` / `--csv` output piping into SIEMs and spreadsheets).
err_console = Console(stderr=True)


def _display_ioc(value: str, should_defang: bool) -> str:
    """Return the IOC string in the form expected by the user.

    When ``--defang`` is active we route the value through
    :func:`ioc_tool.core.defang.defang` so the rendered report is safe to
    paste into mail/ticket systems. Otherwise the live value is returned
    unchanged.
    """
    if should_defang and isinstance(value, str):
        return defang_mod.defang(value)
    return value


# ---------------------------------------------------------------------------
# Configuration / formatting helpers
# ---------------------------------------------------------------------------


def check_config(quiet: bool = False) -> None:
    """Print a warning panel for missing API keys.

    When ``quiet`` is True, the panel is routed to stderr so that
    callers piping ``--json`` / ``--csv`` to stdout still get a
    parse-clean machine-readable payload.
    """
    missing: List[str] = []
    if not os.getenv('VT_API_KEY'):
        missing.append("VT_API_KEY (VirusTotal)")
    if not os.getenv('ABUSEIPDB_API_KEY'):
        missing.append("ABUSEIPDB_API_KEY (AbuseIPDB)")
    if not os.getenv('HYBRID_ANALYSIS_API_KEY'):
        missing.append("HYBRID_ANALYSIS_API_KEY (Hybrid Analysis)")
    if not os.getenv('JOE_SANDBOX_CLOUD_API_KEY'):
        missing.append("JOE_SANDBOX_CLOUD_API_KEY (Joe Sandbox)")
    if not os.getenv('SHODAN_API_KEY'):
        missing.append("SHODAN_API_KEY (Shodan)")

    if missing:
        target = err_console if quiet else console
        target.print(
            Panel(
                f"[yellow]Warning: Missing API Keys for: {', '.join(missing)}.\n"
                f"Some modules will be skipped. Configure .env to enable them.[/yellow]",
                title="Configuration Warning",
                expand=False,
            )
        )


def get_score_color(score: int) -> str:
    if score >= 70:
        return "red"
    if score >= 40:
        return "yellow"
    return "green"


def print_single_result(result: Dict[str, Any], should_defang: bool = False) -> None:
    """Used for 'show' command - detailed view of a single IOC."""
    ioc_value = _display_ioc(result['ioc'], should_defang)
    ioc_type = result['type']
    final_score = result['final_score']
    color = get_score_color(final_score)
    risk_level = "Critical" if final_score >= 70 else "Medium" if final_score >= 40 else "Low"

    console.print(
        Panel(
            f"[bold {color}]IOC: {ioc_value} ({ioc_type.upper()})[/bold {color}]",
            expand=False,
        )
    )

    table = Table(title="Module Results")
    table.add_column("Source", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Details", style="dim")

    for source, data in result['modules'].items():
        score_val = data['score']
        score_color = get_score_color(score_val)

        details = ""
        if source == 'Virustotal':
            stats = data['data'].get('last_analysis_stats', {})
            details = f"Malicious: {stats.get('malicious', 0)}/{sum(stats.values())}"
        elif source == 'AbuseIPDB':
            details = f"Confidence: {data['data'].get('abuseConfidenceScore')}%"
        elif source == 'WHOIS':
            creation = data['data'].get('creation_date')
            details = f"Created: {creation}"
        elif source == 'TOR':
            details = "Tor Exit Node Detected"
        elif source == 'URLhaus':
            urlhaus_data = data['data']
            threat = urlhaus_data.get('threat', 'unknown')
            tags = urlhaus_data.get('tags') or []
            tag_str = f" [{', '.join(str(t) for t in tags)}]" if tags else ""
            details = f"Threat: {threat}{tag_str}"
        elif source == 'GreyNoise':
            gn_data = data['data']
            classification = gn_data.get('classification', 'unknown')
            name = gn_data.get('name')
            details = (
                f"Class: {classification}"
                + (f" — {name}" if name else "")
            )
        elif source == 'ThreatFox':
            tf_data = data['data']
            threat_type = tf_data.get('threat_type', 'unknown')
            malware = tf_data.get('malware', '')
            confidence = tf_data.get('confidence_level')
            parts = [f"Threat: {threat_type}"]
            if malware:
                parts.append(f"Malware: {malware}")
            if confidence is not None:
                parts.append(f"Confidence: {confidence}")
            details = " — ".join(parts)
        elif source == 'OTX':
            otx_data = data['data'] or {}
            pulse_info = otx_data.get('pulse_info') or {}
            pulse_count = pulse_info.get('count', 0) or 0
            pulses = pulse_info.get('pulses') or []
            parts = [f"Pulses: {pulse_count}"]
            # First few pulse names, truncated for readability.
            for pulse in pulses[:3]:
                name = (pulse.get('name') or '').strip()
                if not name:
                    continue
                if len(name) > 60:
                    name = name[:57] + '...'
                parts.append(name)
            adversary = ''
            if pulses:
                adversary = (pulses[0].get('adversary') or '').strip()
            if adversary:
                parts.append(f"Adversary: {adversary}")
            details = " — ".join(parts)
        elif source == 'URLscan':
            us_data = data['data'] or {}
            try:
                total = int(us_data.get('total', 0) or 0)
            except (TypeError, ValueError):
                total = 0
            us_results = us_data.get('results') or []
            parts = [f"Scans: {total}"]
            # First few result links (analysts click through for screenshots).
            for entry in us_results[:3]:
                if not isinstance(entry, dict):
                    continue
                link = entry.get('result')
                if link:
                    parts.append(f"[dim]{link}[/dim]")
            # If any malicious verdict, surface tags from the first one.
            for entry in us_results:
                if not isinstance(entry, dict):
                    continue
                verdicts = entry.get('verdicts') or {}
                overall = verdicts.get('overall') or {}
                if overall.get('malicious') is True:
                    tags = overall.get('tags') or []
                    if tags:
                        parts.append(
                            "Tags: " + ", ".join(str(t) for t in tags[:3])
                        )
                    break
            details = " — ".join(parts)
        elif source == 'NVD':
            nvd_data = data['data'] or {}
            metrics = nvd_data.get('metrics') or {}
            cvss_v31 = metrics.get('cvssMetricV31') or []
            base_score = None
            severity = None
            vector = None
            if cvss_v31:
                cvss_data = (cvss_v31[0] or {}).get('cvssData') or {}
                base_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
                vector = cvss_data.get('vectorString')
            descriptions = nvd_data.get('descriptions') or []
            description = ''
            for d in descriptions:
                if isinstance(d, dict) and d.get('lang') == 'en':
                    description = (d.get('value') or '').strip()
                    break
            parts = []
            if base_score is not None:
                parts.append(f"CVSS: {base_score}")
            if severity:
                parts.append(f"Severity: {severity}")
            if vector:
                parts.append(f"Vector: {vector}")
            if description:
                short = description if len(description) <= 120 else description[:117] + '...'
                parts.append(short)
            details = " — ".join(parts) if parts else "No CVSSv3.1 metric"
        elif source == 'EPSS':
            epss_data = data['data'] or {}
            try:
                epss_val = float(epss_data.get('epss', 0) or 0)
            except (TypeError, ValueError):
                epss_val = 0.0
            try:
                pct = float(epss_data.get('percentile', 0) or 0)
            except (TypeError, ValueError):
                pct = 0.0
            details = (
                f"EPSS: {epss_val:.5f} — Percentile: {pct * 100:.3f}%"
            )
        elif source == 'KEV':
            kev_data = data['data'] or {}
            vendor = kev_data.get('vendorProject', '')
            product = kev_data.get('product', '')
            date_added = kev_data.get('dateAdded', '')
            due_date = kev_data.get('dueDate', '')
            ransomware = kev_data.get('knownRansomwareCampaignUse', '')
            parts = ["Known-Exploited"]
            if vendor or product:
                parts.append(f"{vendor} {product}".strip())
            if date_added:
                parts.append(f"Added: {date_added}")
            if due_date:
                parts.append(f"Due: {due_date}")
            if ransomware == 'Known':
                parts.append("[red](ransomware)[/red]")
            details = " — ".join(parts)
        elif source == 'MalwareBazaar':
            mb_data = data['data']
            signature = mb_data.get('signature') or 'unknown'
            file_type = mb_data.get('file_type', '')
            file_size = mb_data.get('file_size', '')
            first_seen = mb_data.get('first_seen', '')
            parts = [f"Signature: {signature}"]
            if file_type:
                parts.append(f"Type: {file_type}")
            if file_size:
                parts.append(f"Size: {file_size}")
            if first_seen:
                parts.append(f"First seen: {first_seen}")
            details = " — ".join(parts)

        table.add_row(source, f"[{score_color}]{score_val}[/{score_color}]", str(details))

    console.print(table)
    console.print(
        f"\n[bold]Final Risk Score: [{color}]{final_score} ({risk_level})[/{color}][/bold]"
    )
    console.print("-" * 40)


def print_aggregated_table(
    results: List[Dict[str, Any]],
    should_defang: bool = False,
) -> None:
    """Used for 'enrich' command - summary table of all IOCs."""
    sorted_results = sorted(results, key=lambda x: (x['type'], -x['final_score']))

    table = Table(title="ShadowScope Results", box=None, show_lines=False)
    table.add_column("Type", style="bold magenta", width=8)
    table.add_column("IOC", style="white")
    table.add_column("Summary", style="dim")

    malicious_iocs: List[str] = []

    for res in sorted_results:
        score = res['final_score']
        ioc_type = res['type'].upper()
        ioc_value = _display_ioc(res['ioc'], should_defang)
        modules = res.get('modules', {})

        summary_parts: List[str] = []

        # VirusTotal Summary
        if 'VirusTotal' in modules:
            vt_data = modules['VirusTotal']['data']
            stats = vt_data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                summary_parts.append(f"[red]VT:Y[/red] [red]Score:{malicious}[/red]")
            else:
                summary_parts.append("[green]VT:N[/green]")

        # AbuseIPDB Summary
        if 'AbuseIPDB' in modules:
            abuse_data = modules['AbuseIPDB']['data']
            conf = abuse_data.get('abuseConfidenceScore', 0)
            if conf > 0:
                summary_parts.append(f"Abuse:{conf}")

        # Shodan / Tor (VPN/Proxy)
        is_vpn = False
        is_proxy = False
        is_tor = False

        if 'TOR' in modules:
            is_tor = True
            summary_parts.append("[purple]Tor:True 🧅[/purple]")

        if 'Shodan' in modules:
            shodan_data = modules['Shodan']['data']
            tags = shodan_data.get('tags', [])
            if 'vpn' in tags:
                is_vpn = True
            if 'proxy' in tags:
                is_proxy = True

        # AbuseIPDB also has usageType
        if 'AbuseIPDB' in modules:
            usage = modules['AbuseIPDB']['data'].get('usageType', '')
            if usage and 'VPN' in usage:
                is_vpn = True
            if usage and 'Proxy' in usage:
                is_proxy = True

        if is_vpn:
            summary_parts.append("[yellow]VPN:True[/yellow]")
        if is_proxy:
            summary_parts.append("[yellow]Proxy:True[/yellow]")

        # URLhaus (abuse.ch)
        if 'URLhaus' in modules:
            urlhaus_score = modules['URLhaus']['score']
            if urlhaus_score > 0:
                urlhaus_data = modules['URLhaus']['data']
                tags = urlhaus_data.get('tags') or []
                tag_fragment = (
                    " " + ",".join(str(t) for t in tags[:2]) if tags else ""
                )
                summary_parts.append(f"[red]URLhaus:HIT[/red]{tag_fragment}")

        # ThreatFox (abuse.ch) — fresh community-shared IOCs
        if 'ThreatFox' in modules:
            tf_score = modules['ThreatFox']['score']
            if tf_score > 0:
                tf_data = modules['ThreatFox']['data']
                malware = tf_data.get('malware')
                malware_fragment = f" [dim]({malware})[/dim]" if malware else ""
                summary_parts.append(f"[red]TF:HIT[/red]{malware_fragment}")

        # MalwareBazaar (abuse.ch) — hash → sample lookup
        if 'MalwareBazaar' in modules:
            mb_score = modules['MalwareBazaar']['score']
            if mb_score > 0:
                mb_data = modules['MalwareBazaar']['data']
                signature = mb_data.get('signature')
                sig_fragment = f" [dim]({signature})[/dim]" if signature else ""
                summary_parts.append(f"[red]MB:HIT[/red]{sig_fragment}")

        # AlienVault OTX — community pulse / threat-actor reports
        if 'OTX' in modules:
            otx_data = modules['OTX']['data'] or {}
            pulse_info = otx_data.get('pulse_info') or {}
            pulse_count = pulse_info.get('count', 0) or 0
            try:
                pulse_count = int(pulse_count)
            except (TypeError, ValueError):
                pulse_count = 0
            if pulse_count >= 1:
                if pulse_count >= 10:
                    color = 'red'
                elif pulse_count >= 3:
                    color = 'orange1'
                else:
                    color = 'yellow'
                pulses = pulse_info.get('pulses') or []
                adversary = ''
                if pulses:
                    adversary = (pulses[0].get('adversary') or '').strip()
                adversary_fragment = f" [dim]({adversary})[/dim]" if adversary else ""
                summary_parts.append(
                    f"[{color}]OTX:{pulse_count} pulses[/{color}]{adversary_fragment}"
                )

        # URLscan.io — historical scan-archive search
        if 'URLscan' in modules:
            us_data = modules['URLscan']['data'] or {}
            try:
                us_total = int(us_data.get('total', 0) or 0)
            except (TypeError, ValueError):
                us_total = 0
            if us_total >= 1:
                us_results = us_data.get('results') or []
                malicious_entry = None
                for entry in us_results:
                    if not isinstance(entry, dict):
                        continue
                    verdicts = entry.get('verdicts') or {}
                    overall = verdicts.get('overall') or {}
                    if overall.get('malicious') is True:
                        malicious_entry = entry
                        break
                if malicious_entry:
                    tags = (
                        ((malicious_entry.get('verdicts') or {}).get('overall') or {}).get('tags')
                        or []
                    )
                    tag_fragment = f" [dim]({tags[0]})[/dim]" if tags else ""
                    summary_parts.append(
                        f"[red]URLscan:Malicious[/red]{tag_fragment}"
                    )
                else:
                    summary_parts.append(
                        f"[yellow]URLscan:{us_total} seen[/yellow]"
                    )

        # NVD — CVSS base score colored by severity tier
        if 'NVD' in modules:
            nvd_data = modules['NVD']['data'] or {}
            metrics = nvd_data.get('metrics') or {}
            cvss_v31 = metrics.get('cvssMetricV31') or []
            if cvss_v31:
                cvss_data = (cvss_v31[0] or {}).get('cvssData') or {}
                base_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity') or ''
                if isinstance(base_score, (int, float)):
                    if base_score >= 9.0:
                        nvd_color = 'red'
                    elif base_score >= 7.0:
                        nvd_color = 'orange1'
                    elif base_score >= 4.0:
                        nvd_color = 'yellow'
                    else:
                        nvd_color = 'green'
                    sev_fragment = f" [{nvd_color}]{severity}[/{nvd_color}]" if severity else ""
                    summary_parts.append(
                        f"[{nvd_color}]CVSS:{base_score}[/{nvd_color}]{sev_fragment}"
                    )

        # EPSS — exploit-probability percentile
        if 'EPSS' in modules:
            epss_data = modules['EPSS']['data'] or {}
            try:
                pct = float(epss_data.get('percentile', 0) or 0)
            except (TypeError, ValueError):
                pct = 0.0
            pct_display = pct * 100
            if pct >= 0.99:
                summary_parts.append("[red]EPSS:99%+[/red]")
            elif pct >= 0.90:
                summary_parts.append(f"[orange1]EPSS:{pct_display:.1f}%[/orange1]")
            else:
                summary_parts.append(f"[dim]EPSS:{pct_display:.1f}%[/dim]")

        # CISA KEV — Known Exploited Vulnerabilities catalog hit
        if 'KEV' in modules:
            kev_data = modules['KEV']['data'] or {}
            vendor = kev_data.get('vendorProject', '')
            product = kev_data.get('product', '')
            label = f"{vendor} {product}".strip() or "listed"
            ransom_fragment = ""
            if kev_data.get('knownRansomwareCampaignUse') == 'Known':
                ransom_fragment = " [red](ransomware)[/red]"
            summary_parts.append(f"[red]KEV: {label}[/red]{ransom_fragment}")

        # GreyNoise — internet background-noise classification
        if 'GreyNoise' in modules:
            gn_data = modules['GreyNoise']['data']
            classification = gn_data.get('classification')
            is_noise = bool(gn_data.get('noise'))
            is_riot = bool(gn_data.get('riot'))
            if classification == 'benign' and is_noise:
                summary_parts.append("[green]GN:Noise/Benign[/green]")
            elif classification == 'benign' and is_riot:
                summary_parts.append("[green]GN:RIOT[/green]")
            elif classification == 'malicious':
                summary_parts.append("[red]GN:Malicious[/red]")
            # classification == 'unknown' -> deliberately omitted to
            # avoid polluting the table with non-signal cells.

        # IPQualityScore
        if 'IPQS' in modules:
            ipqs_score = modules['IPQS']['score']
            if ipqs_score > 75:
                summary_parts.append(f"[red]IPQS:{ipqs_score}[/red]")
            elif ipqs_score > 0:
                summary_parts.append(f"IPQS:{ipqs_score}")

        # IPinfo
        if 'IPinfo' in modules:
            org = modules['IPinfo']['data'].get('org', '')
            if org:
                summary_parts.append(f"[dim]{org}[/dim]")

        # Risk Score Coloring
        # Green: 0 (Safe)
        # Blue: 1-39 (Low)
        # Orange: 40-74 (Medium)
        # Red: 75-99 (High)
        # Purple: 100 (Critical)

        risk_level = "Safe"
        risk_color = "green"

        if score == 0:
            risk_level = "Safe"
            risk_color = "green"
        elif score < 40:
            risk_level = "Low"
            risk_color = "blue"
        elif score < 75:
            risk_level = "Medium"
            risk_color = "orange1"
        elif score < 100:
            risk_level = "High"
            risk_color = "red"
        else:
            risk_level = "Critical"
            risk_color = "purple"

        if is_tor:
            risk_level = "Critical"
            risk_color = "purple"

        summary_parts.append(f"Risk:[{risk_color}]{risk_level}[/{risk_color}]")

        summary_str = "  ".join(summary_parts)

        # STRICT BLOCKING: If VT malicious > 0 OR Risk Score >= 40
        is_malicious = False

        if 'VirusTotal' in modules:
            vt_mal = (
                modules['VirusTotal']['data'].get('last_analysis_stats', {}).get('malicious', 0)
            )
            if vt_mal > 0:
                is_malicious = True

        if score >= 40:
            is_malicious = True

        style = None
        if is_malicious:
            malicious_iocs.append(ioc_value)

        table.add_row(ioc_type, ioc_value, summary_str, style=style)

    console.print(table)

    if malicious_iocs:
        console.print("\n[bold red]🚨 Malicious IOCs (Block List)[/bold red]")
        console.print(Panel("\n".join(malicious_iocs), border_style="red"))
    else:
        console.print("\n[bold green]No malicious IOCs detected.[/bold green]")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def handle_enrich(args: argparse.Namespace) -> None:
    """Enrich one IOC (positional) and/or a newline-delimited file (-f).

    When ``--json`` or ``--csv`` is set, stdout is reserved for the
    machine-readable payload and all decorative chatter (status
    spinners, warnings, "skipping unknown IOC" notes) is routed to
    stderr — pipelines can pipe stdout straight into a SIEM or
    spreadsheet without scrubbing.
    """
    want_json = getattr(args, 'json', False)
    want_csv = getattr(args, 'csv', False)
    machine_readable = want_json or want_csv
    msg_console = err_console if machine_readable else console

    iocs_to_process: List[str] = []

    # --- Bulk text-blob mode ------------------------------------------------
    # `--text BLOB` and the `-` stdin sentinel both feed into the same
    # extractor pipeline and override any positional / -f input.
    blob_text: Optional[str] = getattr(args, 'text', None)
    if blob_text is None and getattr(args, 'ioc', None) == '-':
        blob_text = sys.stdin.read()

    if blob_text is not None:
        extracted = extractor.extract_iocs(blob_text)
        for bucket in extracted.values():
            iocs_to_process.extend(bucket)
        # One-line summary to stderr so analysts see what was pulled — but
        # only in human mode; JSON/CSV consumers want stdout pristine.
        if not machine_readable:
            total = len(iocs_to_process)
            parts = [f"{len(v)} {k}" for k, v in extracted.items()]
            summary = (
                f"Extracted {total} IOCs: {', '.join(parts)}"
                if parts
                else "Extracted 0 IOCs"
            )
            err_console.print(f"[dim]{summary}[/dim]")
    else:
        if getattr(args, 'ioc', None):
            iocs_to_process.append(args.ioc)

        file_path = getattr(args, 'file', None)
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            iocs_to_process.append(line)
            except FileNotFoundError:
                msg_console.print(f"[red]Error: File {file_path} not found.[/red]")
                return
            except OSError as exc:
                msg_console.print(f"[red]Error reading {file_path}: {exc}[/red]")
                return

    # Deduplicate while preserving order — text extraction can produce
    # repeats across types (e.g. domain + email-domain overlap), and the
    # enrichment cache is keyed on value anyway.
    seen: set[str] = set()
    deduped: List[str] = []
    for ioc in iocs_to_process:
        if ioc not in seen:
            seen.add(ioc)
            deduped.append(ioc)
    iocs_to_process = deduped

    if not iocs_to_process:
        msg_console.print("[yellow]No IOCs provided. Pass an IOC positional or -f FILE.[/yellow]")
        return

    results: List[Dict[str, Any]] = []
    if machine_readable:
        # No spinner — would leak escape codes to stdout via rich's redraw loop.
        for ioc in iocs_to_process:
            ioc_type = parser.detect_type(ioc)
            if ioc_type == 'unknown':
                msg_console.print(f"[yellow]Skipping unknown IOC type: {ioc}[/yellow]")
                continue

            result = enrich.enrich_ioc(ioc, ioc_type)
            results.append(result)
    else:
        with console.status("[bold green]Enriching IOCs...[/bold green]"):
            for ioc in iocs_to_process:
                ioc_type = parser.detect_type(ioc)
                if ioc_type == 'unknown':
                    console.print(f"[yellow]Skipping unknown IOC type: {ioc}[/yellow]")
                    continue

                result = enrich.enrich_ioc(ioc, ioc_type)
                results.append(result)

    if not results:
        return

    want_summary = bool(getattr(args, 'summary', False))
    summaries: Dict[int, Optional[str]] = {}
    if want_summary:
        # Compute one verdict per result upfront so JSON/CSV and table
        # branches share the same data. Each call wraps its own errors
        # and returns None on failure — never blocks the pipeline.
        for idx, res in enumerate(results):
            summaries[idx] = llm_mod.summarize(res)

    if want_json:
        if want_summary:
            payload: List[Dict[str, Any]] = []
            for idx, res in enumerate(results):
                merged = dict(res)
                merged['llm_summary'] = summaries.get(idx)
                payload.append(merged)
            print(output_mod.to_json(payload))
        else:
            print(output_mod.to_json(results))
        return
    if want_csv:
        # Use sys.stdout.write to preserve the trailing newline structure
        # exactly as csv.writer emits it; print() would append an extra \n.
        csv_text = output_mod.to_csv(results)
        if want_summary:
            # Append an llm_summary column on the fly. We pad header +
            # each row so the column count stays balanced.
            lines = csv_text.split("\n")
            if lines and lines[-1] == "":
                trailing_blank = True
                lines = lines[:-1]
            else:
                trailing_blank = False
            if lines:
                lines[0] = lines[0] + ",llm_summary"
                import csv as _csv
                import io as _io
                for i in range(1, len(lines)):
                    summary = summaries.get(i - 1) or ""
                    buf = _io.StringIO()
                    writer = _csv.writer(buf, lineterminator="")
                    writer.writerow([summary])
                    lines[i] = lines[i] + "," + buf.getvalue()
            csv_text = "\n".join(lines) + ("\n" if trailing_blank else "")
        sys.stdout.write(csv_text)
        return

    print_aggregated_table(results, should_defang=getattr(args, 'defang', False))
    if want_summary:
        for idx, res in enumerate(results):
            verdict = summaries.get(idx)
            if verdict:
                console.print(
                    Panel(
                        verdict,
                        title=f"LLM Verdict — {res.get('ioc')}",
                        border_style="cyan",
                        expand=False,
                    )
                )
            else:
                console.print(
                    f"[dim]LLM summary unavailable for {res.get('ioc')} "
                    "(Ollama not reachable)[/dim]"
                )


def handle_show(args: argparse.Namespace) -> None:
    """Pull cached enrichment for an IOC and print the detailed single-IOC view."""
    ioc_id = database.get_ioc_id(args.ioc)
    if not ioc_id:
        console.print(f"[red]IOC {args.ioc} not found in database.[/red]")
        return

    ioc_type = parser.detect_type(args.ioc)
    result = enrich.enrich_ioc(args.ioc, ioc_type)
    print_single_result(result, should_defang=getattr(args, 'defang', False))

    if getattr(args, 'summary', False):
        verdict = llm_mod.summarize(result)
        if verdict:
            console.print(
                Panel(
                    verdict,
                    title=f"LLM Verdict — {result.get('ioc')}",
                    border_style="cyan",
                    expand=False,
                )
            )
        else:
            console.print(
                "[dim]LLM summary unavailable (Ollama not reachable)[/dim]"
            )


def handle_analyze(
    args: Optional[argparse.Namespace] = None,
    target: Optional[str] = None,
    input_type: Optional[str] = None,
    provider: str = "4",
) -> None:
    """Sandbox analyze a file or URL across one or more providers.

    Called either with an argparse Namespace (subcommand path) or with
    keyword arguments (interactive-mode path). Auto-detects file vs URL
    via ``os.path.exists`` when invoked from the CLI.
    """
    if args is not None:
        target = args.target
        input_type = "file" if os.path.exists(target) else "url"
        provider = "4"  # CLI invocation defaults to running every available provider

    console.print("[bold cyan]File/URL Analysis[/bold cyan]")

    # Interactive fallback: ask for input type if still missing
    if not input_type:
        input_type = Prompt.ask("Choose input type", choices=["file", "url", "back"], default="file")
        if input_type == "back":
            return

    if not target:
        if input_type == "file":
            target = Prompt.ask("Enter file path")
        else:
            target = Prompt.ask("Enter URL")

    if input_type == "file" and not os.path.exists(target):
        console.print("[red]File not found[/red]")
        return

    # Resolve provider selection
    providers: List[str] = []
    if provider == "4":
        providers = ["hybrid", "joe", "filescan"]
    elif provider == "1":
        providers = ["hybrid"]
    elif provider == "2":
        providers = ["joe"]
    elif provider == "3":
        providers = ["filescan"]
    else:
        console.print("\n[bold cyan]Select Analysis Provider:[/bold cyan]")
        console.print("1. Hybrid Analysis")
        console.print("2. Joe Sandbox")
        console.print("3. FileScan.IO")
        console.print("4. All")

        choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4"], default="4")
        if choice == "1":
            providers = ["hybrid"]
        elif choice == "2":
            providers = ["joe"]
        elif choice == "3":
            providers = ["filescan"]
        else:
            providers = ["hybrid", "joe", "filescan"]

    for prov in providers:
        if prov == "hybrid":
            title = "Hybrid Analysis Results"
            func_file = hybrid_analysis.submit_file
            func_url = hybrid_analysis.submit_url
            style = "cyan"
        elif prov == "joe":
            title = "Joe Sandbox Results"
            func_file = joe_sandbox.submit_file
            func_url = joe_sandbox.submit_url
            style = "magenta"
        else:  # filescan
            title = "FileScan.IO Results"
            func_file = filescan_io.submit_file
            func_url = filescan_io.submit_url
            style = "green"

        console.print(f"\n[bold {style}]--- Running {title} ---[/bold {style}]")

        with console.status(f"[bold {style}]Submitting to {title}...[/bold {style}]"):
            if input_type == "file":
                res = func_file(target)
            else:
                res = func_url(target)

        if "error" in res:
            console.print(f"[red]Error: {res['error']}[/red]")
        else:
            console.print(Panel(str(res), title=title, border_style=style))


def handle_serve(args: argparse.Namespace) -> None:
    """Launch the FastAPI app under uvicorn.

    Imported lazily so the rest of the CLI doesn't pay the FastAPI /
    uvicorn import cost on every invocation. The ``--reload`` flag is
    intended for dev only; uvicorn requires an import-string target when
    reload is enabled, so we hand it ``ioc_tool.web.api:app`` in that
    case rather than the imported object.
    """
    import uvicorn

    if args.reload:
        uvicorn.run(
            "ioc_tool.web.api:app",
            host=args.host,
            port=args.port,
            reload=True,
        )
    else:
        from ioc_tool.web.api import app
        uvicorn.run(app, host=args.host, port=args.port)


def handle_shodan(
    args: Optional[argparse.Namespace] = None,
    target: Optional[str] = None,
) -> None:
    """Shodan-only host lookup. Accepts an argparse Namespace or a bare target string."""
    if args is not None:
        target = args.target

    console.print("[bold cyan]Shadow OSINT (Shodan)[/bold cyan]")
    if not target:
        target = Prompt.ask("Enter Target IP")

    with console.status("[bold green]Scanning Shadow Realm...[/bold green]"):
        res = shodan_mod.host_search(target)

    if "error" in res:
        console.print(f"[red]Error: {res['error']}[/red]")
        return

    table = Table(title=f"Shodan Results: {target}", show_header=False, box=None)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    table.add_row("IP", str(res.get('ip_str', 'N/A')))
    table.add_row("Organization", str(res.get('org', 'N/A')))
    table.add_row("ISP", str(res.get('isp', 'N/A')))
    table.add_row("ASN", str(res.get('asn', 'N/A')))
    table.add_row(
        "Country",
        f"{res.get('country_name', 'N/A')} ({res.get('country_code', 'N/A')})",
    )
    table.add_row("City", str(res.get('city', 'N/A')))
    table.add_row("Operating System", str(res.get('os', 'N/A')))
    table.add_row("Last Update", str(res.get('last_update', 'N/A')))

    ports = res.get('ports', [])
    table.add_row("Open Ports", ", ".join(map(str, ports)) if ports else "None")

    hostnames = res.get('hostnames', [])
    table.add_row("Hostnames", ", ".join(hostnames) if hostnames else "None")

    domains = res.get('domains', [])
    table.add_row("Domains", ", ".join(domains) if domains else "None")

    vulns = res.get('vulns', [])
    if vulns:
        table.add_row("Vulnerabilities", f"[red]{', '.join(vulns)}[/red]")

    console.print(table)

    if 'data' in res:
        port_table = Table(title="Port Details", show_header=True, header_style="bold magenta")
        port_table.add_column("Port")
        port_table.add_column("Protocol")
        port_table.add_column("Product")
        port_table.add_column("Version")

        for item in res['data']:
            port = str(item.get('port', ''))
            proto = item.get('transport', '')
            product = item.get('product', '')
            version = item.get('version', '')
            port_table.add_row(port, proto, product, version)

        console.print(port_table)


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------


def interactive_mode() -> None:
    while True:
        console.print("\n[bold cyan]Select Mode:[/bold cyan]")
        console.print("1. IOC Checker (Enrichment)")
        console.print("2. File/Link Analysis (Multi-Sandbox)")
        console.print("3. Shadow OSINT (Shodan)")
        console.print("4. Exit")

        choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4"])

        if choice == "1":
            target = Prompt.ask("Enter IOC (or path to file)")
            if os.path.exists(target):
                console.print(f"[dim]Detected file: {target}[/dim]")
                ns = argparse.Namespace(ioc=None, file=target)
            else:
                ns = argparse.Namespace(ioc=target, file=None)
            handle_enrich(ns)

        elif choice == "2":
            handle_analyze()

        elif choice == "3":
            handle_shodan()

        elif choice == "4":
            console.print("[bold green]Closing Secure Uplink...[/bold green]")
            break


# ---------------------------------------------------------------------------
# Argparse plumbing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser with all subcommands.

    Factored out so tests can exercise parser construction and --help
    without touching the rest of the CLI surface (banner, DB init, etc.).
    """
    parser_arg = argparse.ArgumentParser(
        prog="shadowscope",
        description="ShadowScope — terminal IOC enrichment & sandbox CLI",
    )
    parser_arg.add_argument(
        '--defang',
        action='store_true',
        default=False,
        help='Defang IOCs in printed output (e.g. 1.2.3.4 → 1[.]2[.]3[.]4) so reports are safe to share',
    )
    parser_arg.add_argument(
        '--summary',
        action='store_true',
        default=False,
        help='Append an LLM-generated natural-language verdict (requires local Ollama)',
    )
    subparsers = parser_arg.add_subparsers(dest='command', metavar='<command>')

    # enrich
    p_enrich = subparsers.add_parser(
        'enrich',
        help='Enrich an IOC (IP / domain / URL / hash) or a file of IOCs',
    )
    p_enrich.add_argument(
        'ioc',
        nargs='?',
        default=None,
        help='IOC value to enrich (optional if -f is given). Pass "-" to read a text blob from stdin and auto-extract IOCs.',
    )
    p_enrich.add_argument(
        '-f', '--file',
        dest='file',
        default=None,
        help='Path to a file with one IOC per line',
    )
    p_enrich.add_argument(
        '--text',
        metavar='BLOB',
        default=None,
        help='Extract IOCs from a free-form text blob and enrich each (overrides positional ioc / -f)',
    )
    output_group = p_enrich.add_mutually_exclusive_group()
    output_group.add_argument(
        '--json',
        action='store_true',
        help='Output as JSON instead of rich table (stdout stays parse-clean)',
    )
    output_group.add_argument(
        '--csv',
        action='store_true',
        help='Output as CSV instead of rich table (stdout stays parse-clean)',
    )
    # --summary is also exposed on the top-level parser (above) so it works
    # before the subcommand (`--summary enrich 8.8.8.8`); duplicating it on the
    # subparser keeps `enrich 8.8.8.8 --summary` working too. ``default=None``
    # ensures the subparser's value never overrides a top-level ``--summary``.
    p_enrich.add_argument(
        '--summary',
        action='store_true',
        default=argparse.SUPPRESS,
        help='Append an LLM-generated natural-language verdict (requires local Ollama)',
    )

    # analyze
    p_analyze = subparsers.add_parser(
        'analyze',
        help='Submit a file or URL to sandbox providers (auto-detects)',
    )
    p_analyze.add_argument(
        'target',
        help='File path or URL to analyze',
    )

    # shodan
    p_shodan = subparsers.add_parser(
        'shodan',
        help='Shodan-only host lookup for an IP',
    )
    p_shodan.add_argument(
        'target',
        help='IP to look up via Shodan',
    )

    # show
    p_show = subparsers.add_parser(
        'show',
        help='Show cached enrichment details for a previously-enriched IOC',
    )
    p_show.add_argument(
        'ioc',
        help='IOC value to show',
    )
    p_show.add_argument(
        '--summary',
        action='store_true',
        default=argparse.SUPPRESS,
        help='Append an LLM-generated natural-language verdict (requires local Ollama)',
    )

    # serve — REST API
    p_serve = subparsers.add_parser(
        'serve',
        help='Start the REST API server',
    )
    p_serve.add_argument(
        '--host',
        default='127.0.0.1',
        help='Bind address (default: 127.0.0.1)',
    )
    p_serve.add_argument(
        '--port',
        type=int,
        default=8765,
        help='Port (default: 8765)',
    )
    p_serve.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload (dev mode)',
    )

    return parser_arg


def main() -> None:
    # No args -> interactive mode (banner + menu).
    if len(sys.argv) == 1:
        if not banner.show():
            pass
        database.init_db()
        check_config()
        try:
            interactive_mode()
        except KeyboardInterrupt:
            print("\n\n[!] ShadowScope connection terminated by user.")
            sys.exit(0)
        return

    parser_arg = build_parser()
    args = parser_arg.parse_args()

    if args.command is None:
        parser_arg.print_help()
        return

    # When the user wants machine-readable output, stdout is reserved
    # for the payload. Skip the banner entirely and send the missing-
    # keys warning to stderr so JSON/CSV pipes stay parse-clean.
    machine_readable = bool(
        getattr(args, 'json', False) or getattr(args, 'csv', False)
    )

    if not machine_readable:
        if not banner.show():
            pass
    database.init_db()
    check_config(quiet=machine_readable)

    if args.command == 'enrich':
        handle_enrich(args)
    elif args.command == 'analyze':
        handle_analyze(args)
    elif args.command == 'shodan':
        handle_shodan(args)
    elif args.command == 'show':
        handle_show(args)
    elif args.command == 'serve':
        handle_serve(args)
    else:
        parser_arg.print_help()


if __name__ == "__main__":
    main()
