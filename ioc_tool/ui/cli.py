import argparse
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from ..core import parser, enrich, database
from ..modules import vt, abuseipdb, hybrid_analysis, joe_sandbox, shodan_mod, filescan_io, joe_sandbox
from . import banner

console = Console()

# ... (check_config remains similar but needs update too)

def check_config():
    missing = []
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
        console.print(Panel(f"[yellow]Warning: Missing API Keys for: {', '.join(missing)}.\nSome modules will be skipped. Configure .env to enable them.[/yellow]", title="Configuration Warning", expand=False))

def get_score_color(score):
    if score >= 70: return "red"
    if score >= 40: return "yellow"
    return "green"

def print_single_result(result):
    """
    Used for 'show' command - detailed view of a single IOC
    """
    ioc_value = result['ioc']
    ioc_type = result['type']
    final_score = result['final_score']
    color = get_score_color(final_score)
    risk_level = "Critical" if final_score >= 70 else "Medium" if final_score >= 40 else "Low"

    console.print(Panel(f"[bold {color}]IOC: {ioc_value} ({ioc_type.upper()})[/bold {color}]", expand=False))
    
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
            
        table.add_row(source, f"[{score_color}]{score_val}[/{score_color}]", str(details))
        
    console.print(table)
    console.print(f"\n[bold]Final Risk Score: [{color}]{final_score} ({risk_level})[/{color}][/bold]")
    console.print("-" * 40)

def print_aggregated_table(results):
    """
    Used for 'enrich' command - summary table of all IOCs
    """
    # Sort by Type (asc), then Score (desc)
    sorted_results = sorted(results, key=lambda x: (x['type'], -x['final_score']))
    
    table = Table(title="ShadowScope Results", box=None, show_lines=False)
    table.add_column("Type", style="bold magenta", width=8)
    table.add_column("IOC", style="white")
    table.add_column("Summary", style="dim")
    
    malicious_iocs = []
    
    for res in sorted_results:
        score = res['final_score']
        ioc_type = res['type'].upper()
        ioc_value = res['ioc']
        modules = res.get('modules', {})
        
        summary_parts = []
        
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
            if 'vpn' in tags: is_vpn = True
            if 'proxy' in tags: is_proxy = True
            
        # AbuseIPDB also has usageType
        if 'AbuseIPDB' in modules:
            usage = modules['AbuseIPDB']['data'].get('usageType', '')
            if usage and 'VPN' in usage: is_vpn = True
            if usage and 'Proxy' in usage: is_proxy = True
            
        if is_vpn: summary_parts.append("[yellow]VPN:True[/yellow]")
        if is_proxy: summary_parts.append("[yellow]Proxy:True[/yellow]")
        
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
                # No truncation as requested by user
                summary_parts.append(f"[dim]{org}[/dim]")
        # Risk Score Coloring
        # Green: 0
        # Blue: 1-39
        # Orange: 40-74
        # Red: 75-99
        # Purple: 100 (or Tor)
        
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
        
        # Construct Row
        summary_str = "  ".join(summary_parts)
        
        # Highlight malicious rows
        # STRICT BLOCKING: If VT malicious > 0 OR Risk Score >= 40
        is_malicious = False
        
        # Check VT Malicious count
        if 'VirusTotal' in modules:
            vt_mal = modules['VirusTotal']['data'].get('last_analysis_stats', {}).get('malicious', 0)
            if vt_mal > 0:
                is_malicious = True
                
        # Check Risk Score
        if score >= 40:
            is_malicious = True
            
        style = None
        if is_malicious:
            malicious_iocs.append(ioc_value)
            # style = "bold red" # Optional
            
        table.add_row(ioc_type, ioc_value, summary_str, style=style)
            
    console.print(table)
    
    if malicious_iocs:
        console.print("\n[bold red]🚨 Malicious IOCs (Block List)[/bold red]")
        console.print(Panel("\n".join(malicious_iocs), border_style="red"))
    else:
        console.print("\n[bold green]No malicious IOCs detected.[/bold green]")

def handle_enrich(args):
    iocs_to_process = []
    
    if args.ioc:
        iocs_to_process.append(args.ioc)
        
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        iocs_to_process.append(line)
        except FileNotFoundError:
            console.print(f"[red]Error: File {args.file} not found.[/red]")
            return

    if not iocs_to_process:
        console.print("[yellow]No IOCs provided. Use --ioc or --file.[/yellow]")
        return

    results = []
    with console.status("[bold green]Enriching IOCs...[/bold green]") as status:
        for ioc in iocs_to_process:
            ioc_type = parser.detect_type(ioc)
            if ioc_type == 'unknown':
                console.print(f"[yellow]Skipping unknown IOC type: {ioc}[/yellow]")
                continue
                
            result = enrich.enrich_ioc(ioc, ioc_type)
            results.append(result)
            
    print_aggregated_table(results)

def handle_show(args):
    ioc_id = database.get_ioc_id(args.ioc)
    if not ioc_id:
        console.print(f"[red]IOC {args.ioc} not found in database.[/red]")
        return
        
    ioc_type = parser.detect_type(args.ioc)
    result = enrich.enrich_ioc(args.ioc, ioc_type)
    print_single_result(result)

def handle_sandbox(target=None, input_type=None, provider="3"):
    console.print("[bold cyan]File/URL Analysis[/bold cyan]")
    
    # 1. Choose Input Type
    if not input_type:
        input_type = Prompt.ask("Choose input type", choices=["file", "url", "back"], default="file")
        if input_type == "back": return

    # 2. Get Target
    if not target:
        if input_type == "file":
            target = Prompt.ask("Enter file path")
        else:
            target = Prompt.ask("Enter URL")

    if input_type == "file" and not os.path.exists(target):
        console.print("[red]File not found[/red]")
        return

    # 3. Choose Provider
    providers = []
    if provider == "4": # Default/All
        providers = ["hybrid", "joe", "filescan"]
    elif provider == "1":
        providers = ["hybrid"]
    elif provider == "2":
        providers = ["joe"]
    elif provider == "3":
        providers = ["filescan"]
    else:
        # Interactive choice
        console.print("\n[bold cyan]Select Analysis Provider:[/bold cyan]")
        console.print("1. Hybrid Analysis")
        console.print("2. Joe Sandbox")
        console.print("3. FileScan.IO")
        console.print("4. All")
        
        choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4"], default="4")
        if choice == "1": providers = ["hybrid"]
        elif choice == "2": providers = ["joe"]
        elif choice == "3": providers = ["filescan"]
        else: providers = ["hybrid", "joe", "filescan"]
        
    # 4. Execute
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
        elif prov == "filescan":
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

def handle_shodan(target=None):
    console.print("[bold cyan]Shadow OSINT (Shodan)[/bold cyan]")
    if not target:
        target = Prompt.ask("Enter Target IP")
    
    with console.status("[bold green]Scanning Shadow Realm...[/bold green]"):
        res = shodan_mod.host_search(target)
        
    if "error" in res:
        console.print(f"[red]Error: {res['error']}[/red]")
        return

    # Create main info table
    table = Table(title=f"Shodan Results: {target}", show_header=False, box=None)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    
    # Basic Info
    table.add_row("IP", str(res.get('ip_str', 'N/A')))
    table.add_row("Organization", str(res.get('org', 'N/A')))
    table.add_row("ISP", str(res.get('isp', 'N/A')))
    table.add_row("ASN", str(res.get('asn', 'N/A')))
    table.add_row("Country", f"{res.get('country_name', 'N/A')} ({res.get('country_code', 'N/A')})")
    table.add_row("City", str(res.get('city', 'N/A')))
    table.add_row("Operating System", str(res.get('os', 'N/A')))
    table.add_row("Last Update", str(res.get('last_update', 'N/A')))
    
    # Lists
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
    
    # Detailed Port Info
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

def interactive_mode():
    while True:
        console.print("\n[bold cyan]Select Mode:[/bold cyan]")
        console.print("1. IOC Checker (Enrichment)")
        console.print("2. File/Link Analysis (Multi-Sandbox)")
        console.print("3. Shadow OSINT (Shodan)")
        console.print("4. Exit")
        
        choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            target = Prompt.ask("Enter IOC (or path to file)")
            # Check if user entered a file path
            if os.path.exists(target):
                console.print(f"[dim]Detected file: {target}[/dim]")
                args = argparse.Namespace(ioc=None, file=target)
            else:
                # Treat as single IOC
                args = argparse.Namespace(ioc=target, file=None)
            
            handle_enrich(args)
            
        elif choice == "2":
            handle_sandbox()
            
        elif choice == "3":
            handle_shodan()

        elif choice == "4":
            console.print("[bold green]Closing Secure Uplink...[/bold green]")
            break

def main():
    # Show Banner & Check Connection
    if not banner.show():
        # If connection failed, we might still want to allow local work or exit?
        # User said "show like it failed", didn't say exit.
        pass

    parser_arg = argparse.ArgumentParser(description="ShadowScope CLI")
    
    # Shortcuts
    parser_arg.add_argument('-1', '--check', help='Quick Check (Enrichment) for IOC/File')
    parser_arg.add_argument('-2', '--analyze', help='Quick Analysis (Sandbox) for File/URL')
    parser_arg.add_argument('-3', '--shodan', help='Quick OSINT (Shodan) for IP')
    
    subparsers = parser_arg.add_subparsers(dest='command', help='Commands')
    
    # Enrich Command
    enrich_parser = subparsers.add_parser('enrich', help='Enrich IOCs')
    enrich_parser.add_argument('--ioc', help='Single IOC value')
    enrich_parser.add_argument('--file', help='Path to file containing IOCs')
    
    # Show Command
    show_parser = subparsers.add_parser('show', help='Show IOC details')
    show_parser.add_argument('--ioc', required=True, help='IOC value to show')
    
    args = parser_arg.parse_args()
    
    # Initialize DB
    database.init_db()
    
    # Check configuration
    check_config()
    
    # Handle Shortcuts
    if args.check:
        target = args.check
        if os.path.exists(target):
            handle_enrich(argparse.Namespace(ioc=None, file=target))
        else:
            handle_enrich(argparse.Namespace(ioc=target, file=None))
        return

    if args.analyze:
        target = args.analyze
        # Auto-detect input type
        if os.path.exists(target):
            input_type = "file"
        else:
            input_type = "url"
        
        handle_sandbox(target=target, input_type=input_type, provider="4") # Default to All (4)
        return

    if args.shodan:
        handle_shodan(target=args.shodan)
        return
    
    if args.command == 'enrich':
        handle_enrich(args)
    elif args.command == 'show':
        handle_show(args)
    elif len(sys.argv) == 1:
        # No arguments provided -> Interactive Mode
        try:
            interactive_mode()
        except KeyboardInterrupt:
            print("\n\n[!] ShadowScope connection terminated by user.")
            sys.exit(0)
    else:
        parser_arg.print_help()

if __name__ == "__main__":
    main()
