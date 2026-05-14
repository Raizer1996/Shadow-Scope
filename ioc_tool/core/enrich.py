from datetime import datetime, timedelta
import json
from . import database
from . import score
from ..modules import vt, abuseipdb, whois_mod, tor, ip_quality_score, ipinfo_mod, urlhaus, greynoise, threatfox, malwarebazaar, otx, urlscan

def should_refresh(timestamp_str):
    if not timestamp_str:
        return True
    try:
        # Handle different timestamp formats if necessary, but DB stores as standard string usually
        # SQLite default timestamp is often 'YYYY-MM-DD HH:MM:SS.ssssss'
        last_check = datetime.fromisoformat(timestamp_str) if 'T' in timestamp_str else datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        try:
             last_check = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except:
            return True
            
    return datetime.now() - last_check > timedelta(hours=24)

def enrich_ioc(value, ioc_type):
    # 1. Ensure IOC is in DB
    ioc_id = database.add_or_update_ioc(value, ioc_type)
    
    results = {}
    scores = []
    
    # --- VirusTotal ---
    # Check cache
    cached_vt = database.get_latest_enrichment(ioc_id, 'virustotal')
    vt_data = None
    vt_score = 0
    
    if cached_vt and not should_refresh(cached_vt['timestamp']):
        vt_data = json.loads(cached_vt['data'])
        vt_score = cached_vt['score']
    else:
        # Fetch fresh
        if ioc_type == 'ip':
            vt_data = vt.enrich_ip(value)
        elif ioc_type == 'domain':
            vt_data = vt.enrich_domain(value)
        elif ioc_type == 'url':
            vt_data = vt.enrich_url(value)
        elif ioc_type == 'hash':
            vt_data = vt.enrich_hash(value)
            
        if vt_data:
            vt_score = score.calculate_vt_score(vt_data.get('last_analysis_stats', {}))
            database.add_enrichment(ioc_id, 'virustotal', vt_data, vt_score)
            
    if vt_data:
        results['VirusTotal'] = {'score': vt_score, 'data': vt_data}
        scores.append(vt_score)

    # --- AbuseIPDB (IP Only) ---
    if ioc_type == 'ip':
        cached_abuse = database.get_latest_enrichment(ioc_id, 'abuseipdb')
        abuse_data = None
        abuse_score = 0
        
        if cached_abuse and not should_refresh(cached_abuse['timestamp']):
            abuse_data = json.loads(cached_abuse['data'])
            abuse_score = cached_abuse['score']
        else:
            abuse_data = abuseipdb.enrich_ip(value)
            if abuse_data:
                abuse_score = score.calculate_abuseipdb_score(abuse_data)
                database.add_enrichment(ioc_id, 'abuseipdb', abuse_data, abuse_score)
        
        if abuse_data:
            results['AbuseIPDB'] = {'score': abuse_score, 'data': abuse_data}
            scores.append(abuse_score)

    # --- TOR Detection (IP Only) ---
    if ioc_type == 'ip':
        is_tor = tor.is_tor_node(value)
        if is_tor:
            results['TOR'] = {'score': 100, 'data': {'is_tor': True}}
            scores.append(100) # High risk if Tor node

    # --- Shodan (IP Only) ---
    if ioc_type == 'ip':
        cached_shodan = database.get_latest_enrichment(ioc_id, 'shodan')
        shodan_data = None
        
        if cached_shodan and not should_refresh(cached_shodan['timestamp']):
            shodan_data = json.loads(cached_shodan['data'])
        else:
            from ..modules import shodan_mod
            shodan_data = shodan_mod.host_search(value)
            if shodan_data and "error" not in shodan_data:
                # Shodan doesn't have a direct "score" in this context, but we use it for tags
                database.add_enrichment(ioc_id, 'shodan', shodan_data, 0)
            elif shodan_data and "error" in shodan_data:
                shodan_data = None # Don't store errors as data
        
        if shodan_data:
            results['Shodan'] = {'score': 0, 'data': shodan_data}

    # --- IPQualityScore (IP Only) ---
    if ioc_type == 'ip':
        cached_ipqs = database.get_latest_enrichment(ioc_id, 'ipqs')
        ipqs_data = None
        
        if cached_ipqs and not should_refresh(cached_ipqs['timestamp']):
            ipqs_data = json.loads(cached_ipqs['data'])
        else:
            ipqs_data = ip_quality_score.enrich_ip(value)
            if ipqs_data:
                # Use fraud_score directly as risk score
                score_val = ipqs_data.get('fraud_score', 0)
                database.add_enrichment(ioc_id, 'ipqs', ipqs_data, score_val)
                
        if ipqs_data:
            results['IPQS'] = {'score': ipqs_data.get('fraud_score', 0), 'data': ipqs_data}
            scores.append(ipqs_data.get('fraud_score', 0))

    # --- IPinfo (IP Only) ---
    if ioc_type == 'ip':
        cached_ipinfo = database.get_latest_enrichment(ioc_id, 'ipinfo')
        ipinfo_data = None
        
        if cached_ipinfo and not should_refresh(cached_ipinfo['timestamp']):
            ipinfo_data = json.loads(cached_ipinfo['data'])
        else:
            ipinfo_data = ipinfo_mod.enrich_ip(value)
            if ipinfo_data:
                database.add_enrichment(ioc_id, 'ipinfo', ipinfo_data, 0)
                
        if ipinfo_data:
            results['IPinfo'] = {'score': 0, 'data': ipinfo_data}


    # --- GreyNoise (IP Only) ---
    if ioc_type == 'ip':
        cached_gn = database.get_latest_enrichment(ioc_id, 'greynoise')
        gn_data = None
        gn_score = 0

        if cached_gn and not should_refresh(cached_gn['timestamp']):
            gn_data = json.loads(cached_gn['data'])
            gn_score = cached_gn['score']
        else:
            gn_data = greynoise.enrich_ip(value)
            if gn_data:
                gn_score = score.calculate_greynoise_score(gn_data)
                database.add_enrichment(ioc_id, 'greynoise', gn_data, gn_score)

        if gn_data:
            results['GreyNoise'] = {'score': gn_score, 'data': gn_data}
            scores.append(gn_score)

    # --- URLhaus (abuse.ch) — URL / domain / IP (no API key) ---
    if ioc_type in ('url', 'domain', 'ip'):
        cached_urlhaus = database.get_latest_enrichment(ioc_id, 'urlhaus')
        urlhaus_data = None
        urlhaus_score = 0

        if cached_urlhaus and not should_refresh(cached_urlhaus['timestamp']):
            urlhaus_data = json.loads(cached_urlhaus['data'])
            urlhaus_score = cached_urlhaus['score']
        else:
            if ioc_type == 'url':
                urlhaus_data = urlhaus.enrich_url(value)
            else:
                urlhaus_data = urlhaus.enrich_host(value)

            if urlhaus_data:
                urlhaus_score = score.calculate_urlhaus_score(urlhaus_data)
                database.add_enrichment(ioc_id, 'urlhaus', urlhaus_data, urlhaus_score)

        if urlhaus_data:
            results['URLhaus'] = {'score': urlhaus_score, 'data': urlhaus_data}
            scores.append(urlhaus_score)

    # --- ThreatFox (abuse.ch) — IP / domain / URL / hash (no API key) ---
    if ioc_type in ('ip', 'domain', 'url', 'hash'):
        cached_threatfox = database.get_latest_enrichment(ioc_id, 'threatfox')
        threatfox_data = None
        threatfox_score = 0

        if cached_threatfox and not should_refresh(cached_threatfox['timestamp']):
            threatfox_data = json.loads(cached_threatfox['data'])
            threatfox_score = cached_threatfox['score']
        else:
            threatfox_data = threatfox.enrich(value)
            if threatfox_data:
                threatfox_score = score.calculate_threatfox_score(threatfox_data)
                database.add_enrichment(ioc_id, 'threatfox', threatfox_data, threatfox_score)

        if threatfox_data:
            results['ThreatFox'] = {'score': threatfox_score, 'data': threatfox_data}
            scores.append(threatfox_score)

    # --- AlienVault OTX — IP / domain / URL / hash (free API key) ---
    if ioc_type in ('ip', 'domain', 'url', 'hash'):
        cached_otx = database.get_latest_enrichment(ioc_id, 'otx')
        otx_data = None
        otx_score = 0

        if cached_otx and not should_refresh(cached_otx['timestamp']):
            otx_data = json.loads(cached_otx['data'])
            otx_score = cached_otx['score']
        else:
            otx_data = otx.enrich(value, ioc_type)
            if otx_data:
                otx_score = score.calculate_otx_score(otx_data)
                database.add_enrichment(ioc_id, 'otx', otx_data, otx_score)

        if otx_data:
            results['OTX'] = {'score': otx_score, 'data': otx_data}
            scores.append(otx_score)

    # --- URLscan.io — IP / domain / URL (free key optional, anon allowed) ---
    if ioc_type in ('ip', 'domain', 'url'):
        cached_urlscan = database.get_latest_enrichment(ioc_id, 'urlscan')
        urlscan_data = None
        urlscan_score = 0

        if cached_urlscan and not should_refresh(cached_urlscan['timestamp']):
            urlscan_data = json.loads(cached_urlscan['data'])
            urlscan_score = cached_urlscan['score']
        else:
            urlscan_data = urlscan.enrich(value, ioc_type)
            if urlscan_data:
                urlscan_score = score.calculate_urlscan_score(urlscan_data)
                database.add_enrichment(ioc_id, 'urlscan', urlscan_data, urlscan_score)

        if urlscan_data:
            results['URLscan'] = {'score': urlscan_score, 'data': urlscan_data}
            scores.append(urlscan_score)

    # --- MalwareBazaar (abuse.ch) — hash only (no API key) ---
    if ioc_type == 'hash':
        cached_mb = database.get_latest_enrichment(ioc_id, 'malwarebazaar')
        mb_data = None
        mb_score = 0

        if cached_mb and not should_refresh(cached_mb['timestamp']):
            mb_data = json.loads(cached_mb['data'])
            mb_score = cached_mb['score']
        else:
            mb_data = malwarebazaar.enrich_hash(value)
            if mb_data:
                mb_score = score.calculate_malwarebazaar_score(mb_data)
                database.add_enrichment(ioc_id, 'malwarebazaar', mb_data, mb_score)

        if mb_data:
            results['MalwareBazaar'] = {'score': mb_score, 'data': mb_data}
            scores.append(mb_score)

    # --- WHOIS (Domain Only) ---
    if ioc_type == 'domain':
        cached_whois = database.get_latest_enrichment(ioc_id, 'whois')
        whois_data = None
        whois_score = 0
        
        if cached_whois and not should_refresh(cached_whois['timestamp']):
            whois_data = json.loads(cached_whois['data'])
            whois_score = cached_whois['score']
        else:
            whois_data = whois_mod.get_whois_data(value)
            if whois_data:
                # whois_data contains datetime objects which are not JSON serializable directly
                # We need to serialize them before storing
                serializable_whois = {}
                for k, v in whois_data.items():
                    if isinstance(v, datetime):
                        serializable_whois[k] = v.isoformat()
                    elif isinstance(v, list):
                        serializable_whois[k] = [x.isoformat() if isinstance(x, datetime) else x for x in v]
                    else:
                        serializable_whois[k] = v
                        
                whois_score = score.calculate_whois_score(whois_data.get('creation_date'))
                database.add_enrichment(ioc_id, 'whois', serializable_whois, whois_score)
                whois_data = serializable_whois # Use serializable for return
        
        if whois_data:
            results['WHOIS'] = {'score': whois_score, 'data': whois_data}
            scores.append(whois_score)

    final_score = score.calculate_final_risk(scores)
    
    return {
        'ioc': value,
        'type': ioc_type,
        'modules': results,
        'final_score': final_score
    }
