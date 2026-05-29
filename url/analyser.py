from url import url_enrichment
from datetime import datetime
import hashlib
import cachemethods
import config

def extractDataToJSON(email_body, url, file_path, data_index, date=datetime.now()):
    domain          = url_enrichment.urlparse(url)
    cache           = cachemethods.load_cache(config.URL_CACHE_PATH)
    email_cache     = cachemethods.load_cache(config.EMAIL_CACHE_PATH)
    email_body_hash = hashlib.md5(email_body.encode()).hexdigest()

    if domain not in cache:
        ip_info_json    = url_enrichment.ipinfo_scan(url, config.IPINFO_API_KEY)
        domain_info     = url_enrichment.whois_apininja_scan(url, config.APININJAS_API_KEY)
        if ip_info_json is None:
            ip_info_json    = {"Could Not Resolve Domain": "Could Not Resolve Domain"}
            abuseipdb_json  = {"Could Not Resolve Domain": "Could Not Resolve Domain"}
        else:
            abuseipdb_json  = url_enrichment.abuseipdb_scan(ip_info_json.ip, config.ABUSEIPDB_API_KEY).json()
            ip_info_json    = ip_info_json.all
        domain_age = url_enrichment.get_domain_age(domain_info, date)

        cache[domain] = {
            "ipinfo":       ip_info_json,
            "whois":        domain_info,
            "abuseipdb":    abuseipdb_json,
            "domain_age":   domain_age,
            "urls": {}
        }
    
    if url not in cache[domain]["urls"]:
        virustotal_json = url_enrichment.virus_total_scan(url, config.VIRUSTOTAL_API_KEY).json()
        cache[domain]["urls"][url] = {
            "virustotal": virustotal_json
        }

    if email_body_hash not in email_cache:
        email_cache[email_body_hash] = {
            "path":     file_path,
            "index":    data_index,
            "urls":     []
        }

    if url not in email_cache[email_body_hash]["urls"]:
        email_cache[email_body_hash]["urls"].append(url)
    
    cachemethods.save_cache(config.URL_CACHE_PATH, cache)
    cachemethods.save_cache(config.EMAIL_CACHE_PATH, email_cache)