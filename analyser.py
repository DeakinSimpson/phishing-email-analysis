from enrichment import domainchecker, virustotal, ipinfochecker, abuseipdbchecker
from datetime import datetime
import json
import os

def load_cache(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    else: return {}

def save_cache(filepath, cache):
    with open(filepath, "w") as f:
        json.dump(cache, f, indent=4)

def extractDataToJSON(url, date=datetime.now()):
    cache_path = "phishing-email-analysis/cache/url_cache.json"
    domain = domainchecker.urlparse(url)
    cache = load_cache(cache_path)

    # check for domain
    if domain not in cache:
        # call API's
        ip_info_json    = ipinfochecker.getipdetails(url)
        domain_info     = domainchecker.getdomaininfo(url)
        abuseipdb_json  = abuseipdbchecker.getabusedata(ip_info_json.ip).json()
        domain_age      = domainchecker.getage(domain_info, date)

        # create json for this domain
        cache[domain] = {
            "ipinfo": ip_info_json.all,
            "whois": domain_info,
            "abuseipdb": abuseipdb_json,
            "domain_age": domain_age,
            "urls": {}
        }
    
    # checks if the url is within the domain json, if not it scans it usin virustotal then adds it
    if url not in cache[domain]["urls"]:
        virustotal_json = virustotal.scanurl(url).json()
        cache[domain]["urls"][url] = {
            "virustotal": virustotal_json
        }
    
    save_cache(cache_path, cache)