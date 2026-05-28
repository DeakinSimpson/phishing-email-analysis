from enrichment import domainchecker, virustotal, ipinfochecker, abuseipdbchecker
from datetime import datetime
import hashlib
from dotenv import load_dotenv
import os
import cachemethods

load_dotenv()
URL_CACHE_PATH      = os.getenv("URL_CACHE_PATH")
EMAIL_CACHE_PATH    = os.getenv("EMAIL_CACHE_PATH")

def extractDataToJSON(email_body, url, file_path, data_index, date=datetime.now()):
    domain = domainchecker.urlparse(url)
    cache = cachemethods.load_cache(URL_CACHE_PATH)
    email_cache = cachemethods.load_cache(EMAIL_CACHE_PATH)
    email_body_hash = hashlib.md5(email_body.encode()).hexdigest()

    # check for domain
    if domain not in cache:
        # call API's
        ip_info_json    = ipinfochecker.getipdetails(url)
        domain_info     = domainchecker.getdomaininfo(url)
        if ip_info_json is None:
            ip_info_json    = {"Could Not Resolve Domain": "Could Not Resolve Domain"}
            abuseipdb_json  = {"Could Not Resolve Domain": "Could Not Resolve Domain"}
        else:
            abuseipdb_json  = abuseipdbchecker.getabusedata(ip_info_json.ip).json()
            ip_info_json = ip_info_json.all
        domain_age      = domainchecker.getage(domain_info, date)

        # create json for this domain
        cache[domain] = {
            "ipinfo": ip_info_json,
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

    if email_body_hash not in email_cache:
        email_cache[email_body_hash] = {
            "path": file_path,
            "index": data_index,
            "urls": []
        }

    if url not in email_cache[email_body_hash]["urls"]:
        email_cache[email_body_hash]["urls"].append(url)
    
    cachemethods.save_cache(URL_CACHE_PATH, cache)
    cachemethods.save_cache(EMAIL_CACHE_PATH, email_cache)