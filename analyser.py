from enrichment import domainchecker, virustotal, ipinfochecker, abuseipdbchecker
from datetime import datetime
import hashlib
import json

def extractDataToJSON(url, date=datetime.now()):
    # call API's
    ip_info_json        = ipinfochecker.getipdetails(url)
    abuseipdb_json      = abuseipdbchecker.getabusedata(ip_info_json.ip).json()
    virustotal_json     = virustotal.scanurl(url)
    
    # extract the needed information about the URL
    age_of_domain           = domainchecker.getage(domainchecker.getdomaininfo(url), date)
    ip_addr                 = ip_info_json.ip
    org                     = ip_info_json.org
    abuse_confidence_score  = abuseipdb_json["data"]["abuseConfidenceScore"]
    is_tor                  = abuseipdb_json["data"]["isTor"]
    malicious_score         = virustotal_json["malicious"]
    suspicious_score        = virustotal_json["suspicious"]
    
    return None