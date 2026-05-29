import requests
import time
import ipinfo
from datetime import datetime
import traceback

# this uses virustotal to scan the URL, outputs a JSON
def virus_total_scan(url, VIRUSTOTAL_API_KEY):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    data = {"url": url}
    try:
        response        = requests.post(endpoint, headers=headers, data=data)
        analysis_url    = response.json()["data"]["links"]["self"]

        while True:
            analysis_response = requests.get(analysis_url, headers=headers)
            result = analysis_response.json()
            if result["data"]["attributes"]["status"] == "completed":
                return analysis_response
            time.sleep(3)
    except:
        return None

# uses ipinfo.io to scan IP, outputs a json of the details
def ipinfo_scan(ip, IPINFO_API_KEY, show_exceptions=False):
    try:
        if ip is None:
            return None
        
        handler = ipinfo.getHandler(access_token=IPINFO_API_KEY)
        details = handler.getDetails(ip)
        return details
    except Exception as e:
        print(f"Unable to get IP details from ipinfo.io for: {ip}")
        if show_exceptions: print(e)
        return None

# parses urls and extracts the domain
def urlparse(url):
    domain = url.split("//")[-1].split("/")[0]
    return domain
    
# get the whois by using ninjaapi, outputs a json about the domain
def whois_apininja_scan(url, APININJAS_API_KEY):
    try:
        domain = urlparse(url)
        response = requests.get("https://api.api-ninjas.com/v1/whois",params={"domain": domain}, headers={"X-Api-Key": APININJAS_API_KEY})
        data = response.json()

        return data

    except Exception as e:
        print(e)
        return None
    
# input must be the dict that is returned by getdomaininfo() 
def get_domain_age(domaininfo, date=datetime.now(), print_exceptions=False):
    try:
        data = {
            "registrar": domaininfo.get("registrar"),
            "creation_date": domaininfo.get("creation_date"),
            "expiration_date": domaininfo.get("expiration_date")
        }
        # if a string is inputted convert it to a datetime format
        if isinstance(date, str):
            date = datetime.fromisoformat(date)
        
        creation_date = data["creation_date"]
        expiration_date = data["expiration_date"]

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        creation = datetime.fromtimestamp(creation_date)
        expiration = datetime.fromtimestamp(expiration_date)

        agetoexpiry = (expiration - creation).days
        agefromnow = (date - creation).days

        if agefromnow < agetoexpiry:
            return agefromnow
        else:
            return agetoexpiry
    except:
        print(f"Unable to get domain age information for {data["registrar"]}")
        if print_exceptions: print(traceback.format_exc())
        return None

# gets information about the IP using AbuseIPDB, outputs it to a .json file
def abuseipdb_scan(ip, ABUSEIPDB_API_KEY):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip
        # 'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        
        return response
    except:
        print(f"Unable to get AbuseIPDB data for {ip}")

        return None