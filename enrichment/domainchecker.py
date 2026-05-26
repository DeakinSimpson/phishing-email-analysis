import requests
import config
from datetime import datetime

# parses urls and extracts the domain
def urlparse(url):
    domain = url.split("//")[-1].split("/")[0]
    return domain

# get the doimain info by using ninjaapi
def getdomaininfo(url):
    try:
        domain = urlparse(url)
        response = requests.get("https://api.api-ninjas.com/v1/whois",params={"domain": domain}, headers={"X-Api-Key": config.APININJAS_API_KEY})
        data = response.json()

        return {
            "registrar": data.get("registrar"),
            "creation_date": data.get("creation_date"),
            "expiration_date": data.get("expiration_date")
        }

    except Exception as e:
        print(e)
        return None

# input must be the dict that is returned by getdomaininfo() 
def getage(domaininfo, date=datetime.now()):
    if isinstance(date, str):
        date = datetime.fromisoformat(date)
    
    creation = datetime.fromtimestamp(domaininfo["creation_date"])
    age = (date - creation).days

    return age