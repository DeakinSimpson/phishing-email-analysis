import requests
from datetime import datetime
import traceback
from dotenv import load_dotenv
import os

load_dotenv()
APININJAS_API_KEY = os.getenv("APININJAS_API_KEY")

# parses urls and extracts the domain
def urlparse(url):
    domain = url.split("//")[-1].split("/")[0]
    return domain

# get the doimain info by using ninjaapi
def getdomaininfo(url):
    try:
        domain = urlparse(url)
        response = requests.get("https://api.api-ninjas.com/v1/whois",params={"domain": domain}, headers={"X-Api-Key": APININJAS_API_KEY})
        data = response.json()

        return data

    except Exception as e:
        print(e)
        return None

# input must be the dict that is returned by getdomaininfo() 
def getage(domaininfo, date=datetime.now(), print_exceptions=False):
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