import requests
from dotenv import load_dotenv
import os

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def getabusedata(ip):
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