import requests
import config

def getabusedata(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip
        # 'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': config.ABUSEIPDB_API_KEY
    }
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        
        return response
    except:
        print(f"Unable to get AbuseIPDB data for {ip}")

        return None