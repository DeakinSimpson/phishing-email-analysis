import requests
import config

def scanurl(url):
    endpoint = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": config.VIRUSTOTAL_API_KEY
    }

    data = {"url": url}
    try:
        response = requests.post(endpoint, headers=headers, data=data)

        analysis_response = requests.get(response.json()["data"]["links"]["self"], headers=headers)

        # stats = {
        #     "malicious": analysis_response.json()["data"]["attributes"]["stats"]["malicious"],
        #     "suspicious": analysis_response.json()["data"]["attributes"]["stats"]["suspicious"]
        # }

        return analysis_response
    except:
        return None
    
    