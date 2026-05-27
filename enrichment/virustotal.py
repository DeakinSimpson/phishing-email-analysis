import requests
import config
import time

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

        while True:
            analysis_response = requests.get(response.json()["data"]["links"]["self"], headers=headers)
            result = analysis_response.json()
            if result["data"]["attributes"]["status"] == "completed":
                return analysis_response
            time.sleep(3)
    except:
        return None
    
    