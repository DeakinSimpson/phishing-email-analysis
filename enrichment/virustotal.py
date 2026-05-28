import requests
import time
from dotenv import load_dotenv
import os

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def scanurl(url):
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
    
    