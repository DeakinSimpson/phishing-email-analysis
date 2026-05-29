from dotenv import load_dotenv
import os

load_dotenv()
URL_CACHE_PATH      = os.getenv("URL_CACHE_PATH")
EMAIL_CACHE_PATH    = os.getenv("EMAIL_CACHE_PATH")
VIRUSTOTAL_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
IPINFO_API_KEY      = os.getenv("IPINFO_API_KEY")
APININJAS_API_KEY   = os.getenv("APININJAS_API_KEY")
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY")