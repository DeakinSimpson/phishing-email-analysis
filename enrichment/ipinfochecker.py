import ipinfo
import config
from enrichment import domainchecker
import socket

# gets an ip address form a url
def getipaddress(url):
    domain = domainchecker.urlparse(url)
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        print(f"unable to get ip address from domain: {domain}")
        return None
    

# outputs a json of the details
def getipdetails(url, show_exceptions=False):
    try:
        ip = getipaddress(url)
        if ip is None:
            return None
        
        handler = ipinfo.getHandler(access_token=config.IPINFO_API_KEY)
        details = handler.getDetails(ip)
        return details
    except Exception as e:
        print(f"Unable to get IP details from ipinfo.io for: {getipaddress(url)}")
        if show_exceptions: print(e)
        return None