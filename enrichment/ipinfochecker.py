import ipinfo
import config
from enrichment import domainchecker
import socket

# gets an ip address form a url
def getipaddress(url):
    domain = domainchecker.urlparse(url)
    try:
        ip = socket.gethostbyname(domain)
    except:
        print(f"unable to get ip address from domain: {domain}")
    return ip

# outputs a json of the details
def getipdetails(url, show_exceptions=False):
    try:
        handler = ipinfo.getHandler(access_token=config.IPINFO_API_KEY)
        details = handler.getDetails(getipaddress(url))
        return details
    except Exception as e:
        print(f"Unable to get IP details from ipinfo.io for: {getipaddress(url)}")
        if show_exceptions: print(e)
        return None