import ipinfo
import config
  
# outputs a json of the details
def getipdetails(ip, show_exceptions=False):
    try:
        if ip is None:
            return None
        
        handler = ipinfo.getHandler(access_token=config.IPINFO_API_KEY)
        details = handler.getDetails(ip)
        return details
    except Exception as e:
        print(f"Unable to get IP details from ipinfo.io for: {ip}")
        if show_exceptions: print(e)
        return None