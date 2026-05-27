import analyser
from enrichment import domainchecker, virustotal, ipinfochecker, abuseipdbchecker
from parsers import csvpasser
import socket
import analyser

path = "phishing-email-analysis/data/CEAS_08.csv"
date = "2008-01-01"

result = csvpasser.importcsv(path)
testurl = result[4]["urls"][0]

analysis_google = analyser.analyseData("www.google.com", date)
# analysis_bad = analyser.analyseData(testurl, date)
