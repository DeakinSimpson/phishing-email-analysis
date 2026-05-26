import analyser
from enrichment import domainchecker, virustotal
from parsers import csvpasser

path = "phishing-email-analysis/data/CEAS_08.csv"
date = "2008-01-01"

result = csvpasser.importcsv(path)
testurl = result[4]["urls"][0]

# print(domainchecker.getage(domainchecker.getdomaininfo(testurl), date))
print(virustotal.scanurl("https://www.google.com"))
