import analyser
from enrichment import domainchecker
from parsers import csvpasser

path = "phishing-email-analysis/data/CEAS_08.csv"

result = csvpasser.importcsv(path)
testurl = result[4]["urls"][0]
# print(testurl)

print(domainchecker.getdomaininfo(testurl))
