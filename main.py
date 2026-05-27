import analyser
from parsers import csvpasser
import analyser

path = "phishing-email-analysis/data/CEAS_08.csv"
date = "2008-01-01"

result = csvpasser.importcsv(path)
# print(result[0])
for curr_index in range(100):
    line    = result[curr_index]
    if not line["urls"]: 
        continue
    url     = line["urls"][0]
    body    = line["body"]

    analyser.extractDataToJSON(body, url, path, curr_index, date)