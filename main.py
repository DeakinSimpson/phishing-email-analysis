import analyser
from parsers import csvpasser

path = "phishing-email-analysis/data/CEAS_08.csv"

result = csvpasser.importcsv(path)

print(result[4]["urls"])