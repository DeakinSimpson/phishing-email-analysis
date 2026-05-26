import analyser
from parsers import csvpasser

path = "phishing-email-analysis/data/Phishing_Email.csv"

result = csvpasser.importcsv(path)

print(result[0]["subject"])