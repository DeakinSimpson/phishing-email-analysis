def importcsv_pecp(path="phishing-email-analysis/data/Phishing_Email.csv"):
    import csv
    import sys
    import re
    # added maxsize as csv had a limit on numver of lines it could read
    csv.field_size_limit(sys.maxsize)
    results = []

    # import csv and return results
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            reader = csv.DictReader(file)
            for row in reader:
                # converts each row into its own dicts
                results.append({
                    "body":     row["Email Text"],
                    "type":     0 if (row["Email Type"] == "Safe Email") else 1,
                    "urls":     re.findall(r'(https?://[^\s]+)', row["Email Text"])   # thgis uses regex to grab the URLs from the email and converts to array
                })
    except Exception as e:
        print(f"File {path} failed to open")
        return None
    
    return results

def importcsv_ceas(path="phishing-email-analysis/data/CEAS_08.csv"):
    import csv
    import sys
    import re
    # added maxsize as csv had a limit on numver of lines it could read
    csv.field_size_limit(sys.maxsize)
    results = []

    # import csv and return results
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            reader = csv.DictReader(file)
            for row in reader:
                # converts each row into its own dicts
                results.append({
                    "body":     row["body"],
                    "type":     row["label"],
                    "urls":     re.findall(r'(https?://[^\s]+)', row["body"])   # thgis uses regex to grab the URLs from the email and converts to array
                })
    except Exception as e:
        print(f"File {path} failed to open")
        return None
    
    return results

def importcsv_df(path="phishing-email-analysis/data/df.csv"):
    import csv
    import sys
    import re
    # added maxsize as csv had a limit on numver of lines it could read
    csv.field_size_limit(sys.maxsize)
    results = []

    # import csv and return results
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            reader = csv.DictReader(file)

            for row in reader:
                # converts each row into its own dicts
                if str(row["label"]) != "2":
                    results.append({
                        "body":     row["text"],
                        "type":     row["label"],
                        "urls":     re.findall(r'(https?://[^\s]+)', row["text"])   # thgis uses regex to grab the URLs from the email and converts to array
                    })
    except Exception as e:
        print(f"File {path} failed to open")
        return None
    
    return results

def import_csv_data(path):
    if path == "phishing-email-analysis/data/Phishing_Email.csv":   return importcsv_pecp(path)
    if path == "phishing-email-analysis/data/CEAS_08.csv":          return importcsv_ceas(path)
    if path == "phishing-email-analysis/data/df.csv":               return importcsv_df(path)
    return None