def importcsv(path):
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
                    "sender":   row["sender"],
                    "receiver": row["receiver"],
                    "date":     row["date"],
                    "subject":  row["subject"],
                    "body":     row["body"],
                    "label":    row["label"],
                    "urls":     re.findall(r'(https?://[^\s]+)', row["body"])   # thgis uses regex to grab the URLs from the email and converts to array
                })
    except Exception as e:
        print(f"File {path} failed to open")
        return None
    
    return results
