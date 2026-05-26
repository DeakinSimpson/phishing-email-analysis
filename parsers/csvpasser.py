def importcsv(path):
    import csv
    import sys
    # added maxsize as csv had a limit on numver of lines it could read
    csv.field_size_limit(sys.maxsize)
    results = []

    # import csv and return results
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        reader = csv.DictReader(file)
        for row in reader:
            # sender,receiver,date,subject,body,label,urls
            results.append({
                "sender":   row["sender"],
                "receiver": row["receiver"],
                "date":     row["date"],
                "subject":  row["subject"],
                "body":     row["body"],
                "label":    row["label"],
                "urls":     row["urls"]
            })
    return results
