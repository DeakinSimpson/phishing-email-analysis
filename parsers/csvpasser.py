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
            results.append({
                "subject": "",
                "body": row["Email Text"],
                "urls": [],
                "label": row["Email Type"]
            })
    return results
