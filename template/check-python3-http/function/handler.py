from index import notify

def handle(event, context):
    target = event.json["VULCAN_CHECK_TARGET"]

    if "666" in target:
        event.notes = "Found vulnerability"
        event.vulnerabilities.append({
                "description": "Example vulnerability check",
                "id": "",
                "score": 0,
                "summary": "Found vulnerability"
            })

    return {
        "statusCode": 200,
        "body": "Processed: " + target
    }
