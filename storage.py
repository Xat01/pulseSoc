import json


def save_monitor_result(host, port, alert_type):
    alert = {"host": host, "port": port, "type": alert_type}

    try:
        with open("alert_result.json", "r") as file:
            history = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):
        history = []

    history.append(alert)

    with open("alert_result.json", "w") as file:
        json.dump(history, file, indent=4)

    try:
        with open("scan_results.json", "r") as file:
            history = json.load(file)

    except FileNotFoundError:
        history = []
