from ui import menu_loop
import asyncio

banners = {}
open_ports = []
verbose = 0
semaphore = asyncio.Semaphore(500)


def view_last_scan():

    try:
        with open("scan_results.json", "r") as file:
            history = json.load(file)

    except FileNotFoundError:
        print("No scan history found.")
        return

    if len(history) == 0:
        print("No scans stored.")
        return

    last_scan = history[-1]

    print("\n=== Last Scan ===\n")

    print(f"Host: {last_scan['host']}")
    print(f"IP: {last_scan['ip']}")
    print(f"Open Ports: {last_scan['open_ports']}")
    print(f"Scan Time: {last_scan['scan_time']} sec")


def view_scan_history():

    try:
        with open("scan_results.json", "r") as file:
            history = json.load(file)

    except FileNotFoundError:
        print("No scan history found.")
        return

    if len(history) == 0:
        print("No scans stored.")
        return

    print("\n=== Scan History ===\n")

    for scan in history:

        print("-" * 40)
        print(f"Host: {scan['host']}")
        print(f"IP: {scan['ip']}")
        print(f"Open Ports: {scan['open_ports']}")
        print(f"Scan Time: {scan['scan_time']} sec")


def view_alerts():

    try:
        with open("alert_result.json", "r") as file:
            alerts = json.load(file)

    except FileNotFoundError:
        print("No alerts found.")
        return

    if len(alerts) == 0:
        print("No alerts generated.")
        return

    print("\n=== Alerts ===\n")

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        if "severity" in alert:

            print("-" * 40)
            print(f"Host: {alert['host']}")
            print(f"Severity: {alert['severity']}")
            print(f"Port: {alert['port']}")
            print(f"Service: {alert['service']}")
        elif "type" in alert:
            print("-" * 40)
            print(f"Host: {alert['host']}")
            print(f"Type: {alert['type']}")
            print(f"Port: {alert['port']}")


if __name__ == "__main__":
    menu_loop()
