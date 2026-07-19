import asyncio
import json

from Monitor import monitor_scan
from scanner_engine import run_scan

print("UI start")


def banner():

    print(r"""
██████╗ ██╗   ██╗██╗     ███████╗███████╗
██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██████╔╝██║   ██║██║     ███████╗█████╗
██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝
██║     ╚██████╔╝███████╗███████║███████╗
╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝

          Security Operations Center
          
         """)


def menu():

    print("""
        =================================================
 [01] Start Scan
 [02] Start Monitoring
 [03] View Last Scan
 [04] View Scan History
 [05] View Alerts
 [06] Asset Inventory
 [07] 

 [00] Exit#
=================================================
""")


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

    if "fingerprints" in last_scan:
        print("\n === Service Intelligence ===")

        for fing in last_scan:
            display_fingerprint(fing)

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


def menu_loop():

    while True:

        banner()
        menu()

        choice = input("PulseSOC > ")

        if choice == "1":
            host = input("Target Host: ")
            port_range = input("Port Range (eg:- 1-1000): ")
            asyncio.run(run_scan(host, port_range))

        elif choice == "2":
            host = input("Target Host: ")
            port_range = input("Port Range (eg:1-1000): ")
            asyncio.run(monitor_scan(host, port_range, 10))

        elif choice == "3":
            view_last_scan()

        elif choice == "4":
            view_scan_history()

        elif choice == "5":
            view_alerts()

        elif choice == "0":
            break

        input("\nPress Enter...")


def display_fingerprint(fingerprint):
    print("-" * 45)
    print(f"Port     : {fingerprint['port']}")
    print(f"Service  : {fingerprint['service']}")
    print(f"Vendor   : {fingerprint['vendor']}")
    print(f"Version  : {fingerprint['version']}")
    print("-" * 45)
    print()
    protocol = fingerprint.get("protocol")

    if protocol:
        print("\n Protocol Interlligence")
        print("-" * 45)

        for key, value in protocol.items():
            print(f"{key:<15}:{value}")

        print("-" * 45)


print("UI finished loading")
