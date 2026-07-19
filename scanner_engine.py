import asyncio
import json
import time

from colorama import Fore
from scanner import (
    open_ports,
    banners,
    host_resolver,
    parse_ports,
    log,
    Producer,
    Worker,
    fingerprints,
)
from alert import gen_alert


async def run_scan(host, port_range, silent=False):

    queue = asyncio.Queue()

    global open_ports

    open_ports.clear()
    banners.clear()
    fingerprints.clear()

    if not silent:
        print(f"\n[*] Scanning {host}")

    ip = host_resolver(host)

    if ip is None:
        return

    if not silent:
        print("DEBUG HOST: ", host)
        print("DEBUG PORT_RANGE: ", port_range)

    start_port, end_port = parse_ports(port_range)

    if start_port is None:
        return

    start_time = time.time()

    log(f"[INFO] Starting scan on {host} ({ip})", level=1, color=Fore.CYAN)

    await Producer(queue, start_port, end_port)

    workers = []

    worker_count = 500

    for _ in range(worker_count):
        workers.append(asyncio.create_task(Worker(queue, ip, host)))

    await queue.join()

    for _ in range(worker_count):
        await queue.put(None)

    await asyncio.gather(*workers)

    scan_time = round(time.time() - start_time, 2)

    if not silent:
        print("\n===== Scan Complete =====")

        if open_ports:

            for port in sorted(open_ports):

                print(Fore.GREEN + f"[+] Port {port} is open")

                if port in banners:
                    print(Fore.MAGENTA + f"     Banner: {banners[port]}")

        else:
            print(Fore.RED + "No Open Ports Found.")

    result = {
        "host": host,
        "ip": ip,
        "open_ports": open_ports,
        "banners": banners,
        "services": fingerprints,
        "scan_time": scan_time,
    }

    alerts = gen_alert(result)

    if not silent:
        print("\nGenerated Alerts:")
        print(alerts)

    try:
        with open("scan_results.json", "r") as file:
            history = json.load(file)

    except FileNotFoundError:
        history = []

    history.append(result)

    with open("scan_results.json", "w") as file:
        json.dump(history, file, indent=4)

    try:
        with open("alert_result.json", "r") as file:
            alert_history = json.load(file)

    except FileNotFoundError:
        alert_history = []

    alert_history.extend(alerts)

    with open("alert_result.json", "w") as file:
        json.dump(alert_history, file, indent=4)

    if not silent:
        print("\n===== Summary =====")
        print(f"Host: {host}")
        print(f"IP: {ip}")
        print(f"Open Ports Found: {len(open_ports)}")
        print(f"Scan Completed In {scan_time} sec")

    return result
