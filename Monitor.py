import json
import asyncio
from scanner_engine import run_scan
from scanner import compare_port
from storage import save_monitor_result
from datetime import datetime


async def monitor_scan(host, port_range, interval):

    previous_scan = await run_scan(host, port_range, silent=True)
    while True:
        await asyncio.sleep(interval)

        current_scan = await run_scan(host, port_range, silent=True)
        print("\n DEBUG!")
        print("Previous ", previous_scan["open_ports"])
        print("Current ", current_scan["open_ports"])

        opened_ports, closed_ports = compare_port(
            previous_scan["open_ports"], current_scan["open_ports"]
        )

        timestamp = datetime.now().strftime("%H:%M:%S")

        for port in opened_ports:
            print(f"[ALERT] New port opened: {port}")
            save_monitor_result(host, port, "PORT_OPENED")
        for port in closed_ports:
            print(f"[{timestamp}] Port Closed! {port}")
            save_monitor_result(host, port, "PORT_CLOSED")

        previous_scan = current_scan
