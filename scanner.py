import socket
import argparse
from colorama import Fore, Style, init
import asyncio
import time

verbose = 0
open_ports = []
banners = {}
semaphore = asyncio.Semaphore(500)

init(autoreset=True)


def compare_port(old_port, new_ports):
    old_set = set(old_port)
    new_set = set(new_ports)

    opened_ports = new_set - old_set
    closed_ports = old_set - new_set

    return opened_ports, closed_ports


def log(msg, level=1, color=Fore.WHITE):
    if verbose >= level:
        print(color + msg + Style.RESET_ALL)


def host_resolver(host):

    try:
        return socket.gethostbyname(host)

    except socket.gaierror:
        print("Invalid or Unknown Hostname.")
        return None


def parse_ports(port_range):
    try:
        start_port, end_port = port_range.split("-")
        start_port = int(start_port)
        end_port = int(end_port)

        if start_port < 0 or end_port > 65535:
            print("Ports must be between 0 and 65535.")
            exit()

        if start_port > end_port:
            print("Invalid Port Range.")
            exit()
        return start_port, end_port

    except ValueError:
        print("Invalid Port Range Format." + Fore.RED)
        exit()


async def scan_port(ip, port):
    try:
        async with semaphore:

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1
            )

            writer.close()

            await writer.wait_closed()
            return port

    except asyncio.TimeoutError:
        log(f"Debug: timeout at port{port}", level=3, color=Fore.RED)
    except ConnectionRefusedError:
        return None
    except OSError:
        return None


async def banner_grabbing(host, port):
    try:
        if port == 443:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=True), timeout=2
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2
            )

        if port in (80, 443, 8080):
            request = f"HEAD / HTTP/1.1 \r\n" f"Host: {host}\r\n" f"\r\n"
            writer.write(request.encode())
            await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=2)

        writer.close()
        return data.decode(errors="ignore").strip()
    except Exception as e:
        return f"Banner Grabbing failed: {e}"


async def Producer(queue, start_port, end_port):
    for port in range(start_port, end_port + 1):
        await queue.put(port)


async def Worker(queue, ip, host):
    while True:
        try:
            port = await queue.get()

            if port is None:
                queue.task_done()
                break
            log(f"Trying Port {port}", level=2, color=Fore.LIGHTCYAN_EX)

            result = await scan_port(ip, port)
            if result is not None:
                open_ports.append(result)
                log(f"[OPEN] Port {port} is open", level=1, color=Fore.GREEN)

                service_banner = await banner_grabbing(host, port)
                banner_lines = service_banner.splitlines()
                short_banner = banner_lines[0] if banner_lines else "No banner"
                banners[port] = short_banner

                log(f"      Banner: {short_banner}", level=1, color=Fore.MAGENTA)
            queue.task_done()

        except Exception as e:
            print("Worker crashed", e)
            queue.task_done()
            return
