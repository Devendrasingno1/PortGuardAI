import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from config import DEFAULT_TIMEOUT, MAX_WORKERS
from services import get_service_name
from utils import resolve_target
from progress import show_progress
from banner_grabber import grab_service_banner, detect_technology


def scan_single_port(ip: str, port: int) -> Dict | None:
    """
    Scan a single TCP port and return service intelligence if open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result != 0:
            return None

        service = get_service_name(port)
        banner = grab_service_banner(ip, port)
        tech_info = detect_technology(banner, service)

        return {
            "port": port,
            "status": "OPEN",
            "service": service,
            "banner": tech_info["raw_banner"],
            "technology": tech_info["technology"],
            "os_guess": tech_info["os_guess"],
            "confidence": tech_info["confidence"]
        }

    except Exception:
        return None


def scan_target(target: str, start_port: int, end_port: int) -> Dict:
    """
    Scan a target host for open TCP ports.
    """
    ip = resolve_target(target)

    if ip is None:
        return {
            "success": False,
            "error": "Invalid hostname or IP address.",
            "target": target,
            "ip": None,
            "start_port": start_port,
            "end_port": end_port,
            "open_ports": [],
            "scan_time": 0,
            "total_ports_scanned": 0
        }

    total_ports = end_port - start_port + 1

    print(f"\nTarget   : {target}")
    print(f"IP       : {ip}")
    print(f"Range    : {start_port}-{end_port}")
    print("\nScanning started...\n")

    start_time = time.time()
    open_ports: List[Dict] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(scan_single_port, ip, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            completed += 1
            show_progress(completed, total_ports)

            result = future.result()

            if result:
                open_ports.append(result)

    end_time = time.time()
    scan_time = round(end_time - start_time, 2)

    open_ports.sort(key=lambda item: item["port"])

    print("\nOpen Ports:")
    for item in open_ports:
        print(
            f"[OPEN] Port {item['port']} - {item['service']} "
            f"| Tech: {item['technology']}"
        )

    return {
        "success": True,
        "error": None,
        "target": target,
        "ip": ip,
        "start_port": start_port,
        "end_port": end_port,
        "open_ports": open_ports,
        "scan_time": scan_time,
        "total_ports_scanned": total_ports
    }