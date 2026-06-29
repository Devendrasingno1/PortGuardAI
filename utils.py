import os
import socket
from config import REPORTS_DIR, LOGS_DIR


def create_required_folders() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)


def resolve_target(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def validate_port_range(start_port: int, end_port: int) -> bool:
    return 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port