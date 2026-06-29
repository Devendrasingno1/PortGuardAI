from datetime import datetime
from config import LOGS_DIR

LOG_FILE = f"{LOGS_DIR}/scan.log"


def save_scan_log(scan_result: dict, score_info: dict) -> str:
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write("=" * 60 + "\n")
        file.write(f"Date: {datetime.now().strftime('%d-%m-%Y %I:%M:%S %p')}\n")
        file.write(f"Target: {scan_result['target']}\n")
        file.write(f"IP: {scan_result['ip']}\n")
        file.write(f"Port Range: {scan_result['start_port']}-{scan_result['end_port']}\n")
        file.write(f"Open Ports: {len(scan_result['open_ports'])}\n")
        file.write(f"Security Score: {score_info['score']}/100\n")
        file.write(f"Overall Risk: {score_info['overall_risk']}\n\n")

        for item in scan_result["open_ports"]:
            risk = item.get("risk", {}).get("level", "N/A")
            file.write(f"Port {item['port']} | {item['service']} | Risk: {risk}\n")

        file.write("\n")

    return LOG_FILE