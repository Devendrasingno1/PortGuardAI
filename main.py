from banner import show_banner
from scanner import scan_target
from utils import create_required_folders, validate_port_range

from risk import get_risk_info
from cve_database import get_cve_info
from threat_intel import get_threat_intel, get_highest_threat_level, get_average_cvss
from score import calculate_security_score, get_risk_distribution
from attack_surface import identify_attack_surface
from advisor import generate_ai_advice
from report import save_csv_report, save_html_report
from logger import save_scan_log


def main():
    create_required_folders()
    show_banner()

    target = input("Enter Target IP/Hostname: ")
    start_port = int(input("Enter Start Port: "))
    end_port = int(input("Enter End Port: "))

    if not validate_port_range(start_port, end_port):
        print("Invalid port range. Please enter ports between 1 and 65535.")
        return

    scan_result = scan_target(target, start_port, end_port)

    if not scan_result["success"]:
        print(scan_result["error"])
        return

    for item in scan_result["open_ports"]:
        item["risk"] = get_risk_info(item["port"])
        item["cve"] = get_cve_info(item["port"])
        item["threat"] = get_threat_intel(item["port"])

    score_info = calculate_security_score(scan_result["open_ports"])
    risk_distribution = get_risk_distribution(scan_result["open_ports"])
    attack_surface = identify_attack_surface(scan_result["open_ports"])

    ai_advice = generate_ai_advice(
        scan_result["open_ports"],
        score_info,
        risk_distribution,
        attack_surface
    )

    highest_threat = get_highest_threat_level(scan_result["open_ports"])
    average_cvss = get_average_cvss(scan_result["open_ports"])

    csv_file = save_csv_report(
        scan_result,
        score_info,
        risk_distribution,
        attack_surface,
        ai_advice
    )

    html_file = save_html_report(
        scan_result,
        score_info,
        risk_distribution,
        attack_surface,
        ai_advice
    )

    log_file = save_scan_log(scan_result, score_info)

    print("\n" + "=" * 60)
    print("SCAN COMPLETED SUCCESSFULLY")
    print("=" * 60)
    print(f"Target             : {scan_result['target']}")
    print(f"IP Address         : {scan_result['ip']}")
    print(f"Security Score     : {score_info['score']}/100")
    print(f"Rating             : {score_info['rating']}")
    print(f"Overall Risk       : {score_info['overall_risk']}")
    print(f"Highest Threat     : {highest_threat}")
    print(f"Average CVSS       : {average_cvss}")
    print(f"Open Ports Found   : {len(scan_result['open_ports'])}")
    print(f"Scan Time          : {scan_result['scan_time']} seconds")
    print(f"CSV Report         : {csv_file}")
    print(f"HTML Report        : {html_file}")
    print(f"Log File           : {log_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()