import csv
from datetime import datetime

from config import REPORTS_DIR
from dashboard import (
    generate_score_meter,
    generate_risk_bars,
    generate_cvss_summary
)


def save_csv_report(scan_result, score_info, risk_distribution, attack_surface, ai_advice):
    filename = f"{REPORTS_DIR}/scan_report.csv"

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Port", "Status", "Service", "Technology", "OS Guess", "Confidence",
            "Banner", "Risk", "MITRE", "CVE", "CVE Severity", "CVSS",
            "Threat Level", "Known Exploit", "Attack Type", "Known Malware",
            "Exploit Available", "Priority", "Recommendation"
        ])

        for item in scan_result["open_ports"]:
            threat = item.get("threat", {})

            writer.writerow([
                item["port"],
                item["status"],
                item["service"],
                item.get("technology", "Unknown"),
                item.get("os_guess", "Unknown"),
                item.get("confidence", 0),
                item.get("banner", "No banner detected"),
                item["risk"]["level"],
                item["risk"]["mitre"],
                item["cve"]["id"],
                item["cve"]["severity"],
                threat.get("cvss", 0.0),
                threat.get("threat_level", "Info"),
                threat.get("known_exploit", "N/A"),
                threat.get("attack_type", "N/A"),
                ", ".join(threat.get("known_malware", [])),
                threat.get("exploit_available", "Unknown"),
                threat.get("priority", "Review"),
                item["risk"]["recommendation"]
            ])

    return filename


def save_html_report(scan_result, score_info, risk_distribution, attack_surface, ai_advice):
    filename = f"{REPORTS_DIR}/scan_report.html"
    generated_on = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")

    port_rows = ""
    threat_rows = ""
    banner_rows = ""

    for item in scan_result["open_ports"]:
        risk_level = item["risk"]["level"]
        threat = item.get("threat", {})
        malware = ", ".join(threat.get("known_malware", [])) or "None mapped"

        port_rows += f"""
        <tr>
            <td>{item["port"]}</td>
            <td>{item["status"]}</td>
            <td>{item["service"]}</td>
            <td class="{risk_level}">{risk_level}</td>
            <td>{item["risk"]["mitre"]}</td>
            <td>{item["cve"]["id"]}</td>
            <td>{item["cve"]["severity"]}</td>
            <td>{item["risk"]["recommendation"]}</td>
        </tr>
        """

        threat_rows += f"""
        <tr>
            <td>{item["port"]}</td>
            <td>{item["service"]}</td>
            <td class="{threat.get("threat_level", "Info")}">{threat.get("threat_level", "Info")}</td>
            <td>{threat.get("cvss", 0.0)}</td>
            <td>{threat.get("known_exploit", "N/A")}</td>
            <td>{threat.get("attack_type", "N/A")}</td>
            <td>{malware}</td>
            <td>{threat.get("exploit_available", "Unknown")}</td>
            <td>{threat.get("priority", "Review")}</td>
        </tr>
        """

        banner_rows += f"""
        <tr>
            <td>{item["port"]}</td>
            <td>{item["service"]}</td>
            <td>{item.get("technology", "Unknown")}</td>
            <td>{item.get("os_guess", "Unknown")}</td>
            <td>{item.get("confidence", 0)}%</td>
            <td><pre>{item.get("banner", "No banner detected")}</pre></td>
        </tr>
        """

    recommendations = ""
    for rec in ai_advice["recommendations"]:
        recommendations += f"<li>{rec}</li>"

    score_meter = generate_score_meter(score_info)
    risk_bars = generate_risk_bars(risk_distribution)
    cvss_summary = generate_cvss_summary(scan_result["open_ports"])

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PortGuard AI Security Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #e5e7eb;
            padding: 30px;
        }}

        h1 {{
            color: #22c55e;
            margin-bottom: 5px;
        }}

        h2 {{
            color: #38bdf8;
        }}

        .subtitle {{
            color: #94a3b8;
            margin-bottom: 30px;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }}

        .metric {{
            background: #020617;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 18px;
            text-align: center;
        }}

        .metric h3 {{
            margin: 0;
            font-size: 28px;
            color: #22c55e;
        }}

        .metric p {{
            margin: 5px 0 0;
            color: #94a3b8;
        }}

        .card {{
            background: #111827;
            border: 1px solid #374151;
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: #111827;
            margin-top: 15px;
        }}

        th, td {{
            border: 1px solid #374151;
            padding: 12px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #1f2937;
            color: #22c55e;
        }}

        pre {{
            white-space: pre-wrap;
            word-break: break-word;
            color: #cbd5e1;
            font-size: 12px;
            margin: 0;
        }}

        .meter-container {{
            width: 100%;
            height: 22px;
            background: #020617;
            border: 1px solid #334155;
            border-radius: 30px;
            overflow: hidden;
            margin: 15px 0;
        }}

        .meter-fill {{
            height: 100%;
            border-radius: 30px;
        }}

        .bar-container {{
            width: 100%;
            height: 14px;
            background: #020617;
            border-radius: 20px;
            overflow: hidden;
            border: 1px solid #334155;
            margin-bottom: 12px;
        }}

        .bar-fill {{
            height: 100%;
            border-radius: 20px;
        }}

        .Critical {{
            color: #ef4444;
            font-weight: bold;
        }}

        .High {{
            color: #f97316;
            font-weight: bold;
        }}

        .Medium {{
            color: #eab308;
            font-weight: bold;
        }}

        .Low {{
            color: #22c55e;
            font-weight: bold;
        }}

        .Info {{
            color: #38bdf8;
            font-weight: bold;
        }}

        .footer {{
            margin-top: 30px;
            color: #94a3b8;
            font-size: 13px;
        }}
    </style>
</head>

<body>

<h1>PortGuard AI Security Report</h1>
<p class="subtitle">Enterprise Network Exposure & Threat Intelligence Platform</p>

<div class="grid">
    <div class="metric">
        <h3>{score_info["score"]}/100</h3>
        <p>Security Score</p>
    </div>

    <div class="metric">
        <h3>{score_info["rating"]}</h3>
        <p>Rating</p>
    </div>

    <div class="metric">
        <h3>{score_info["overall_risk"]}</h3>
        <p>Overall Risk</p>
    </div>

    <div class="metric">
        <h3>{len(scan_result["open_ports"])}</h3>
        <p>Open Ports</p>
    </div>
</div>

{score_meter}

{risk_bars}

{cvss_summary}

<div class="card">
    <h2>Security Overview</h2>
    <p><b>Target:</b> {scan_result["target"]}</p>
    <p><b>IP Address:</b> {scan_result["ip"]}</p>
    <p><b>Total Ports Scanned:</b> {scan_result["total_ports_scanned"]}</p>
    <p><b>Scan Time:</b> {scan_result["scan_time"]} seconds</p>
    <p><b>Generated On:</b> {generated_on}</p>
</div>

<div class="card">
    <h2>Executive Summary</h2>
    <p>
        This scan identified <b>{len(scan_result["open_ports"])}</b>
        exposed service(s) on <b>{scan_result["target"]}</b>.
        The security score is <b>{score_info["score"]}/100</b>
        with an overall risk rating of <b>{score_info["overall_risk"]}</b>.
    </p>
    <p><b>Attack Surface:</b> {", ".join(attack_surface)}</p>
</div>

<div class="card">
    <h2>AI Security Assessment</h2>
    <p>{ai_advice["analysis"]}</p>

    <h3>Recommendations</h3>
    <ul>
        {recommendations}
    </ul>
</div>

<div class="card">
    <h2>Banner Intelligence</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Technology</th>
            <th>OS Guess</th>
            <th>Confidence</th>
            <th>Raw Banner</th>
        </tr>
        {banner_rows}
    </table>
</div>

<div class="card">
    <h2>Threat Intelligence</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Threat Level</th>
            <th>CVSS</th>
            <th>Known Exploit</th>
            <th>Attack Type</th>
            <th>Known Malware</th>
            <th>Exploit Available</th>
            <th>Priority</th>
        </tr>
        {threat_rows}
    </table>
</div>

<div class="card">
    <h2>Open Port Analysis</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Status</th>
            <th>Service</th>
            <th>Risk</th>
            <th>MITRE</th>
            <th>CVE</th>
            <th>CVE Severity</th>
            <th>Recommendation</th>
        </tr>
        {port_rows}
    </table>
</div>

<p class="footer">
    Report generated by PortGuard AI v6.2 | Developed by Devendra Rajput
</p>

</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html)

    return filename