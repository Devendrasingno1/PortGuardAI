"""
Dashboard helper module for PortGuard AI.

This module generates reusable HTML dashboard components:
- Security score meter
- Risk distribution bars
- CVSS summary
- Threat level badge
"""


def get_score_color(score: int) -> str:
    if score >= 90:
        return "#22c55e"
    elif score >= 75:
        return "#84cc16"
    elif score >= 60:
        return "#eab308"
    elif score >= 40:
        return "#f97316"
    return "#ef4444"


def generate_score_meter(score_info: dict) -> str:
    score = score_info["score"]
    color = get_score_color(score)

    return f"""
    <div class="card">
        <h2>Security Score Meter</h2>
        <div class="meter-container">
            <div class="meter-fill" style="width: {score}%; background: {color};"></div>
        </div>
        <p><b>Score:</b> {score}/100</p>
        <p><b>Rating:</b> {score_info["rating"]}</p>
        <p><b>Overall Risk:</b> {score_info["overall_risk"]}</p>
    </div>
    """


def generate_risk_bars(risk_distribution: dict) -> str:
    total = sum(risk_distribution.values())
    if total == 0:
        total = 1

    colors = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#22c55e",
        "Info": "#38bdf8"
    }

    html = """
    <div class="card">
        <h2>Risk Distribution Dashboard</h2>
    """

    for risk, count in risk_distribution.items():
        percent = int((count / total) * 100)
        color = colors.get(risk, "#38bdf8")

        html += f"""
        <p><b>{risk}:</b> {count}</p>
        <div class="bar-container">
            <div class="bar-fill" style="width: {percent}%; background: {color};"></div>
        </div>
        """

    html += "</div>"
    return html


def generate_cvss_summary(open_ports: list[dict]) -> str:
    mapped_scores = []

    for item in open_ports:
        threat = item.get("threat", {})
        cvss = float(threat.get("cvss", 0.0))
        if cvss > 0:
            mapped_scores.append(cvss)

    if mapped_scores:
        avg_cvss = round(sum(mapped_scores) / len(mapped_scores), 2)
        max_cvss = max(mapped_scores)
    else:
        avg_cvss = 0.0
        max_cvss = 0.0

    return f"""
    <div class="card">
        <h2>CVSS Summary</h2>
        <p><b>Average CVSS:</b> {avg_cvss}</p>
        <p><b>Highest CVSS:</b> {max_cvss}</p>
        <p><b>Mapped Vulnerabilities:</b> {len(mapped_scores)}</p>
    </div>
    """