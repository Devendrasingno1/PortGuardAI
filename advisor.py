def generate_ai_advice(
    open_ports: list[dict],
    score_info: dict,
    risk_distribution: dict,
    attack_surface: list[str]
) -> dict:

    score = score_info["score"]
    overall_risk = score_info["overall_risk"]

    if risk_distribution["Critical"] > 0:
        analysis = "Critical exposure detected. Immediate security review is required."
    elif risk_distribution["High"] > 0:
        analysis = "High-risk services are exposed. Access control and patching should be reviewed."
    elif risk_distribution["Medium"] > 0:
        analysis = "Medium-risk services are exposed. Review whether these services are necessary."
    elif risk_distribution["Low"] > 0:
        analysis = "Only low-risk services were detected. Exposure appears limited."
    else:
        analysis = "No open ports were detected in the scanned range."

    recommendations = [
        "Close unnecessary open ports.",
        "Restrict administrative services using firewall rules.",
        "Keep exposed services updated and patched.",
        "Perform regular scans to detect new exposed services."
    ]

    for item in open_ports:
        port = item["port"]

        if port == 80:
            recommendations.append("Redirect HTTP traffic to HTTPS.")
        elif port == 22:
            recommendations.append("Use SSH keys and disable password-based login.")
        elif port == 445:
            recommendations.append("Restrict SMB access and disable SMBv1.")
        elif port == 3389:
            recommendations.append("Place RDP behind VPN and enable MFA.")
        elif port == 3306:
            recommendations.append("Do not expose MySQL directly to untrusted networks.")

    return {
        "analysis": analysis,
        "score": score,
        "overall_risk": overall_risk,
        "attack_surface": attack_surface,
        "recommendations": list(dict.fromkeys(recommendations))
    }