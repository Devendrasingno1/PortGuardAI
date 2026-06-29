RISK_PENALTY = {
    "Critical": 30,
    "High": 20,
    "Medium": 10,
    "Low": 3,
    "Info": 1
}


def calculate_security_score(open_ports: list[dict]) -> dict:
    score = 100

    for item in open_ports:
        risk_level = item["risk"]["level"]
        score -= RISK_PENALTY.get(risk_level, 1)

    score = max(score, 0)

    if score >= 90:
        rating = "Excellent"
        overall_risk = "Low"
    elif score >= 75:
        rating = "Good"
        overall_risk = "Low"
    elif score >= 60:
        rating = "Moderate"
        overall_risk = "Medium"
    elif score >= 40:
        rating = "Poor"
        overall_risk = "High"
    else:
        rating = "Critical"
        overall_risk = "Critical"

    return {
        "score": score,
        "rating": rating,
        "overall_risk": overall_risk
    }


def get_risk_distribution(open_ports: list[dict]) -> dict:
    distribution = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for item in open_ports:
        level = item["risk"]["level"]
        distribution[level] = distribution.get(level, 0) + 1

    return distribution