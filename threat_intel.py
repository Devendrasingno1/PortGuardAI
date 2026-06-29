"""
Threat Intelligence Engine for PortGuard AI v6.1

This module maps open ports and services to:
- Threat level
- CVSS score
- Known exploit
- Attack type
- Known malware
- Exploit availability
- Remediation priority
- Threat summary
- Confidence score
"""


THREAT_INTEL_DATABASE = {
    21: {
        "threat_level": "High",
        "cvss": 8.1,
        "known_exploit": "FTP Remote Exploitation",
        "attack_type": "Credential Theft / Remote Access",
        "known_malware": ["Credential Stealers", "Brute-force Bots"],
        "exploit_available": "Yes",
        "priority": "High",
        "confidence": 85,
        "summary": "FTP services may expose credentials because traditional FTP does not encrypt authentication traffic."
    },

    22: {
        "threat_level": "Medium",
        "cvss": 6.5,
        "known_exploit": "SSH Brute Force",
        "attack_type": "Unauthorized Remote Access",
        "known_malware": ["Botnets", "Credential Stuffing Tools"],
        "exploit_available": "Yes",
        "priority": "Medium",
        "confidence": 80,
        "summary": "SSH is commonly used for remote administration and should be restricted to trusted IP addresses."
    },

    23: {
        "threat_level": "High",
        "cvss": 8.6,
        "known_exploit": "Telnet Credential Interception",
        "attack_type": "Plaintext Credential Exposure",
        "known_malware": ["Mirai Botnet", "IoT Botnets"],
        "exploit_available": "Yes",
        "priority": "High",
        "confidence": 90,
        "summary": "Telnet is insecure because it transmits credentials and commands in plaintext."
    },

    25: {
        "threat_level": "Medium",
        "cvss": 6.8,
        "known_exploit": "SMTP Relay Abuse",
        "attack_type": "Mail Abuse / Spam Relay",
        "known_malware": ["Spam Bots"],
        "exploit_available": "Limited",
        "priority": "Medium",
        "confidence": 70,
        "summary": "Exposed SMTP services should be checked for open relay and authentication weaknesses."
    },

    53: {
        "threat_level": "Medium",
        "cvss": 7.0,
        "known_exploit": "DNS Amplification",
        "attack_type": "Denial of Service",
        "known_malware": ["DDoS Botnets"],
        "exploit_available": "Yes",
        "priority": "Medium",
        "confidence": 75,
        "summary": "DNS services may be abused for amplification attacks if improperly configured."
    },

    80: {
        "threat_level": "Medium",
        "cvss": 7.5,
        "known_exploit": "HTTP Enumeration / HTTP DoS",
        "attack_type": "Web Attack Surface",
        "known_malware": ["Web Scanners", "Exploit Kits"],
        "exploit_available": "Yes",
        "priority": "Medium",
        "confidence": 80,
        "summary": "HTTP exposes an unencrypted web service and should redirect traffic to HTTPS."
    },

    110: {
        "threat_level": "Medium",
        "cvss": 6.5,
        "known_exploit": "POP3 Credential Capture",
        "attack_type": "Credential Theft",
        "known_malware": ["Credential Stealers"],
        "exploit_available": "Limited",
        "priority": "Medium",
        "confidence": 70,
        "summary": "POP3 should use encrypted variants to protect email credentials."
    },

    139: {
        "threat_level": "High",
        "cvss": 8.0,
        "known_exploit": "NetBIOS Enumeration",
        "attack_type": "Information Disclosure / Lateral Movement",
        "known_malware": ["Worms", "Ransomware"],
        "exploit_available": "Yes",
        "priority": "High",
        "confidence": 85,
        "summary": "NetBIOS exposure can reveal host and share information useful for lateral movement."
    },

    143: {
        "threat_level": "Medium",
        "cvss": 6.5,
        "known_exploit": "IMAP Credential Capture",
        "attack_type": "Credential Theft",
        "known_malware": ["Credential Stealers"],
        "exploit_available": "Limited",
        "priority": "Medium",
        "confidence": 70,
        "summary": "IMAP should be protected with TLS and strong authentication."
    },

    443: {
        "threat_level": "Low",
        "cvss": 4.3,
        "known_exploit": "TLS Misconfiguration",
        "attack_type": "Encrypted Web Exposure",
        "known_malware": ["Web Scanners"],
        "exploit_available": "Limited",
        "priority": "Low",
        "confidence": 65,
        "summary": "HTTPS is generally expected, but TLS configuration should be reviewed."
    },

    445: {
        "threat_level": "Critical",
        "cvss": 9.8,
        "known_exploit": "EternalBlue",
        "attack_type": "Remote Code Execution / Lateral Movement",
        "known_malware": ["WannaCry", "NotPetya", "TrickBot"],
        "exploit_available": "Yes",
        "priority": "Immediate",
        "confidence": 95,
        "summary": "SMB exposure is highly sensitive and commonly associated with ransomware and lateral movement attacks."
    },

    3306: {
        "threat_level": "High",
        "cvss": 8.0,
        "known_exploit": "MySQL Unauthorized Access",
        "attack_type": "Database Exposure",
        "known_malware": ["SQL Bots", "Credential Stealers"],
        "exploit_available": "Yes",
        "priority": "High",
        "confidence": 85,
        "summary": "Database services should not be exposed to untrusted networks."
    },

    3389: {
        "threat_level": "Critical",
        "cvss": 9.8,
        "known_exploit": "BlueKeep",
        "attack_type": "Remote Desktop Exploitation",
        "known_malware": ["Ransomware", "Brute-force Bots"],
        "exploit_available": "Yes",
        "priority": "Immediate",
        "confidence": 95,
        "summary": "RDP exposure is frequently targeted by attackers and should be protected with VPN and MFA."
    },

    8080: {
        "threat_level": "Medium",
        "cvss": 7.2,
        "known_exploit": "Exposed Admin Panel / Proxy Abuse",
        "attack_type": "Web Administration Exposure",
        "known_malware": ["Web Scanners", "Exploit Kits"],
        "exploit_available": "Yes",
        "priority": "Medium",
        "confidence": 80,
        "summary": "Port 8080 often hosts admin panels, proxies, or alternate web services."
    }
}


DEFAULT_THREAT_INTEL = {
    "threat_level": "Info",
    "cvss": 0.0,
    "known_exploit": "No known exploit mapped",
    "attack_type": "Unknown / General Exposure",
    "known_malware": [],
    "exploit_available": "Unknown",
    "priority": "Review",
    "confidence": 40,
    "summary": "No specific threat intelligence is mapped for this port in the local database."
}


def get_threat_intel(port: int) -> dict:
    """
    Return threat intelligence for a given port.

    Args:
        port: TCP port number.

    Returns:
        Dictionary containing threat intelligence details.
    """
    return THREAT_INTEL_DATABASE.get(port, DEFAULT_THREAT_INTEL.copy())


def get_highest_threat_level(open_ports: list[dict]) -> str:
    """
    Determine the highest threat level across all open ports.
    """
    priority_order = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "Info": 1
    }

    highest = "Info"

    for item in open_ports:
        threat = item.get("threat", {})
        level = threat.get("threat_level", "Info")

        if priority_order.get(level, 1) > priority_order.get(highest, 1):
            highest = level

    return highest


def get_average_cvss(open_ports: list[dict]) -> float:
    """
    Calculate average CVSS score for detected open ports.
    """
    if not open_ports:
        return 0.0

    total = 0.0

    for item in open_ports:
        threat = item.get("threat", {})
        total += float(threat.get("cvss", 0.0))

    return round(total / len(open_ports), 2)