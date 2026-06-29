RISK_DATABASE = {
    21: {
        "level": "High",
        "description": "FTP may transmit credentials in plain text.",
        "recommendation": "Use SFTP or FTPS instead of FTP.",
        "mitre": "T1048"
    },
    22: {
        "level": "Medium",
        "description": "SSH allows remote administration access.",
        "recommendation": "Use SSH keys, disable password login, and restrict IP access.",
        "mitre": "T1021.004"
    },
    23: {
        "level": "High",
        "description": "Telnet sends data in plain text.",
        "recommendation": "Disable Telnet and use SSH instead.",
        "mitre": "T1021"
    },
    80: {
        "level": "Medium",
        "description": "HTTP traffic is unencrypted.",
        "recommendation": "Redirect HTTP traffic to HTTPS.",
        "mitre": "T1040"
    },
    443: {
        "level": "Low",
        "description": "HTTPS is encrypted and commonly required.",
        "recommendation": "Keep TLS certificates updated and disable weak ciphers.",
        "mitre": "N/A"
    },
    445: {
        "level": "Critical",
        "description": "SMB is commonly targeted in ransomware and lateral movement attacks.",
        "recommendation": "Disable SMBv1, restrict SMB access, and patch Windows systems.",
        "mitre": "T1021.002"
    },
    3306: {
        "level": "High",
        "description": "MySQL exposure may allow database attacks.",
        "recommendation": "Restrict database access to trusted hosts only.",
        "mitre": "T1190"
    },
    3389: {
        "level": "Critical",
        "description": "RDP exposure can lead to brute-force attacks.",
        "recommendation": "Use VPN, MFA, and restrict RDP access.",
        "mitre": "T1021.001"
    },
    8080: {
        "level": "Medium",
        "description": "Alternate web ports may expose admin panels.",
        "recommendation": "Verify authentication and disable unused services.",
        "mitre": "T1190"
    }
}


def get_risk_info(port: int) -> dict:
    return RISK_DATABASE.get(port, {
        "level": "Info",
        "description": "No specific risk mapping available for this port.",
        "recommendation": "Verify whether this service is required.",
        "mitre": "N/A"
    })