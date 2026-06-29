CVE_DATABASE = {
    21: {
        "id": "CVE-2015-3306",
        "severity": "High",
        "title": "ProFTPD Remote Command Execution",
        "description": "Some FTP servers may allow remote command execution if unpatched."
    },
    22: {
        "id": "CVE-2018-15473",
        "severity": "Medium",
        "title": "OpenSSH User Enumeration",
        "description": "Attackers may enumerate valid SSH usernames."
    },
    80: {
        "id": "CVE-2023-44487",
        "severity": "High",
        "title": "HTTP/2 Rapid Reset",
        "description": "HTTP/2 servers may be abused for denial-of-service attacks."
    },
    443: {
        "id": "CVE-2023-44487",
        "severity": "Medium",
        "title": "HTTP/2 Rapid Reset",
        "description": "HTTPS services should be patched against HTTP/2 abuse."
    },
    445: {
        "id": "CVE-2017-0144",
        "severity": "Critical",
        "title": "EternalBlue SMB RCE",
        "description": "SMB remote code execution vulnerability used by WannaCry."
    },
    3306: {
        "id": "CVE-2012-2122",
        "severity": "High",
        "title": "MySQL Authentication Bypass",
        "description": "Improper authentication may allow unauthorized access."
    },
    3389: {
        "id": "CVE-2019-0708",
        "severity": "Critical",
        "title": "BlueKeep RDP RCE",
        "description": "Remote Desktop vulnerability allowing remote code execution."
    }
}


def get_cve_info(port: int) -> dict:
    return CVE_DATABASE.get(port, {
        "id": "N/A",
        "severity": "Info",
        "title": "No mapped CVE",
        "description": "No local CVE mapping available for this port."
    })