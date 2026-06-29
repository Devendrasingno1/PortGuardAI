import socket


def grab_service_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Try to grab a service banner from an open TCP port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in [80, 8080]:
            request = b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
            sock.sendall(request)

        elif port == 443:
            sock.close()
            return "HTTPS service detected. TLS banner inspection not enabled."

        elif port in [21, 22, 25, 110, 143]:
            pass

        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
        except socket.timeout:
            banner = ""

        sock.close()

        return banner if banner else "No banner detected"

    except Exception:
        return "No banner detected"


def detect_technology(banner: str, service: str) -> dict:
    """
    Detect basic technology from banner text.
    """
    text = banner.lower()

    technology = "Unknown"
    os_guess = "Unknown"
    confidence = 40

    if "apache" in text:
        technology = "Apache HTTP Server"
        confidence = 90
    elif "nginx" in text:
        technology = "Nginx Web Server"
        confidence = 90
    elif "iis" in text or "microsoft" in text:
        technology = "Microsoft IIS / Windows Service"
        os_guess = "Windows"
        confidence = 85
    elif "openssh" in text:
        technology = "OpenSSH"
        confidence = 90
    elif "ubuntu" in text:
        os_guess = "Ubuntu Linux"
        confidence = max(confidence, 75)
    elif "debian" in text:
        os_guess = "Debian Linux"
        confidence = max(confidence, 75)
    elif "centos" in text:
        os_guess = "CentOS Linux"
        confidence = max(confidence, 75)

    if service == "SMB":
        technology = "SMB / Windows File Sharing"
        os_guess = "Windows"
        confidence = max(confidence, 70)

    if service == "HTTPS" and technology == "Unknown":
        technology = "Encrypted Web Service"
        confidence = 60

    if service == "HTTP" and technology == "Unknown":
        technology = "Web Service"
        confidence = 60

    return {
        "technology": technology,
        "os_guess": os_guess,
        "confidence": confidence,
        "raw_banner": banner
    }