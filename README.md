# 🛡️ PortGuardAI

### AI-Powered Enterprise Port Scanner & Network Security Assessment Platform
An enterprise-grade AI-powered cybersecurity tool for intelligent network scanning, attack surface analysis, vulnerability assessment, threat intelligence, and professional security reporting.

<img width="1536" height="1024" alt="ChatGPT Image Jun 30, 2026, 02_18_34 PM" src="https://github.com/user-attachments/assets/5bc92d14-349d-40be-aaae-ca2afb27dfa1" />


<img width="1920" height="1080" alt="Screenshot (271)" src="https://github.com/user-attachments/assets/01625771-4ff9-4ab3-863f-f245b96cd564" />
<img width="1920" height="1080" alt="Screenshot (272)" src="https://github.com/user-attachments/assets/29b5bbee-dc6e-403d-bbbc-281a00bac2d5" />

---

# 🚀 About PortGuardAI

PortGuardAI is an advanced **AI-Powered Enterprise Port Scanner** designed to help security professionals, ethical hackers, students, and researchers perform intelligent network reconnaissance and security assessments.

Unlike traditional port scanners, PortGuardAI combines:

- AI Risk Assessment
- Banner Intelligence
- Threat Intelligence
- CVE Mapping
- MITRE ATT&CK Mapping
- Attack Surface Analysis
- HTML Dashboard Reporting

to generate enterprise-level security reports.

---

# ✨ Key Features

| Feature | Description |
|----------|-------------|
| 🚀 Multi-threaded Scanner | High-speed concurrent port scanning |
| 🤖 AI Security Engine | Intelligent risk analysis |
| 🔥 Banner Grabbing | Detect technologies and exposed services |
| 🎯 Attack Surface Detection | Identify exposed attack vectors |
| 📚 Threat Intelligence | Known exploits & malware mapping |
| 🛡 CVE Database | Vulnerability identification |
| 🎖 MITRE ATT&CK | Technique mapping |
| 📊 Security Score | AI-generated security rating |
| 📈 CVSS Analysis | Severity calculation |
| 📄 Executive Summary | Enterprise report overview |
| 🌐 HTML Dashboard | Professional security report |
| 📁 CSV Export | Export scan results |
| 📝 Logging | Complete scan history |
| ⚡ Progress Bar | Real-time scan progress |

---

# 📷 Dashboard Preview

<img width="1920" height="1080" alt="Screenshot (273)" src="https://github.com/user-attachments/assets/b9646529-18e8-4654-b5b1-34cb54af52de" />


## Security Dashboard


<img width="1920" height="1080" alt="Screenshot (274)" src="https://github.com/user-attachments/assets/675570d7-e9d1-44e5-a630-7b64aee5c4e8" />


## Security Overview


<img width="1920" height="1080" alt="Screenshot (275)" src="https://github.com/user-attachments/assets/8a02f935-24f9-431f-8b68-ce44bf42abf5" />


## AI Security Assessment

<img width="1920" height="1080" alt="Screenshot (276)" src="https://github.com/user-attachments/assets/1ad87950-63dd-4b7e-9e78-b284e4812425" />


## Threat Intelligence


<img width="1920" height="1080" alt="Screenshot (277)" src="https://github.com/user-attachments/assets/6dfc7a2d-fcdd-46fc-b702-ddf2a42beae3" />



### Banner Intelligence


<img width="1536" height="1024" alt="ChatGPT Image Jun 30, 2026, 02_18_34 PM" src="https://github.com/user-attachments/assets/1bad25b9-96c2-45a6-99de-f465b6699b19" />




## Open Port Analysis


<img width="1920" height="1080" alt="Screenshot (272)" src="https://github.com/user-attachments/assets/d63c725c-3e18-4540-859a-0db34cc90ef8" />


# 🏗 Architecture

```text
                +----------------------+
                |      User Input      |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |  Multi-thread Scanner|
                +----------+-----------+
                           |
         +-----------------+----------------+
         |                 |                |
         v                 v                v
 Banner Grabbing     CVE Mapping     Threat Intelligence
         |                 |                |
         +-----------------+----------------+
                           |
                           v
                +----------------------+
                | AI Risk Assessment   |
                +----------+-----------+
                           |
                           v
               +------------------------+
               | HTML / CSV Reporting   |
               +------------------------+
```
# ⚙ Installation

## Clone the Repository

```bash
git clone https://github.com/Devendrasingno1/PortGuardAI.git
```

Move into the project directory

```bash
cd PortGuardAI
```

Install required dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python main.py
```

---

# 🚀 Usage

Start the scanner

```text
python main.py
```

Example

```text
Enter Target IP/Hostname : google.com

Enter Start Port : 1

Enter End Port : 1000
```

Example Output

```text
============================================================

Target : google.com

Open Ports

80 HTTP

443 HTTPS

Security Score : 87/100

Overall Risk : Low

Attack Surface : Web Services

Threat Intelligence Completed

HTML Report Generated

CSV Report Generated

============================================================
```

---

# 📊 Generated Reports

After every successful scan PortGuardAI automatically generates:

```
reports/

├── scan_report.html

└── scan_report.csv
```

The HTML report contains:

- Executive Summary
- Security Score
- Banner Intelligence
- Threat Intelligence
- CVE Mapping
- MITRE ATT&CK Mapping
- Risk Distribution
- AI Recommendations
- Open Port Analysis

---

# 📂 Project Structure

```text
PortGuardAI/

│

├── assets/

├── logs/

├── reports/

│

├── advisor.py

├── attack_surface.py

├── banner.py

├── banner_grabber.py

├── config.py

├── cve_database.py

├── dashboard.py

├── logger.py

├── main.py

├── progress.py

├── report.py

├── risk.py

├── scanner.py

├── score.py

├── services.py

├── threat_intel.py

├── utils.py

│

├── requirements.txt

├── README.md

├── LICENSE

└── .gitignore
```

---

# 🧠 Technologies Used

| Category | Technology |
|-----------|------------|
| Programming Language | Python 3.11 |
| Networking | Python Socket |
| Concurrency | ThreadPoolExecutor |
| Reporting | HTML + CSV |
| Security Framework | MITRE ATT&CK |
| Vulnerability Intelligence | CVE Mapping |
| Threat Intelligence | Local Threat Database |
| Banner Grabbing | HTTP Banner Analysis |
| Risk Engine | AI Security Score |
| Dashboard | HTML/CSS |

---

# 🔍 Scan Workflow

```text
User Input

↓

DNS Resolution

↓

Port Scanning

↓

Banner Grabbing

↓

Technology Detection

↓

Threat Intelligence

↓

CVE Mapping

↓

MITRE ATT&CK Mapping

↓

Security Score Calculation

↓

Attack Surface Analysis

↓

AI Recommendation Engine

↓

HTML Report

↓

CSV Report

↓

Scan Log
```

---

# 💡 Enterprise Features

✅ High-Speed Multi-thread Scanning

✅ Banner Intelligence

✅ Threat Intelligence

✅ AI Security Score

✅ Attack Surface Analysis

✅ MITRE ATT&CK Integration

✅ CVE Mapping

✅ Executive Summary

✅ HTML Dashboard

✅ CSV Export

✅ Logging System

✅ Security Recommendations

---

# 🎯 Use Cases

- Penetration Testing
- Network Security Auditing
- Security Awareness Training
- Internal Network Assessment
- Educational Cybersecurity Labs
- Enterprise Security Validation
- Cybersecurity Learning
- Research Projects
- Portfolio Demonstration


# 🛣 Project Roadmap

The following features are planned for future releases.

| Feature | Status |
|----------|--------|
| Multi-thread Port Scanner | ✅ Completed |
| Banner Grabbing | ✅ Completed |
| Technology Detection | ✅ Completed |
| AI Security Score | ✅ Completed |
| Attack Surface Analysis | ✅ Completed |
| Threat Intelligence | ✅ Completed |
| CVE Mapping | ✅ Completed |
| MITRE ATT&CK Mapping | ✅ Completed |
| HTML Dashboard | ✅ Completed |
| CSV Report | ✅ Completed |
| Scan Logging | ✅ Completed |
| Interactive Charts | 🚧 Planned |
| PDF Report Export | 🚧 Planned |
| Service Version Detection | 🚧 Planned |
| Operating System Detection | 🚧 Planned |
| SSL/TLS Scanner | 🚧 Planned |
| Security Headers Analysis | 🚧 Planned |
| Subdomain Enumeration | 🚧 Planned |
| REST API | 🚧 Planned |
| Flask Web Dashboard | 🚧 Planned |
| AI Security Assistant | 🚧 Planned |
| Multi Target Scan | 🚧 Planned |

---

# 📈 Performance

| Capability | Details |
|------------|---------|
| Scan Type | TCP Connect Scan |
| Concurrency | Multi-threaded |
| Progress Tracking | Real-time |
| Report Generation | HTML + CSV |
| Logging | Supported |
| Platform | Windows |
| Language | Python 3.11 |

---

# 🔐 Security Notice

PortGuardAI is developed for:

- Educational purposes
- Security research
- Authorized penetration testing
- Internal security assessments
- Cybersecurity learning

**Always obtain proper authorization before scanning systems you do not own or have explicit permission to test.**

---

# 🤝 Contributing

Contributions are welcome.

If you would like to improve PortGuardAI:

1. Fork the repository
2. Create a new feature branch
3. Commit your changes
4. Push your branch
5. Open a Pull Request

---

# 📌 Why PortGuardAI?

Unlike a basic port scanner, PortGuardAI combines multiple security assessment capabilities into one platform.

### Core Modules

- Intelligent Port Scanner
- AI Risk Assessment
- Banner Intelligence
- Threat Intelligence
- CVE Mapping
- MITRE ATT&CK Mapping
- Attack Surface Analysis
- Security Scoring
- Executive Reporting

This makes PortGuardAI suitable for learning, demonstrations, and portfolio projects while following responsible security practices.

---

# 📷 Repository Preview

```
PortGuardAI
│
├── Python Source Code
├── HTML Security Dashboard
├── Threat Intelligence Engine
├── AI Security Assessment
├── CVE Mapping
├── MITRE ATT&CK Mapping
├── Banner Intelligence
├── Security Reports
└── Professional Documentation
```

---

# 👨‍💻 Developer

## Devendra Rajput

Cybersecurity Enthusiast • Python Developer • AI Security Learner

### Skills

- Python
- Cybersecurity
- Network Security
- Socket Programming
- Threat Intelligence
- AI-based Security Analysis

GitHub:

**https://github.com/Devendrasingno1**

---

# 📄 License

This project is licensed under the **MIT License**.

See the LICENSE file for more information.

---

# ⭐ Support the Project

If you found this project useful:

⭐ Star this repository

🍴 Fork the project

📢 Share it with others

---

<div align="center">

## 🚀 PortGuardAI

### AI-Powered Enterprise Port Scanner & Network Security Assessment Platform

Developed with ❤️ by **Devendra Rajput**

⭐ Thank you for visiting this repository!

</div>
````

