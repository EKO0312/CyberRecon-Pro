# 🔍 CyberRecon Pro — Domain Security Scanner

> Professional domain security reconnaissance tool with automated PDF report generation.
> Built by **Olojede Emmanuel Kolade** — Cybersecurity Enthusiast, Nigeria 🇳🇬

---

## 🎯 What It Does

Performs automated security reconnaissance on any domain and produces a professional PDF intelligence report covering:

- 🔒 SSL Certificate — Validity, expiry date, issuer, days remaining
- 🌐 HTTP Security Headers — Missing HSTS, CSP, X-Frame-Options
- 🔌 Port Scanning — 11 common ports, flags dangerous open ports
- 📊 Risk Scoring — Overall 0-100 security score with risk level
- 💡 Recommendations — Specific, prioritized remediation steps

---

## 🚀 Quick Start

Clone the repo and install dependencies:

pip install -r requirements.txt

Scan any domain:

python scanner.py example.com

Your PDF report will be generated instantly.

---

## 🧠 How It Works

1. Takes a target domain as input
2. Runs automated OSINT reconnaissance across 4 attack surface categories
3. Identifies Indicators of Compromise and misconfigurations
4. Calculates an overall risk score based on findings
5. Generates a branded client-ready PDF intelligence report

---

## 📋 Sample Report Output

TARGET: example.com
IP ADDRESS: 93.184.216.34
SCAN DATE: 2026-04-06

SSL CERTIFICATE:
  Valid | Issuer: DigiCert | Expires: 2027-01-15 | 285 days remaining

PORT SCAN:
  Port 3306 MySQL - OPEN - HIGH RISK - Database exposed to internet
  Port 23 Telnet - OPEN - CRITICAL - Unencrypted protocol active
  Port 443 HTTPS - OPEN - Normal
  Port 80 HTTP - OPEN - Normal

SECURITY HEADERS:
  Missing: Content-Security-Policy
  Missing: Strict-Transport-Security HSTS
  Present: X-Frame-Options

RISK SCORE: 45 / 100
RISK LEVEL: HIGH RISK

RECOMMENDATIONS:
  1. Close Port 3306 — restrict MySQL behind firewall immediately
  2. Disable Telnet Port 23 — use SSH instead
  3. Implement Content-Security-Policy header
  4. Enable HSTS to enforce HTTPS connections

---

## 🛠️ Tech Stack

- Core scanning — Python, Socket programming
- SSL analysis — Python SSL module
- DNS lookups — Subprocess and nslookup
- HTTP header analysis — urllib
- PDF generation — ReportLab

---

## 👨‍💻 Author

Olojede Emmanuel Kolade
Cybersecurity and AI Security Enthusiast | Nigeria
Google Cybersecurity Certificate In Progress | AI Governance Certified
Email: emmanuelkolade8@gmail.com
GitHub: github.com/EKO0312

---

## 📄 License

MIT License
