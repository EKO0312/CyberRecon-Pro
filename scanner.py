"""
CyberRecon Pro - Domain Security Reconnaissance Tool
Author: Olojede Emmanuel Kolade
Scans a domain and generates a professional PDF security report.
Sell this as a service to small businesses: ₦5,000 - ₦20,000 per scan
"""

import socket
import ssl
import datetime
import sys
import json
import os
import subprocess
import ipaddress
from urllib.request import urlopen, Request
from urllib.error import URLError
from report_generator import generate_pdf_report


def banner():
    print("""
╔═══════════════════════════════════════════════╗
║           🔍  CyberRecon Pro v1.0             ║
║    Domain Security Reconnaissance Tool        ║
║    By: Olojede Emmanuel Kolade                ║
╚═══════════════════════════════════════════════╝
    """)


def get_ip_address(domain):
    """Resolve domain to IP address"""
    try:
        ip = socket.gethostbyname(domain)
        return {"ip": ip, "status": "resolved"}
    except socket.gaierror as e:
        return {"ip": None, "status": f"Failed: {e}"}


def get_dns_records(domain):
    """Get DNS records using system nslookup"""
    records = {}
    record_types = ["A", "MX", "TXT", "NS"]

    for rtype in record_types:
        try:
            result = subprocess.run(
                ["nslookup", "-type=" + rtype, domain],
                capture_output=True, text=True, timeout=5
            )
            records[rtype] = result.stdout.strip()
        except Exception as e:
            records[rtype] = f"Lookup failed: {e}"

    return records


def check_ssl_certificate(domain):
    """Check SSL certificate validity and details"""
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        # Parse expiry
        expiry_str = cert.get("notAfter", "")
        expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days
        issuer = dict(x[0] for x in cert.get("issuer", []))

        return {
            "valid": True,
            "issuer": issuer.get("organizationName", "Unknown"),
            "expires": expiry.strftime("%Y-%m-%d"),
            "days_remaining": days_left,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "warning": days_left < 30
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"SSL Verification failed: {e}", "warning": True}
    except Exception as e:
        return {"valid": False, "error": str(e), "warning": True}


def check_open_ports(ip, ports=None):
    """Check common ports for open/closed status"""
    if ports is None:
        ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }

    results = {}
    risky_open = []

    for port, service in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        is_open = result == 0
        results[port] = {
            "service": service,
            "status": "OPEN" if is_open else "CLOSED",
            "open": is_open
        }
        # Flag risky open ports
        if is_open and port in [21, 23, 3306, 3389]:
            risky_open.append(f"Port {port} ({service}) is open — HIGH RISK")

    return results, risky_open


def check_http_headers(domain):
    """Check security-related HTTP headers"""
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy",
    }

    found = {}
    missing = []

    try:
        req = Request(f"https://{domain}", headers={"User-Agent": "CyberRecon-Pro/1.0"})
        response = urlopen(req, timeout=5)
        headers = dict(response.headers)

        for header, label in security_headers.items():
            if header in headers:
                found[label] = headers[header]
            else:
                missing.append(label)

        return {
            "server": headers.get("Server", "Hidden"),
            "found": found,
            "missing": missing,
            "score": len(found),
            "max_score": len(security_headers)
        }
    except Exception as e:
        return {"error": str(e), "found": {}, "missing": list(security_headers.values())}


def calculate_risk_score(ssl_data, port_risks, header_data):
    """Calculate overall security risk score"""
    score = 100  # Start perfect, deduct for issues

    # SSL issues
    if not ssl_data.get("valid"):
        score -= 30
    elif ssl_data.get("warning"):
        score -= 15

    # Risky open ports
    score -= len(port_risks) * 10

    # Missing security headers
    missing = len(header_data.get("missing", []))
    score -= missing * 5

    score = max(0, min(100, score))

    if score >= 80:
        level = "LOW RISK"
    elif score >= 60:
        level = "MEDIUM RISK"
    elif score >= 40:
        level = "HIGH RISK"
    else:
        level = "CRITICAL RISK"

    return score, level


def run_scan(domain):
    """Run full security scan on a domain"""
    # Clean domain
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    print(f"\n[*] Starting scan for: {domain}")
    print("-" * 48)

    results = {
        "domain": domain,
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "analyst": "Olojede Emmanuel Kolade",
    }

    print("[1/5] Resolving IP address...")
    results["ip_info"] = get_ip_address(domain)

    print("[2/5] Checking SSL certificate...")
    results["ssl"] = check_ssl_certificate(domain)

    ip = results["ip_info"].get("ip")
    if ip:
        print("[3/5] Scanning common ports...")
        port_results, port_risks = check_open_ports(ip)
        results["ports"] = port_results
        results["port_risks"] = port_risks
    else:
        results["ports"] = {}
        results["port_risks"] = []
        print("[3/5] Port scan skipped (IP not resolved)")

    print("[4/5] Checking HTTP security headers...")
    results["headers"] = check_http_headers(domain)

    print("[5/5] Calculating risk score...")
    score, level = calculate_risk_score(
        results["ssl"],
        results["port_risks"],
        results["headers"]
    )
    results["risk_score"] = score
    results["risk_level"] = level

    return results


def main():
    banner()

    if len(sys.argv) < 2:
        domain = input("Enter domain to scan (e.g. example.com): ").strip()
    else:
        domain = sys.argv[1]

    if not domain:
        print("[-] No domain provided. Exiting.")
        sys.exit(1)

    results = run_scan(domain)

    print("\n" + "=" * 48)
    print(f"  SCAN COMPLETE: {results['domain']}")
    print(f"  Risk Score: {results['risk_score']}/100")
    print(f"  Risk Level: {results['risk_level']}")
    print("=" * 48)

    print("\n[*] Generating PDF report...")
    filename = generate_pdf_report(results)
    print(f"[✓] Report saved: {filename}")
    print(f"\n💰 This report is ready to deliver to your client!")


if __name__ == "__main__":
    main()
