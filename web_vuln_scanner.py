import subprocess
from fpdf import FPDF
from datetime import datetime
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
import time
import re

def run_command(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        return result.stdout.decode('utf-8') + "\n" + result.stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        return f"Command {' '.join(command)} timed out."

def get_detailed_recommendations(tool, output):
    recommendations = []

    def add_recommendation(text, severity, cvss_score):
        recommendations.append(f"[{severity} | CVSS: {cvss_score}] {text}")

    if tool == "Nikto":
        if "x-frame-options header is not present" in output.lower():
            add_recommendation("Add the X-Frame-Options header to prevent clickjacking attacks.", "Medium", "6.1")
        if "x-xss-protection header is not defined" in output.lower():
            add_recommendation("Add the X-XSS-Protection header to mitigate some forms of XSS attacks.", "Medium", "6.1")
        if "x-content-type-options header is not set" in output.lower():
            add_recommendation("Add the X-Content-Type-Options header to prevent MIME type sniffing.", "Low", "3.7")
        if ".xml contains a full wildcard entry" in output.lower():
            add_recommendation("Restrict wildcard entries in XML to trusted domains only.", "High", "7.5")

    elif tool == "SQLMap":
        if "boolean-based blind" in output.lower():
            add_recommendation("Use parameterized queries to prevent boolean-based blind SQL injection.", "High", "8.6")
        if "error-based" in output.lower():
            add_recommendation("Sanitize inputs and disable SQL error messages to prevent error-based SQL injection.", "High", "8.6")
        if "time-based blind" in output.lower():
            add_recommendation("Use timeouts and input validation to mitigate time-based blind SQL injection.", "High", "8.0")
        if "union query" in output.lower():
            add_recommendation("Use ORM or query builders to avoid UNION SQL injection.", "Critical", "9.8")

    elif tool == "Gobuster":
        if ".bak" in output.lower():
            add_recommendation("Avoid storing backup files on production servers or restrict access to them.", "High", "7.4")
        if "/admin" in output.lower():
            add_recommendation("Secure admin directories with authentication and IP whitelisting.", "Medium", "6.3")

    elif tool == "Nmap":
        if "open" in output.lower():
            add_recommendation("Close unnecessary open ports or restrict with firewall rules.", "Medium", "6.5")
        if "vulnerable" in output.lower():
            add_recommendation("Update vulnerable services and apply security patches.", "Critical", "9.0")

    elif tool == "OWASP ZAP":
        if "xss" in output.lower():
            add_recommendation("Sanitize all user inputs and implement a Content Security Policy (CSP).", "Critical", "9.4")
        if "sql" in output.lower():
            add_recommendation("Use parameterized SQL queries and input validation.", "Critical", "9.8")
        if "http" in output.lower():
            add_recommendation("Enforce HTTPS and use secure HTTP headers.", "High", "7.1")

    return "\n".join(recommendations) if recommendations else "No specific recommendations available."

def generate_pdf(report_data, output_file):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Vulnerability Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(10)

    for tool, data in report_data.items():
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, txt=f"Tool: {tool}", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 10, txt=data)
        pdf.ln(5)

    pdf.output(output_file)

def generate_html(report_data, output_file):
    with open(output_file, 'w') as f:
        f.write("<html><head><title>Vulnerability Report</title></head><body>")
        f.write(f"<h1>Vulnerability Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h1>")
        for tool, data in report_data.items():
            f.write(f"<h2>Tool: {tool}</h2><pre>{data}</pre>")
        f.write("</body></html>")

def scan_nikto(url):
    return run_command(["nikto", "-h", url, "-maxtime", "10m"])

def scan_nmap(url):
    hostname = url.replace("http://", "").replace("https://", "").split("/")[0]
    return run_command(["nmap", "-p", "80,443", "-T3", "-sV", "--script", "vuln", hostname, "--host-timeout", "2m"])

def scan_sqlmap(url):
    return run_command(["sqlmap", "-u", f"{url}/artists.php?artist=1", "--batch", "--crawl=3", "--threads=10", "--timeout=15", "--retries=1"])

def scan_gobuster(url):
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    return run_command(["gobuster", "dir", "-u", url, "-w", wordlist, "-x", ".php,.bak,.txt", "-t", "50", "-q", "-e"])

def scan_zap(url):
    try:
        subprocess.run(["zap-cli", "start", "--start-options", "-config", "api.disablekey=true"], check=True)
        subprocess.run(["zap-cli", "open-url", url], check=True)
        subprocess.run(["zap-cli", "spider", url], check=True)
        subprocess.run(["zap-cli", "active-scan", url], check=True)
        time.sleep(10)
        return run_command(["zap-cli", "alerts"])
    except FileNotFoundError:
        return "ZAP scan failed: 'zap-cli' not found. Please install it with `pip install python-owasp-zap-v2.4` or ensure it is in your PATH."
    except Exception as e:
        return f"ZAP scan failed: {str(e)}"

def save_raw_output(tool, output, base_name):
    filename = f"{base_name}_{tool.lower().replace(' ', '_')}.txt"
    with open(filename, 'w') as f:
        f.write(output)

def main():
    parser = argparse.ArgumentParser(description="AI-powered Web App Vulnerability Scanner")
    parser.add_argument('--url', required=True, help="URL of the target website")
    parser.add_argument('--output', default="report", help="Output file name (without extension)")
    parser.add_argument('--format', choices=["pdf", "html"], default="pdf", help="Report format (pdf/html)")
    args = parser.parse_args()

    url = args.url.rstrip("/")
    output_file = args.output
    report_format = args.format
    report_data = {}

    print(f"[+] Starting vulnerability scan for {url}...")

    with ThreadPoolExecutor() as executor:
        futures = {
            "Nikto": executor.submit(scan_nikto, url),
            "Nmap": executor.submit(scan_nmap, url),
            "SQLMap": executor.submit(scan_sqlmap, url),
            "Gobuster": executor.submit(scan_gobuster, url),
            "OWASP ZAP": executor.submit(scan_zap, url),
        }

        for tool, future in futures.items():
            output = future.result()
            save_raw_output(tool, output, output_file)
            report_data[tool] = output + "\n\nRecommendations:\n" + get_detailed_recommendations(tool, output)

    final_output_file = output_file + (".pdf" if report_format == "pdf" else ".html")
    if report_format == "pdf":
        generate_pdf(report_data, final_output_file)
    else:
        generate_html(report_data, final_output_file)

    print(f"[+] Scan completed. Report saved to: {final_output_file}")

if __name__ == "__main__":
    main()