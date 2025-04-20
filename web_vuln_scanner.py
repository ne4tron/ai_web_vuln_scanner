import subprocess
from fpdf import FPDF
from datetime import datetime
import os
import argparse
from concurrent.futures import ThreadPoolExecutor

# Function to run a system command and capture output
def run_command(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        return result.stdout.decode('utf-8') + "\n" + result.stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        return f"Command {' '.join(command)} timed out."

# Function to get recommendations based on scanner output
def get_recommendations(tool, output):
    keywords = {
        "Nikto": {
            "outdated": "Upgrade the server software to the latest version.",
            "exposed": "Ensure sensitive files are not publicly accessible.",
            "directory listing": "Disable directory listing to prevent directory content exposure."
        },
        "Nmap": {
            "open": "Close unnecessary open ports.",
            "vulnerable": "Update the service to fix known vulnerabilities.",
            "outdated": "Upgrade the detected outdated services."
        },
        "SQLMap": {
            "injection": "Use parameterized queries to prevent SQL injection.",
            "vulnerable": "Sanitize user inputs to mitigate SQLi risk."
        },
        "Gobuster": {
            "Found:": "Restrict access to sensitive directories or files using proper authentication and firewalls."
        },
        "OWASP ZAP": {
            "xss": "Sanitize user input and implement Content Security Policy (CSP).",
            "sql": "Use parameterized queries and sanitize all inputs.",
            "http": "Force HTTPS and use secure headers."
        }
    }

    output_lower = output.lower()
    recs = set()
    for keyword, rec in keywords.get(tool, {}).items():
        if keyword in output_lower:
            recs.add(f"{keyword.title()}: {rec}")
    
    return "\n".join(recs) if recs else "No specific recommendations available."

# PDF report generation
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
        f.write("<html><body>")
        f.write(f"<h1>Vulnerability Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h1>")
        for tool, data in report_data.items():
            f.write(f"<h2>Tool: {tool}</h2><pre>{data}</pre>")
        f.write("</body></html>")

# Updated scan functions
def scan_nikto(url):
    return run_command(["nikto", "-h", url])

def scan_nmap(url):
    return run_command(["nmap", "-p", "80,443", "-T4", "-sV", "--script", "vuln", url])

def scan_sqlmap(url):
    return run_command(["sqlmap", "-u", f"{url}/artists.php?artist=1", "--batch", "--crawl=3", "--threads=10", "--timeout=15", "--retries=1"])

def scan_gobuster(url):
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    return run_command(["gobuster", "dir", "-u", url, "-w", wordlist, "-x", ".php,.bak,.txt", "-t", "50", "-q", "-e"])

def scan_zap(url):
    try:
        subprocess.run(["zap-cli", "start", "--start-options", "-config api.disablekey=true"], check=True)
        subprocess.run(["zap-cli", "open-url", url], check=True)
        subprocess.run(["zap-cli", "spider", url], check=True)
        subprocess.run(["zap-cli", "active-scan", url], check=True)
        subprocess.run(["sleep", "10"])  # Give it some time
        return run_command(["zap-cli", "alerts"])
    except Exception as e:
        return f"ZAP scan failed: {str(e)}"

# Save raw tool output for inspection
def save_raw_output(tool, output, base_name):
    filename = f"{base_name}_{tool.lower().replace(' ', '_')}.txt"
    with open(filename, 'w') as f:
        f.write(output)

# Main function
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
            report_data[tool] = output + "\n\nRecommendations:\n" + get_recommendations(tool, output)

    if report_format == "pdf":
        output_file += ".pdf"
        generate_pdf(report_data, output_file)
    else:
        output_file += ".html"
        generate_html(report_data, output_file)

    print(f"[+] Scan completed. Report saved to: {output_file}")

if __name__ == "__main__":
    main()