import subprocess
from fpdf import FPDF
from datetime import datetime
import os
import argparse
from concurrent.futures import ThreadPoolExecutor

# Function to run a system command and capture output
def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8') + "\n" + result.stderr.decode('utf-8')

# Function to get recommendations based on scanner output
def get_recommendations(tool, output):
    recommendations = {
        "Nikto": [
            ("Outdated server software", "Upgrade the server software to the latest version."),
            ("Potentially dangerous files exposed", "Ensure that sensitive files (e.g., backup files) are not exposed to the public."),
            ("Directory listing enabled", "Disable directory listing to prevent attackers from viewing directory contents."),
        ],
        "Nmap": [
            ("Open ports", "Close unnecessary ports and services to reduce attack surface."),
            ("Old version of service detected", "Update the service to the latest version to patch known vulnerabilities."),
        ],
        "SQLMap": [
            ("SQL Injection vulnerability", "Use prepared statements or parameterized queries to prevent SQL injection."),
        ],
        "Gobuster": [
            ("Hidden directories found", "Restrict access to sensitive directories with proper authentication or firewalls."),
        ],
        "OWASP ZAP": [
            ("XSS", "Sanitize user input and use Content Security Policy (CSP)."),
            ("SQL Injection", "Use parameterized queries to prevent SQL injection."),
            ("Insecure HTTP", "Redirect to HTTPS and use secure headers."),
        ]
    }

    recommendations_found = []
    for issue, recommendation in recommendations.get(tool, []):
        if issue.lower() in output.lower():
            recommendations_found.append(f"{issue}: {recommendation}")
    
    return "\n".join(recommendations_found) if recommendations_found else "No specific recommendations available."

# Report generation
def generate_pdf(report_data, output_file):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    pdf.cell(200, 10, txt=f"Vulnerability Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(10)
    
    for tool, data in report_data.items():
        pdf.cell(200, 10, txt=f"Tool: {tool}", ln=True)
        pdf.multi_cell(0, 10, txt=data)
        pdf.ln(5)
    
    pdf.output(output_file)

def generate_html(report_data, output_file):
    with open(output_file, 'w') as f:
        f.write("<html><body>")
        f.write(f"<h1>Vulnerability Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h1>")
        
        for tool, data in report_data.items():
            f.write(f"<h2>Tool: {tool}</h2>")
            f.write(f"<pre>{data}</pre>")
        
        f.write("</body></html>")

# Speed-optimized scan functions
def scan_nikto(url):
    return run_command(["nikto", "-h", url, "-Tuning", "x", "-Plugins", "ALL", "-nointeractive"])

def scan_nmap(url):
    return run_command(["nmap", "-T4", "-sV", "--min-rate", "1000", url])

def scan_sqlmap(url):
    return run_command(["sqlmap", "-u", url, "--batch", "--crawl=1", "--threads=10", "--timeout=10", "--retries=1"])

def scan_gobuster(url):
    return run_command(["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50", "-q"])

def scan_zap(url):
    try:
        subprocess.run(["zap-cli", "start", "--start-options", "-config api.disablekey=true"], check=True)
        subprocess.run(["zap-cli", "open-url", url], check=True)
        subprocess.run(["zap-cli", "spider", url], check=True)
        subprocess.run(["zap-cli", "active-scan", url], check=True)
        output = run_command(["zap-cli", "alerts"])
        return output
    except Exception as e:
        return f"ZAP scan failed: {str(e)}"

# Main function
def main():
    parser = argparse.ArgumentParser(description="AI-powered Web App Vulnerability Scanner")
    parser.add_argument('--url', required=True, help="URL of the target website")
    parser.add_argument('--output', default="report", help="Output file name (without extension)")
    parser.add_argument('--format', choices=["pdf", "html"], default="pdf", help="Report format (pdf/html)")
    args = parser.parse_args()
    
    url = args.url
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