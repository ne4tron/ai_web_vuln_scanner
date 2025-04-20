# AI-Powered Web Vulnerability Scanner

This tool automates web app penetration testing using:

- **Nikto** – web server vulnerabilities
- **Nmap** – port scanning & service detection
- **SQLMap** – SQL injection detection
- **Gobuster** – directory brute-forcing
- **OWASP ZAP** – full security scan (via zap-cli)
- **PDF/HTML Report** – with recommendations

## Usage

```bash
python3 scanner.py --url http://example.com --format pdf --output example_report

clone tool:
git clone https://github.com/NE4TRON/ai_web_vuln_scanner.git 
cd ai_web_vuln_scanner