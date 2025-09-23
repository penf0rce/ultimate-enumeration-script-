
***a powerful Bash-based automation tool that performs extensive reconnaissance and vulnerability scanning on web applications and domains. It integrates multiple open-source tools to streamline the initial phases of penetration testing, from subdomain enumeration to active vulnerability checks.***

**🔍 Features**

Subdomain Enumeration: Uses subfinder, findomain, and ffuf for comprehensive subdomain discovery.

Subdomain Takeover Detection: Leverages subzy to identify potential subdomain takeover vulnerabilities.

Web Crawling & JS Analysis: Employs katana for crawling and extracts JavaScript files for further analysis.

Sensitive File Discovery: Searches for potentially exposed sensitive files (e.g., .sql, .env, .config).

Parameter Discovery: Uses arjun to find hidden parameters in URLs for further testing.

Content Discovery: Runs dirb and ffuf for directory and file brute-forcing with extensive extension fuzzing.

Vulnerability Scanning:
XSS Testing: Fuzzes discovered parameters with XSS payloads using ffuf.

LFI Testing: Checks for Local File Inclusion vulnerabilities with common payloads.

CORS Misconfiguration Checks: Tests endpoints for improper CORS configurations.

SSRF Testing: Identifies potential SSRF and open redirect candidates and tests them.

WordPress Scanning: Actively scans for common WordPress misconfigurations and vulnerabilities.

Checkpoint/Resume Functionality: Automatically saves progress and allows resuming scans from the last completed phase.

Logging & Reporting: All output is logged and saved in a structured directory for easy review.

**🧰 Tools Used** 

subfinder

findomain

ffuf

httpx

subzy

katana

arjun

dirb

curl

**📁 Output Structure**

All results are saved in a dedicated directory named recon-<domain>, including:

Subdomain lists
Live subdomains with status codes and technologies
Crawled URLs and JS files
Sensitive file findings
Vulnerability scan results (XSS, LFI, CORS, SSRF, WordPress)
Detailed logs of all operations
🚀 Usage
bash


```
# Basic usage with a domain
./enumz.sh example.com

# Use a custom subdomain list
./enumz.sh subdomains.txt

# Scan a specific URL path
./enumz.sh https://example.com/api/v1
```
