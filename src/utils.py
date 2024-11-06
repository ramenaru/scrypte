import re

def check_headers(headers):
    vulnerabilities = []
    if "Server" in headers and "Apache/2.4.1" in headers.get("Server", ""):
        vulnerabilities.append("Outdated Apache server detected.")
    if "X-Powered-By" in headers:
        vulnerabilities.append("Server reveals technology in headers (X-Powered-By).")
    return vulnerabilities

def check_xss(html_content):
    vulnerabilities = []
    xss_patterns = [r"<script>alert\(", r"<img src="]
    for pattern in xss_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            vulnerabilities.append("Potential XSS vulnerability detected.")
    return vulnerabilities
